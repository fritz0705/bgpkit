# coding: utf-8

from __future__ import annotations

from typing import *
from itertools import chain

import netaddr

T = TypeVar('T')


class _Node(Generic[T]):
    __slots__ = ('net', 'children')

    net: netaddr.IPNetwork
    children: Set[_Node[T]]

    def __init__(self, net: netaddr.IPNetwork) -> None:
        self.net = net
        self.children = set()

    def lookup(self, net: netaddr.IPNetwork) -> _Node[T]:
        item = self
        for item in self.lookup_chain(net):
            pass
        return item

    def lookup_chain(self, net: netaddr.IPNetwork) -> Generator[_Node[T], None, None]:
        yield self
        node = self
        while node.net != net:
            for child in node.children:
                if net in child.net:
                    node = child
                    yield node
                    break
            else:
                break

    def __iter__(self) -> Generator[_Node[T], None, None]:
        yield self
        for child in self.children:
            yield from iter(child)

    def __repr__(self) -> str:
        return f"<_Node net={self.net} children={self.children!r}>"


class _DataNode(_Node[T]):
    __slots__ = ('net', 'children', 'data')

    data: T

    def __init__(self, net: netaddr.IPNetwork, data: T) -> None:
        super().__init__(net)
        self.data = data

    def __repr__(self) -> str:
        return f"<_DataNode net={self.net} data={self.data!r} children={self.children!r}>"


class RoutingTable(Generic[T], Mapping[netaddr.IPNetwork, T]):
    """A generic type that implements the semantics of a routing table. It
    behaves like a dictionary, which maps IP prefixes to arbitrary values, but
    also supports most-specific prefix matches."""

    splits = [8, 16, 24, 32, 40, 48, 56, 64, 96, 104, 112, 120]
    split_min1 = 64

    _root: _Node[T]

    @overload
    def __init__(self) -> None: ...

    @overload
    def __init__(self, _data: Iterable[Tuple[netaddr.IPNetwork, T]]) -> None:
        ...

    @overload
    def __init__(self, _data: Mapping[netaddr.IPNetwork, T]) -> None:
        ...

    def __init__(self, _data: Any=None) -> None:
        self._root = _Node(netaddr.IPNetwork('::/0'))
        if _data is not None:
            self.update(_data)

    def __repr__(self) -> str:
        s = "RoutingTable({"
        for net, value in self.items():
            s += repr(net) + ": " + repr(value) + ", "
        return s + "})"

    def add_stub(self, net: netaddr.IPNetwork) -> None:
        net = self._coerce_net(net)
        self._insert_node(net, _Node(net))

    def _insert_node(self, net: netaddr.IPNetwork, ins_node: _Node[T]) -> None:
        if net == self._root.net:
            ins_node.children = self._root.children
            self._root = ins_node
            return
        net = self._coerce_net(net)
        # Fetch best matching node from tree
        nodes = list(self._root.lookup_chain(net))
        node = nodes[-1]
        # If the best match is an exact metach, then we just add the data to
        # the node, instead of extending the tree.
        if node.net == net:
            sup_node = nodes[-2]
            ins_node.children = node.children
            sup_node.children.remove(node)
            sup_node.children.add(ins_node)
            return
        # In the other case, we extend the tree. To build the tree structure,
        # we use preferred prefix lengths for sub-nodes, i.e. the split
        # lengths.
        split_len: Optional[int]
        try:
            # To determine the correct split length for the insertion, we
            # consider the set of all split lengths between the best match
            # prefix length and the network prefix length to insert, and take
            # the minimum of them.
            split_len = min(s for s in self.splits if s > node.net.prefixlen
                            and net.prefixlen >= s)
        except ValueError:
            # If there is no suitable split length, this is acceptable.
            split_len = None
        # We will rewrite the best matching node (`node`) in the subsequent
        # code. Hence, we allocate a stub node (`rep_node`) that will store
        # the new children for `node`.
        rep_node: _Node[T] = _Node(node.net)
        # Now there are several cases...
        if split_len is None or len(node.children) < self.split_min1 \
                or split_len == net.prefixlen:
            # If there is no suitable split length, the best matching node
            # has no children or the split length is the prefix length of the
            # network to insert, we just rearrange the children of `node` and
            # insert `ins_node`.
            rep_node.children.add(ins_node)
            for child in node.children:
                if child.net in ins_node.net:
                    ins_node.children.add(child)
                else:
                    rep_node.children.add(child)
        else:
            # If the best matching node has at least one child, the split
            # length is determined, and if the split length is less than the
            # prefix length of the network to insert, then we create a node with
            # prefix length equal to the split length, the split node
            # `spl_node`, and group the children of `node` to satisfy the
            # trie condition.
            spl_node: _Node[T] = _Node(net.supernet(split_len)[0])
            # First, we add the `ins_node` node to the split node.
            spl_node.children.add(ins_node)
            # Then, we add the split node `spl_node` to the replacement
            # node `rep_node`.
            rep_node.children.add(spl_node)
            # Then group the children of the best matching node `node`:
            for child in node.children:
                if child.net in ins_node.net:
                    # If the child is in the network to insert, we add it to
                    # the node to insert, i.e. `ins_node`.
                    ins_node.children.add(child)
                elif child.net in spl_node.net:
                    # If the child is in the network of the split node, we add
                    # it directly to the split node.
                    spl_node.children.add(child)
                else:
                    # Otherwise, we add the child to the replacement node.
                    rep_node.children.add(child)
        # Finally, we populate the best matching node with the children of the
        # replacement node `rep_node`.
        node.children = rep_node.children

    def lookup(self, net: netaddr.IPNetwork, exact: bool=False) \
            -> Tuple[netaddr.IPNetwork, T]:
        net = self._coerce_net(net)
        nodes = [self._root]
        node = self._root.lookup(net)
        if isinstance(node, _DataNode) and (not exact or node.net == net):
            return node.net, node.data
        raise KeyError(net)

    def _coerce_net(self, net: netaddr.IPNetwork) -> netaddr.IPNetwork:
        if self._root.net.version == 4:
            return net.ipv4()
        return net.ipv6()

    def __iter__(self) -> Generator[netaddr.IPNetwork, None, None]:
        if isinstance(self._root, _DataNode):
            yield self._root.net
        for node in self._root:
            if isinstance(node, _DataNode):
                yield node.net

    def __len__(self) -> int:
        i = 0
        for _ in self:
            i += 1
        return i

    def remove(self, net: netaddr.IPNetwork) -> None:
        net = self._coerce_net(net)
        nodes = list(self._root.lookup_chain(net))
        node = nodes[-1]
        if node.net != net:
            raise KeyError(net)
        if not isinstance(node, _DataNode):
            raise KeyError(net)
        new_node = _Node(net)
        new_node.children = node.children
        if node == self._root:
            self._root = new_node
        else:
            nodes[-2].children.remove(node)
            nodes[-2].children.add(new_node)

    def clear(self) -> None:
        self._root = _Node(self._root.net)

    def __setitem__(self, net: netaddr.IPNetwork, val: T) -> None:
        net = self._coerce_net(net)
        self._insert_node(net, _DataNode(net, val))

    def __getitem__(self, net: netaddr.IPNetwork) -> T:
        return self.lookup(net, exact=True)[1]

    def __delitem__(self, net: netaddr.IPNetwork) -> None:
        self.remove(net)

    @overload
    def update(self, _data: Iterable[Tuple[netaddr.IPNetwork, T]]) -> None:
        ...

    @overload
    def update(self, _data: Mapping[netaddr.IPNetwork, T]) -> None:
        ...

    def update(self, _data: Any) -> None:
        if isinstance(_data, Mapping):
            for net, value in _data.items():
                self[net] = value
        elif isinstance(_data, Iterable):
            for net, value in _data:
                self[net] = value

    def __eq__(self, rt: Any) -> bool:
        if not isinstance(rt, RoutingTable):
            return False
        for net, value in self.items():
            if net not in rt:
                return False
            if rt[net] != value:
                return False
        return True


class RoutingTable4(RoutingTable):
    """IPv4 version of the RoutingTable data structure. Automatically coerces
    to IPv4 addresses and this class is optimized for IPv4 access."""
    splits = [8, 16, 24]

    def __init__(self, _data: Any=None) -> None:
        self._root = _Node(netaddr.IPNetwork('0.0.0.0/0'))
        if _data is not None:
            self.update(_data)


__all__ = ("RoutingTable", "RoutingTable4")
