# coding: utf-8

from __future__ import annotations

from typing import *
from itertools import chain

import netaddr

T = TypeVar('T')


class _Node(Generic[T]):
    __slots__ = ('net', 'children')

    net: netaddr.IPNetwork
    children: List[_Node[T]]

    def __init__(self, net: netaddr.IPNetwork) -> None:
        self.net = net
        self.children = []

    def lookup(self, net: netaddr.IPNetwork) -> _Node[T]:
        node = self
        while node.net != net:
            for child in node.children:
                if net in child.net:
                    node = child
                    break
            else:
                break
        return node

    def __iter__(self) -> Generator[_Node[T], None, None]:
        for child in self.children:
            yield child
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


class RoutingTable(Generic[T]):
    family: int
    # Magic split lengths, do not touch!
    splits = [8, 12, 16, 20, 24, 28, 32, 40, 48, 56, 64, 96, 104, 112, 120]

    _root: _Node[T]

    @overload
    def __init__(self) -> None: ...

    @overload
    def __init__(self, _data: Iterable[Tuple[netaddr.IPNetwork, T]]): ...

    def __init__(self, _data: Any=None) -> None:
        self._root = _Node(netaddr.IPNetwork('::/0'))
        if _data:
            for net, val in _data:
                self.add(net, val)

    def __repr__(self) -> str:
        return "<RoutingTable>"

    def add(self, net: Union[str, netaddr.IPNetwork],
            value: T) -> None:
        if isinstance(net, str):
            net = netaddr.IPNetwork(net)
        ins_node: _DataNode[T]
        if net == self._root.net:
            ins_node = _DataNode(net, value)
            ins_node.children = self._root.children
            self._root = ins_node
            return
        # Fetch best matching node from tree
        node = self._root.lookup(net)
        # If the best matching node is the right node, then just add the data
        # to the node, instead of rebalancing the tree.
        if node.net == net:
            sup_node = self._root.lookup(net.supernet()[-1])
            ins_node = _DataNode(net, value)
            ins_node.children = node.children
            sup_node.children.remove(node)
            sup_node.children.append(ins_node)
            return
        # We have to insert a new node.
        # Prepare the node that we want to insert
        ins_node = _DataNode(net, value)
        # Determine the split_len, that is the prefixlength that will be
        # inserted for an intermediate node.
        split_len: Optional[int]
        try:
            split_len = max(s for s in self.splits if s > node.net.prefixlen
                            and net.prefixlen >= s)
        except ValueError:
            split_len = None
        rep_node: _Node[T] = _Node(node.net)
        if split_len is None or not node.children:
            # Handle the case that we cannot determine a split len, that is the
            # case when the inserted prefix and the parent prefix are located
            # between two split lengths.
            # In this case, we insert the node directly, but we also have to
            # check for child nodes that are contained in the inserted prefix.
            # These prefixes are relocated into the new prefix, namely
            # 'ins_node'.
            rep_node.children.append(ins_node)
            for child in node.children:
                if child.net in ins_node.net:
                    ins_node.children.append(child)
                else:
                    rep_node.children.append(child)
        elif split_len == net.prefixlen:
            # In this case, the introduced child node is the split node, hence
            # we don't need a separate split node.
            rep_node.children.append(ins_node)
            for child in node.children:
                if child.net in ins_node.net:
                    ins_node.children.append(child)
                else:
                    rep_node.children.append(child)
        else:
            # Now, we decided that we need to introduce a split node. The split
            # node is called 'spl_node', and 'rep_node' is the node that holds
            # the new children value for the parent node, i.e. 'node'.
            # Iterate over the children in the old node 'node'.
            spl_node: _Node[T] = _Node(net.supernet(split_len)[0])
            spl_node.children.append(ins_node)
            rep_node.children.append(spl_node)
            for child in node.children:
                if child.net in ins_node.net:
                    ins_node.children.append(child)
                elif child.net in spl_node.net:
                    ins_node.children.append(child)
                else:
                    rep_node.children.append(child)
        node.children = rep_node.children

    def lookup(self, net: Union[str, netaddr.IPNetwork],
               exact: bool=False) -> Tuple[netaddr.IPNetwork, T]:
        nodes = [self._root]
        while nodes[-1].net != net:
            for child in nodes[-1].children:
                if net in child.net:
                    nodes.append(child)
                    break
            else:
                break
        node = nodes[-1]
        if isinstance(node, _DataNode) and (not exact or node.net == net):
            return node.net, node.data
        raise KeyError(net)

    def items(self) -> Generator[Tuple[netaddr.IPNetwork, T], None, None]:
        for node in self._root:
            if isinstance(node, _DataNode):
                yield node.net, node.data

    def __iter__(self) -> Generator[Tuple[netaddr.IPNetwork, T], None, None]:
        yield from self.items()

    def remove(self, net: netaddr.IPNetwork) -> None:
        ins_node: _Node[T]
        if net == self._root.net:
            if not isinstance(self._root, _DataNode):
                raise KeyError(net)
            ins_node = _Node(net)
            ins_node.children = self._root.children
            self._root = ins_node
            return
        node = self._root.lookup(net)
        if node.net != net:
            raise KeyError(net)
        sup_node = self._root.lookup(net.supernet()[-1])
        if node.children:
            ins_node = _Node(net)
            ins_node.children = node.children
            sup_node.children.remove(node)
            sup_node.children.append(ins_node)
            return
        sup_node.children.remove(node)

    def __setitem__(self, net: Union[str, netaddr.IPNetwork],
                    val: T) -> None:
        self.add(net, val)

    def __getitem__(self, net: Union[str, netaddr.IPNetwork]) -> T:
        return self.lookup(net, exact=True)[1]
