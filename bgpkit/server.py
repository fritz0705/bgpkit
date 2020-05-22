from __future__ import annotations

import asyncio
import enum
from typing import *

import netaddr

from bgpkit.rt import *
from bgpkit.message import *
from bgpkit.session import *

# TODO Evaluate use of locks

R = TypeVar('R', bound='Route')
P = TypeVar('P', bound=PathAttribute)

class ASPathView(object):
    _attribute: ASPathAttribute

    def __init__(self, attribute):
        self._attribute = attribute

    def __iter__(self) -> Generator[int, None, None]:
        for segment in self._attribute.segments:
            for entry in segment:
                yield entry

    def __contains__(self, asn: int) -> bool:
        for entry in self:
            if asn == entry:
                return True
        return False

    def append(self, asn: int) -> None:
        pass

    def add(self, asn: int) -> None:
        pass

    def remove(self, asn: int) -> None:
        pass

    def clear(self) -> None:
        self._attribute.segments = []

class RouteAction(enum.Enum):
    ANNOUNCE = 1
    WITHDRAW = 2

class Route(object):
    afi: AFI
    safi: SAFI
    nlri: NLRI
    attributes: Set[PathAttribute]
    source_router: Optional[RouterID]

    def __init__(self, afi: int, safi: int, nlri: NLRI,
            attributes: Set[PathAttribute],
            source_router: Optional[RouterID]=None) -> None:
        self.afi = AFI(afi)
        self.safi = SAFI(safi)
        self.nlri = nlri
        self.attributes = frozenset(attributes)
        self.source_router = source_router

    def copy(self) -> Route:
        return Route(self.afi, self.safi, self.nlri, self.attributes,
                self.source_router)

    def __hash__(self) -> int:
        return hash(self.afi) ^ hash (self.safi) ^ hash(self.nlri) ^ hash(self.source_router) ^ hash(Route) ^ hash(self.attributes)

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, Route):
            return False
        return other.afi == self.afi and other.safi == self.safi and \
                other.nlri == self.nlri and \
                other.attributes == self.attributes and \
                other.source_router == self.source_router

    @property
    def proto(self) -> ProtoTuple:
        return self.afi, self.safi

    @property
    def aggregator(self) -> Optional[RouterID]:
        a = self._get_by_type(AggregatorAttribute)
        if a is not None:
            return a.asn, a.ip_address

    @property
    def atomic_aggregate(self) -> bool:
        return self._get_by_type(AtomicAggregateAttribute) is not None

    @property
    def origin(self) -> Optional[int]:
        a = self._get_by_type(OriginAttribute)
        if a is not None:
            return a.origin

    @property
    def med(self) -> int:
        a = self._get_by_type(MultiExitDisc)
        if a is not None:
            return a.med

    @property
    def ip_prefix(self) -> Optional[netaddr.IPNetwork]:
        if isinstance(self.nlri, IPNLRI):
            return self.nlri.net

    @property
    def next_hop(self) -> List[netaddr.IPAddress]:
        raise TypeError('Protocol {self.proto!r} doesn\'t support `next_hop` attribute')

    @property
    def local_pref(self) -> Optional[int]:
        a = self._get_by_type(LocalPrefAttribute)
        if a is not None:
            return a.local_pref

    def _getall_by_type(self, _type: Type[P]) -> Generator[P, None, None]:
        for attribute in self.attributes:
            if isinstance(attribute, _type):
                yield attribute

    def _get_by_type(self, _type: Type[P]) -> Optional[P]:
        i = self._getall_by_type(_type)
        try:
            return next(i)
        except StopIteration:
            pass
        return None

    def __repr__(self) -> str:
        local_pref = self.local_pref
        aggregator = self.aggregator
        source_router = self.source_router
        med = self.med
        s = f"<Route afi={self.afi!r} safi={self.safi!r} {self.nlri!r}"
        if source_router is not None:
            s += f" source_router={source_router!r}"
        if local_pref is not None:
            s += f" local_pref={local_pref!r}"
        if aggregator is not None:
            s += f" aggregator={aggregator!r}"
        if med is not None:
            s += f" med={med!r}"
        return s + ">"

    @classmethod
    def from_update(cls: Type[R], update: UpdateMessage) -> Generator[R, None, None]:
        attrs: Set[PathAttribute] = set()
        mpreachs: List[MultiprotocolReachableNLRI] = []
        mpunreachs: List[MultiprotocolUnreachableNLRI] = []
        for attr in update.path_attributes:
            if isinstance(attr, MultiprotocolReachableNLRI):
                mpreachs.append(attr)
            elif isinstance(attr, MultiprotocolUnreachableNLRI):
                mpunreachs.append(attr)
            else:
                attrs.add(attr)
        for nlri in update.nlri:
            yield RouteAction.ANNOUNCE, cls(AFI.AFI_IPV4, SAFI.SAFI_UNICAST, nlri, attrs)
        for withdrawn in update.withdrawn:
            yield RouteAction.WITHDRAW, cls(AFI.AFI_IPV4, SAFI.SAFI_UNICAST, withdrawn, attrs)
        for mpreach in mpreachs:
            for nlri in mpreach.nlri:
                yield RouteAction.ANNOUNCE, cls(mpreach.afi, mpreach.safi, nlri, attrs | {mpreach})
        for mpunreach in mpunreachs:
            for nlri in mpunreach.nlri:
                yield RouteAction.WITHDRAW, cls(mpreach.afi, mpreach.safi, nlri, attrs | {mpunreach})

# High-level timer, maybe replace by low-level asyncio timer?
class Timer(object):
    delta: float
    callback: Optional[Callable[[Timer], Any]]
    _task: Optional[asyncio.Task]

    def __init__(self, delta: float,
            callback: Optional[Callable[[Timer], Any]]=None) -> None:
        self.delta = delta
        self.callback = callback
        self._task = None

    @property
    def started(self) -> bool:
        return self._task is not None or self.delta == 0

    @property
    def expired(self) -> bool:
        return self._task is not None and self._task.done() and self.delta != 0

    def start(self) -> None:
        if self.delta == 0:
            return
        if self.started:
            # TODO Raise appropriate exception
            raise
        self._task = asyncio.create_task(self._run())

    def stop(self) -> None:
        if self.delta == 0:
            return
        if not self.started:
            # TODO Raise appropriate exception
            raise
        self._task.cancel()
        self._task = None

    def force_start(self) -> None:
        if not self.started:
            self.start()

    def force_stop(self) -> None:
        if self.started:
            self.stop()
    
    async def _run(self) -> Any:
        await asyncio.sleep(self.delta)
        if self.callback is not None:
            # Some reflection to call coroutines when the Timer fires
            if asyncio.iscoroutinefunction(self.callback):
                return await self.callback(self)
            return self.callback(self)

class NotificationException(Exception):
    notification: NotificationMessage

    def __init__(self, notification: NotificationMessage) -> None:
        super().__init__()
        self.notification = notification

    def __repr__(self) -> str:
        return f"<NotificationException {self.notification!r}>"

    def to_bytes(self) -> bytes:
        return self.notification.to_bytes()

class ServerSession(Session):
    hold_timer: Timer
    keepalive_timer: Timer
    connect_retry_timer: Timer
    reader_task: Optional[asyncio.Task]
    writer: Optional[asyncio.StreamWriter]
    reader: Optional[asyncio.StreamReader]
    server: Optional[BGPServer]
    peername: Optional[Tuple[str, int, ...]]
    active: bool

    def __init__(self, session: Optional[BaseSession]=None,
            writer: Optional[asyncio.StreamWriter]=None,
            reader: Optional[asyncio.StreamReader]=None,
            server: Optional[BGPServer]=None,
            reader_task: Optional[asyncio.Task]=None,
            peername: Optional[Tuple[str, int, ...]]=None,
            active: bool=False, **kwargs):
        super().__init__(session, **kwargs)
        self.writer = writer
        self.reader = reader
        self.server = server
        self.reader_task = reader_task
        self.active = active
        self.peername = peername
        if session is not None and isinstance(session, ServerSession):
            self.active = session.active
            self.peername = session.peername
            self.server = session.server
            self.writer = writer
            self.reader = reader
        self.create_timers()

    def create_timers(self) -> None:
        self.hold_timer = Timer(self.hold_time, self.hold_callback)
        self.keepalive_timer = Timer(self.keepalive_time, self.keepalive_callback)
        self.connect_retry_timer = Timer(self.connect_retry_time,
                self.connect_retry_callback)

    async def hold_callback(self, timer):
        if self.state != State.ESTABLISHED:
            return
        self.reader_task.cancel()
        notif_msg = None
        self.writer.write(notif_msg.to_bytes())

    async def keepalive_callback(self, timer):
        if self.state != State.ESTABLISHED:
            return
        msg = KeepaliveMessage()
        self.writer.write(msg.to_bytes())
        await self.writer.drain()
        timer.start()

    def connect_retry_callback(self, timer):
        if self.active is False:
            return
        if self.state != State.IDLE:
            return
        self.state = State.CONNECT
        self.server.open_connection(self, self.peername[0], self.peername[1])
        timer.start()

    def load_peer_data(self, msg: OpenMessage) -> None:
        super().load_peer_data(msg)
        self.create_timers()

    def close(self, notification: NotificationMessage) -> None:
        self.writer.write(notification.to_bytes())
        self.reader_task.cancel()

    async def on_update(self, update: UpdateMessage) -> None:
        print(update)

    async def on_route_refresh(self, route_refresh: RouteRefreshMessage) -> None:
        print(route_refresh)

    async def on_shutdown(self) -> None:
        pass

    async def on_established(self) -> None:
        pass

    async def on_notification(self, notification: NotificationMessage) -> None:
        pass

    @property
    def initiator_router_id(self) -> Optional[netaddr.IPNetwork]:
        if self.active:
            return self.local_router_id
        return self.peer_router_id
    
    @property
    def initiator_asn(self) -> Optional[int]:
        if self.active:
            return self.local_asn
        return self.peer_asn

class BGPServer(object):
    peers: RoutingTable[BaseSession]
    sessions_lock: asyncio.Lock
    sessions: Mapping[RouterID, ServerSession]

    def __init__(self) -> None:
        self.peers = RoutingTable()
        self.sessions_lock = asyncio.Lock()
        self.sessions = {}
        self.on_update = None

    def create_session(self, base_session: BaseSession,
            **kwargs: Any) -> ServerSession:
        session = base_session.copy(ServerSession, **kwargs)
        return session

    def add_active_session(self, session: ServerSession, start=False) -> None:
        if not session.active:
            raise ValueError('Session must be marked as active.')
        if session.peername is None:
            raise ValueError('Session must have a valid peername.')
        net = netaddr.IPNetwork(session.peername[0])
        self.peers[net] = session

    def start(self) -> None:
        for peer in self.peers.values():
            if isinstance(peer, ServerSession) and peer.active:
                peer.connect_retry_timer.force_start()

    def stop(self) -> None:
        for peer in self.peers:
            if isinstance(peer, ServerSession) and peer.active:
                peer.connect_retry_timer.force_stop()

    def start_server(self, *args: Any, **kwargs: Any) -> Any:
        return asyncio.start_server(self.accept_handler, *args, **kwargs)

    def open_connection(self, session: ServerSession, host: str,
            port: int) -> asyncio.Task:
        asyncio.create_task(self.connect(session, host, port))

    def __enter__(self) -> None:
        self.start()

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.stop()

    async def connect(self, session: ServerSession, *args: Any,
            **kwargs: Any) -> None:
        session.reader_task = asyncio.current_task()
        reader, writer = await asyncio.open_connection(*args, **kwargs)
        session.connect_retry_timer.force_stop()
        try:
            await self.run_session(reader, writer, session)
        finally:
            writer.close()
            await writer.wait_closed()
            session.reader_task = None
            if session.active:
                session.connect_retry_timer.start()

    async def accept_handler(self, reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter) -> None:
        # First, we need the peer_addr (and maybe the peer_port) to determine
        # the right BGP session settings.
        peername = writer.get_extra_info('peername')
        peer_addr: str
        peer_port: int
        peer_addr = peername[0]
        peer_port = peername[1]
        try:
            net, base_session = self.peers.lookup(netaddr.IPAddress(peer_addr))
        except KeyError:
            return
        # Create ServerSession from session template
        session = self.create_session(base_session, server=self)
        session.reader = reader
        session.writer = writer
        session.reader_task = asyncio.current_task()
        session.peername = peername
        session.active = False
        try:
            base_session.connect_retry_timer.force_stop()
            # Run session
            await self.run_session(reader, writer, session)
        finally:
            base_session.last_error = session.last_error
            if base_session.active:
                base_session.connect_retry_timer.start()

    async def perform_collision_resolution(self, session: ServerSession) -> None:
        if session.peer_id not in self.sessions:
            return
        async with self.sessions_lock:
            other_session = self.sessions[session.peer_id]
        if other_session.state == State.ESTABLISHED:
            # Send CEASE error
            raise NotificationException(NotificationMessage(6))
        if other_session.state != State.OPEN_CONFIRM:
            return
        if session.initiator_router_id > other_session.initiator_router_id:
            # Destroy other session
            return other_session.close(NotificationMessage(6))
        elif session.initiator_router_id < other_session.initiator_router_id:
            # Destroy this session
            raise NotificationException(NotificationMessage(6))
        # In this case, session.initiator_router_id = other_session.init_rtr_id
        if session.initiator_asn > other_session.initiator_asn:
            # Destroy other session
            return other_session.close(NotificationMessage(6))
        elif session.initiator_asn > other_session.initiator_asn:
            # Destroy this session
            raise NotificationException(NotificationMessage(6))
        

    async def handle_message(self, session: ServerSession,
            msg: Message) -> None:
        if isinstance(msg, KeepaliveMessage):
            # Reset hold timer after reception of KEEPALIVE message
            session.hold_timer.reset()
        elif isinstance(msg, UpdateMessage):
            # Delegate handling of UPDATE message
            await session.on_update(msg)
        elif isinstance(msg, RouteRefreshMessage):
            # Delegate handling of ROUTE_REFRESH message
            await session.on_route_refresh(msg)
        elif isinstance(msg, NotificationMessage):
            # TODO Implement proper handling of NOTIFICATION message
            await session.on_notification(msg)
            session.last_error = msg
            return
        elif isinstance(msg, OpenMessage):
            # TODO Implement proper handling of OPEN message
            return

    async def run_session(self, reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
            session: ServerSession) -> None:
        # We are, right now, in the Active state, which means that we haven't
        # sent an OPEN message. To change to OpenSent state, we have to
        # construct an OPEN message and send it to our peer.
        if session.state != State.ACTIVE:
            # TODO Handle this case
            pass
        msg = session.make_open_message()
        writer.write(msg.to_bytes())
        # Wait until we have really sent the OPEN message
        await writer.drain()
        session.state = State.OPEN_SENT
        # Now wait for the OPEN message from the other side.
        msg = await read_message(reader)
        msg = session.decode_message(msg)
        if isinstance(msg, NotificationMessage):
            # We received a NotificationMessage.  This means that the remote
            # side does not want to establish a BGP session with us.  The
            # reason is encoded in the received NotificationMessage object.
            # For further handling we put this NotificationMessage into the
            # last_error attribute of the session object.
            session.last_error = msg
            writer.close()
            await writer.wait_closed()
            return
        elif not isinstance(msg, OpenMessage):
            # TODO Answer with appropriate NOTIFICATION message
            writer.close()
            await writer.wait_closed()
            return
        # We have received an OPEN message from the peer side. The next step is
        # to verify this OPEN message if it matches on our configured session.
        # Then, we load the peer information (ASN, Router ID, etc.) to our
        # session instance.
        try:
            session.load_peer_data(msg)
        except NotificationException as notif:
            writer.write(notif.to_bytes())
            await writer.wait_closed()
            return
        # Then, we have to perform collision detection.
        try:
            await self.perform_collision_resolution(session)
        except NotificationException as notif:
            writer.write(notif.to_bytes())
            await writer.wait_closed()
            return
        # When we resolved the collision, we register the current session
        # in our server instance.
        async with self.sessions_lock:
            self.sessions[session.peer_id] = session
        try:
            # To change to OpenConfirm state, we have to send a KEEPALIVE message
            # to our peer. After that, we wait for a KEEPALIVE message from our
            # peer.
            msg = KeepaliveMessage()
            writer.write(msg.to_bytes())
            await writer.drain()
            session.state = State.OPEN_CONFIRM
            msg = await read_message(reader)
            msg = session.decode_message(msg)
            if not isinstance(msg, KeepaliveMessage):
                if isinstance(msg, NotificationMessage):
                    session.last_error = msg
                    return
                # TODO Answer with appropriate NOTIFICATION message
            # After reception of the KEEPALIVE message from the peer, we change
            # from the OpenConfirm state to the Established state. Further, we
            # start the associated session timers.
            session.state = State.ESTABLISHED
            session.keepalive_timer.start()
            session.hold_timer.start()
            while True:
                msg = await read_message(reader)
                msg = session.decode_message(msg)
                await self.handle_message(session, msg)
        except NotificationException as notif:
            writer.write(notif.to_bytes())
            session.last_error = notif.notification
        except asyncio.IncompleteReadError:
            # This happens when the peer closes the connection before we are
            # done with reading a complete message.
            pass
        except asyncio.CancelledError:
            # The session has been cancelled, but we have to 
            raise
        finally:
            # If the session was in Established state, then we call the
            # session.on_shutdown hook to allow the session to withdraw routes
            # from the loc_rib.
            if session.state == State.ESTABLISHED:
                try:
                    await session.on_shutdown()
                except:
                    # Ignore exceptions in on_shutdown, since the session is
                    # dying anyway.
                    pass
            session.state = State.IDLE
            # Stop the associated connection timers
            session.keepalive_timer.stop()
            session.hold_timer.stop()
            # Remove session from session dictionary
            async with self.sessions_lock:
                del self.sessions[session.peer_id]
            writer.close()
            await writer.wait_closed()

Filter = Callable[[Route], bool]

def accept_all_filter(route):
    return True

def reject_all_filter(route):
    return False

RIBKey = Tuple[AFI, SAFI, NLRI]
T = TypeVar('T')

class RIB(Generic[T], Mapping[RIBKey, T]):
    _rts: Mapping[ProtoTuple, RoutingTable[T]]
    _protos: Set[ProtoTuple]

    def __init__(self, protos: Set[ProtoTuple]=set()) -> None:
        self._protos = set(protos)
        self._rts = {proto: RoutingTable() for proto in self._protos}

    @property
    def protos(self) -> FrozenSet[ProtoTuple]:
        return frozenset(self._protos)

    def clear(self) -> None:
        for rt in self._rts.values():
            rt.clear()

    def register_proto(self, proto: ProtoTuple) -> None:
        if proto in self._protos:
            return
        self._protos.add(proto)
        self._rts[proto] = RoutingTable()

    def unregister_proto(self, proto: ProtoTuple) -> None:
        if proto not in self._protos:
            return
        self._protos.remove(proto)
        del self._rts[proto]

    def register_protos(self, protos: Iterable[ProtoTuple]) -> None:
        for proto in protos:
            self.register_proto(proto)

    def add(self, route: Route) -> None:
        if route.proto not in self._protos:
            raise ValueError(f'Protocol {route.proto} not supported.')
        if not isinstance(route.nlri, IPNLRI):
            raise ValueError(f'Non-IP routes not supported.')
        self[route.afi, route.safi, route.nlri] = route

    def add_value(self, route: Route, value: T) -> None:
        if route.proto not in self._protos:
            raise ValueError(f'Protocol {route.proto} not supported.')
        if not isinstance(route.nlri, IPNLRI):
            raise ValueError(f'Non-IP routes not supported.')
        self[route.afi, route.safi, route.nlri] = value

    def add_set(self: RIB[Set[T]], route: Route) -> None:
        if route.proto not in self._protos:
            raise ValueError(f'Protocol {route.proto} not supported.')
        if not isinstance(route.nlri, IPNLRI):
            raise ValueError(f'Non-IP routes not supported.')
        if (route.afi, route.safi, route.nlri) not in self:
            self[route.afi, route.safi, route.nlri] = set()
        self[route.afi, route.safi, route.nlri].add(route)

    def get_value(self, route: Route) -> T:
        if route.proto not in self._protos:
            raise ValueError(f'Protocol {route.proto} not supported.')
        if not isinstance(route.nlri, IPNLRI):
            raise ValueError(f'Non-IP routes not supported.')
        return self[route.afi, route.safi, route.nlri]

    def remove(self, route: Route) -> None:
        if (route.afi, route.safi, route.nlri) not in self:
            return
        del self[route.afi, route.safi, route.nlri]

    def remove_set(self: RIB[Set[T]], route: Route) -> None:
        if (route.afi, route.safi, route.nlri) not in self:
            return
        self[route.afi, route.safi, route.nlri].remove(route)

    def __setitem__(self, key: RIBKey,
            value: T) -> None:
        afi, safi, route = key
        self._rts[afi, safi][route] = value

    def __getitem__(self, key: RIBKey) -> T:
        return self._rts[key[0], key[1]][key[2]]

    def __delitem__(self, key: RIBKey) -> None:
        del self._rts[key[0], key[1]][key[2]]

    def __contains__(self, key: RIBKey) -> bool:
        if (key[0], key[1]) not in self._rts:
            return False
        return key[2] in self._rts

    def __iter__(self) -> Generator[RIBKey, None, None]:
        for afi, safi in self._protos:
            for net in self._rts[afi, safi]:
                yield (afi, safi, net)

    def __len__(self) -> int:
        n = 0
        for rt in self._rts.values():
            n += len(rt)
        return n

    def __repr__(self) -> str:
        return f"<RIB protos={self.protos!r} length={len(self)}>"

class RoutingSession(ServerSession):
    adj_rib_in_lock: asyncio.Lock
    adj_rib_in: RIB[Route]
    adj_rib_out: RIB[Route]
    filter_in: Filter
    filter_out: Filter
    server: RoutingServer

    def __init__(self, server: RoutingServer,
            session: Optional[BaseSession]=None,
            filter_in: Filter=reject_all_filter,
            filter_out: Filter=accept_all_filter,
            **kwargs: Any) -> None:
        super().__init__(session, **kwargs)
        self.server = server
        self.adj_rib_in_lock = asyncio.Lock()
        self.adj_rib_in = RIB()
        self.adj_rib_out = RIB()
        self.filter_in = filter_in
        self.filter_out = filter_out
        if session is not None and isinstance(session, RoutingSession):
            self.filter_in = session.filter_in
            self.filter_out = session.filter_out

    def load_peer_data(self, msg: OpenMessage) -> None:
        super().load_peer_data(msg)
        self.adj_rib_in.register_protos(self.common_protocols)

    def announce(self, route: Route, apply_filter=True) -> None:
        if apply_filter and not self.filter_out(route):
            return
        self.adj_rib_out.add(route)
        if self.state == State.ESTABLISHED:
            update = route.update_message()
            self.writer.write(update)

    def withdraw(self, route: Route) -> None:
        if self.state == State.ESTABLISHED and route in self.adj_rib_out:
            update = route.withdraw_update_message()
            self.writer.write(update)
        self.adj_rib_out.remove(route)

    async def on_update(self, update: UpdateMessage) -> None:
        routes = []
        # First we collect the routes from the update message `update`
        for action, route in Route.from_update(update):
            # If we do not support the AFI-SAFI-tuple of the received route,
            # then this is clearly a protocol violation, and we close the
            # session with a NOTIFICATION message.
            if route.proto not in self.common_protocols:
                raise NotificationException(NotificationMessage(3, 9))
            route.source_router = self.peer_id
            routes.append((action, route))
        # Then we add the routes to adj_rib_in
        async with self.adj_rib_in_lock:
            for action, route in routes:
                if action == RouteAction.ANNOUNCE:
                    self.adj_rib_in.add(route)
                elif action == RouteAction.WITHDRAW:
                    self.adj_rib_in.remove(route)
        # After importing the routes to adj_rib_in, we merge adj_rib_in into
        # the server RIB
        async with self.server.loc_rib_lock:
            for action, route in routes:
                if action == RouteAction.ANNOUNCE and self.filter_in(route):
                    self.server.loc_rib.add_set(route)
                elif action == RouteAction.WITHDRAW:
                    self.server.loc_rib.remove_set(route)

    async def on_route_refresh(self, route_refresh: RouteRefreshMessage) -> None:
        for route in self.adj_rib_out.values():
            if route.afi != route_refresh.afi \
                    or route.safi != route_refresh.safi:
                continue
            update = route.update_message()
            self.writer.write(update.to_bytes())
        self.writer.write(UpdateMessage())
        await self.writer.drain()

    async def on_shutdown(self) -> None:
        async with self.adj_rib_in_lock:
            for route in self.adj_rib_in.values():
                self.server.loc_rib.remove_set(route)
        self.adj_rib_in.clear()

    async def on_established(self) -> None:
        self.adj_rib_in.clear()
        for route in self.adj_rib_out.values():
            update = route.update_message()
            self.writer.write(update.to_bytes())
            await self.writer.drain()

class RoutingServer(BGPServer):
    sessions: Mapping[RouterID, RoutingSession]
    loc_rib_lock: asyncio.Lock
    loc_rib: RIB[Set[Route]]

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.loc_rib_lock = asyncio.Lock()
        self.loc_rib = RIB()

    def create_session(self, session: BaseSession,
            **kwargs: Any) -> RoutingSession:
        return session.copy(RoutingSession, **kwargs)

__all__ = ('BGPServer', 'ServerSession', 'RoutingSession', 'RoutingServer',
        'RIB', 'Route')
