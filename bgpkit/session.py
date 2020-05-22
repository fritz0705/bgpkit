# coding: utf-8

from __future__ import annotations

from abc import ABC, abstractmethod
import asyncio
import enum
from typing import *

import netaddr

import bgpkit.message
import bgpkit.rt

AS_TRANS = 23456


class State(enum.Enum):
    """State of a BGP session."""
    IDLE = 1
    ACTIVE = 2
    CONNECT = 3
    OPEN_CONFIRM = 4
    OPEN_SENT = 5
    ESTABLISHED = 6

ProtoTuple = bgpkit.message.ProtoTuple

RouterID = Tuple[int, netaddr.IPAddress]
S = TypeVar('S', bound='BaseSession')

class BaseSession(ABC):
    """Abstraction for a concrete implementation of a BGP session. Provides a
    basic constructor together with some basic state information.

    :params _sess: Session object that acts as a template for the new session
    instance.
    :params state: Initial session state.
    :params local_router_id: Optional router ID of the local side.
    :params local_as: Optional AS number of the local side.
    :params local_capabilities: Optional set of locally supported capabilities.
    :params peer_router_id: Optional router ID of the peer side.
    :params peer_as: Optional AS number of the peer side.
    :params peer_capabilities: Optional set of supported capabilities of the
    peer.
    :params hold_time: Hold time in seconds.
    :params connect_retry_time: Connect retry time in seconds.
    :params connect_retry_counter: Connect retry counter.
    :params keepalive_time: Keepalive time in seconds.
    :params decoder: Optional decoder object to be used to decode incoming
    messages.
    """

    state: State
    """State of the BGP session."""

    local_router_id: Optional[netaddr.IPAddress]
    """Optional router ID of the local side."""

    local_as: Optional[int]
    """Optional AS number of the local side."""

    local_capabilities: Set[bgpkit.message.Capability]
    """Set of supported capabilities of the local side."""

    peer_router_id: Optional[netaddr.IPAddress]
    """Router ID of the peer side."""

    peer_as: Optional[int]
    """Router AS number of the peer side."""

    peer_capabilities: Set[bgpkit.message.Capability]
    """Set of supported capabilities of the peer side."""

    hold_time: int
    """Hold time in seconds. If the local side does not receive a keepalive
    message within the hold time, the local side closes the BGP session."""

    connect_retry_time: int
    """Connect retry time in seconds. When the session is shutdown by an error,
    wait the connect retry time until reconnecting."""

    connect_retry_counter: int
    """The number of reconnection tries."""

    keepalive_time: int
    """The number of seconds between two keepalive messages."""

    decoder: bgpkit.message.MessageDecoder
    """Message decoder instance that is used to decode incoming messages."""

    last_error: NotificationMessage
    """Last error received from the peer side."""

    def __init__(self, _sess: Optional[BaseSession]=None,
            state: State=State.IDLE,
                 local_router_id: Optional[netaddr.IPAddress]=None,
                 local_as: Optional[int]=None,
                 local_capabilities: Set[bgpkit.message.Capability]=set(),
                 peer_router_id: Optional[netaddr.IPAddress]=None,
                 peer_as: Optional[int]=None,
                 peer_capabilities: Set[bgpkit.message.Capability]=set(),
                 hold_time: int=0,
                 connect_retry_time: int=0,
                 connect_retry_counter: int=0,
                 keepalive_time: int=0,
                 decoder: Optional[bgpkit.message.MessageDecoder]=None) \
            -> None:
        self.state = state
        self.local_router_id = local_router_id
        self.local_as = local_as
        self.local_capabilities = set(local_capabilities)
        self.peer_router_id = peer_router_id
        self.peer_as = peer_as
        self.peer_capabilities = set(peer_capabilities)
        self.hold_time = hold_time
        self.connect_retry_time = connect_retry_time
        self.connect_retry_counter = connect_retry_counter
        self.keepalive_time = keepalive_time
        self.last_error = None
        if decoder is None:
            decoder = bgpkit.message.MessageDecoder(
                bgpkit.message.default_decoder)
        self.decoder = decoder
        if _sess is not None:
            self.update(_sess)

    def update(self, _sess: BaseSession) -> None:
        """Load the attributes of a template, given as a session object, into
        the object, if available in the template.

        :param _sess: Session object to be used as a template."""
        self.state = _sess.state
        if _sess.local_router_id is not None:
            self.local_router_id = _sess.local_router_id
        if _sess.local_as is not None:
            self.local_as = _sess.local_as
        self.local_capabilities.update(_sess.local_capabilities)
        if _sess.peer_router_id is not None:
            self.peer_router_id = _sess.peer_router_id
        if _sess.peer_as is not None:
            self.peer_as = _sess.peer_as
        self.peer_capabilities.update(_sess.peer_capabilities)
        self.hold_time = _sess.hold_time
        self.connect_retry_time = _sess.connect_retry_time
        self.connect_retry_counter = _sess.connect_retry_counter
        self.keepalive_time = _sess.keepalive_time
        if _sess.decoder is not None:
            self.decoder = _sess.decoder

    def copy(self, _cls: Type[S]=None, **kwargs: Any) -> S:
        if _cls is None:
            _cls = self.__class__
        return _cls(session=self, **kwargs)

    @abstractmethod
    def make_open_message(self) -> bgpkit.message.OpenMessage: ...

    @abstractmethod
    def decode_message(self, _b: bytes) -> bgpkit.message.Message: ...

    @property
    def peer_id(self) -> Optional[RouterID]:
        """Full identity of the peer that consists of the peer AS number
        and peer router ID."""
        if self.peer_as is not None or self.peer_router_id is not None:
            return self.peer_as, self.peer_router_id
        return None

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} state={self.state!r} " \
            f"local_router_id={self.local_router_id!r} " \
            f"local_as={self.local_as!r} " \
            f"local_capabilities={self.local_capabilities!r} " \
            f"peer_router_id={self.peer_router_id!r} " \
            f"peer_as={self.peer_as!r} " \
            f"peer_capabilities={self.peer_capabilities!r} " \
            f"hold_time={self.hold_time!r} " \
            f"keepalive_time={self.keepalive_time!r} " \
            f"connect_retry_time={self.connect_retry_time!r} " \
            f"connect_retry_counter={self.connect_retry_counter!r} " \
            f"last_error={self.last_error!r}>"


class Session(BaseSession):
    """A basic BGP session implementation with ASN4 support and callbacks for
    messages."""

    peer_address: Any
    """The address of the peer side."""

    local_address: Any
    """The address of the local side."""

    @property
    def common_capabilities(self) -> Set[bgpkit.message.Capability]:
        """The set of capabilities that are supported by the local and remote
        side."""
        caps = self.local_capabilities & self.peer_capabilities
        if self.supports_asn4 and self.local_as is not None:
            caps.add(bgpkit.message.FourOctetASNCapability(self.peer_as))
        if self.supports_add_path:
            caps.add(self.peer_add_path_cap & self.local_add_path_cap)
        return caps

    @property
    def supports_asn4(self) -> bool:
        """Whether the session uses four-byte autonomous system numbers."""
        if self.peer_as is None:
            return self.local_supports_asn4
        return self.peer_supports_asn4 and self.local_supports_asn4

    @property
    def local_supports_asn4(self) -> bool:
        """Whether the local side supports four-byte autonomous system numbers.
        """
        for capability in self.local_capabilities:
            if isinstance(capability, bgpkit.message.FourOctetASNCapability):
                return True
        return False

    @property
    def peer_supports_asn4(self) -> bool:
        """Whether the peer supports four-byte autonomous system numbers, that
        is the case when the peer has the FourOctetASNCapability."""
        for capability in self.peer_capabilities:
            if isinstance(capability, bgpkit.message.FourOctetASNCapability):
                return True
        return False

    @property
    def peer_add_path_cap(self) -> Optional[bgpkit.message.AddPathCapability]:
        for capability in self.peer_capabilities:
            if isinstance(capability, bgpkit.message.AddPathCapability):
                return capability

    @property
    def local_add_path_cap(self) -> Optional[bgpkit.message.AddPathCapability]:
        for capability in self.local_capabilities:
            if isinstance(capability, bgpkit.message.AddPathCapability):
                return capability

    @property
    def supports_add_path(self) -> bool:
        return self.peer_add_path_cap is not None and \
                self.local_add_path_cap is not None

    @property
    def local_protocols(self) -> Set[ProtoTuple]:
        """Set of protocols supported by the local side. For the format, see
        the attribute `peer_protocols`."""
        protos = set()
        for capability in self.local_capabilities:
            if isinstance(capability, bgpkit.message.MultiprotocolCapability):
                protos.add((capability.afi, capability.safi))
        return protos

    @property
    def peer_protocols(self) -> Set[ProtoTuple]:
        """Set of protocols supported by the peer. The protocols are
        represented by protocol tuples, that consist of the AFI and SAFI
        value."""
        protos = set()
        for capability in self.local_capabilities:
            if isinstance(capability, bgpkit.message.MultiprotocolCapability):
                protos.add((capability.afi, capability.safi))
        return protos

    @property
    def common_protocols(self) -> Set[ProtoTuple]:
        return self.local_protocols & self.peer_protocols

    @property
    def peer(self) -> Optional[Tuple[int, netaddr.IPAddress]]:
        if self.peer_as is not None and self.peer_router_id is not None:
            return self.peer_as, self.peer_router_id
        return None

    def load_peer_data(self, msg: bgpkit.message.OpenMessage) -> None:
        """Loads peer data into Session object from OPEN message. This sets
        the session attributes `peer_capabilities`, `peer_router_id`, and
        `peer_as` from the data contained in the OPEN message. Furthermore,
        this replaces the session-specific decoder by an appropriate decoder
        for the common session capabilities.

        :params msg: Instance of the OPEN message."""
        self.peer_capabilities = set(msg.capabilities())
        self.peer_router_id = msg.router_id
        self.peer_as = msg.asn
        if self.supports_asn4:
            for cap in self.peer_capabilities:
                if isinstance(cap, bgpkit.message.FourOctetASNCapability):
                    self.peer_as = cap.asn
        self.decoder = bgpkit.message.MessageDecoder.for_capabilities(
                self.common_capabilities,
                self.decoder)

    def decode_message(self, _b: bytes) -> bgpkit.message.Message:
        """Decodes a message given as a bytes-like object by using the
        session-specific BGP message decoder. Returns a
        `bgpkit.message.Message` object.

        :params _b: Message object as a bytes-like object."""
        return self.decoder.decode_message(_b)

    def make_open_message(self) -> bgpkit.message.OpenMessage:
        """Generates an OPEN message that covers the information stored in this
        session."""
        msg = bgpkit.message.OpenMessage()
        if self.local_router_id is not None:
            msg.router_id = self.local_router_id
        if not self.supports_asn4 and self.local_as is not None:
            msg.asn = self.local_as
        else:
            msg.asn = AS_TRANS
        msg.hold_time = self.hold_time
        for capability in self.local_capabilities:
            msg.parameters.append(capability.as_param())
        return msg


__all__ = (
    "AS_TRANS",
    "BaseSession",
    "RouterID",
    "Session",
    "State"
)
