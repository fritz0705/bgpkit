# coding: utf-8

from abc import ABC, abstractmethod
import asyncio
import enum
from typing import *

import netaddr

import bgpkit.message

AS_TRANS = 23456


class State(enum.Enum):
    IDLE = 1
    ACTIVE = 2
    CONNECT = 3
    OPEN_CONFIRM = 4
    OPEN_SENT = 5
    ESTABLISHED = 6


ProtocolTuple = Tuple[bgpkit.message.AFI, bgpkit.message.SAFI]


class BaseSession(ABC):
    state: State
    local_router_id: Optional[netaddr.IPAddress]
    local_as: Optional[int]
    local_capabilities: Set[bgpkit.message.Capability]
    peer_router_id: Optional[netaddr.IPAddress]
    peer_as: Optional[int]
    peer_capabilities: Set[bgpkit.message.Capability]
    hold_time: int
    connect_retry_time: int
    keepalive_time: int
    decoder: bgpkit.message.MessageDecoder

    def __init__(self, state: State=State.IDLE,
                 local_router_id: Optional[netaddr.IPAddress]=None,
                 local_as: Optional[int]=None,
                 local_capabilities: Set[bgpkit.message.Capability]=set(),
                 peer_router_id: Optional[netaddr.IPAddress]=None,
                 peer_as: Optional[int]=None,
                 peer_capabilities: Set[bgpkit.message.Capability]=set(),
                 hold_time: int=0,
                 connect_retry_time: int=0,
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
        self.keepalive_time = keepalive_time
        self.last_error = None
        if decoder is None:
            decoder = bgpkit.message.MessageDecoder(
                bgpkit.message.defaultDecoder)
        self.decoder = decoder

    def copy(self, _cls=None, _args={}):
        if _cls is None:
            _cls = self.__class__
        return _cls(state=self.state, local_router_id=self.local_router_id,
                    local_as=self.local_as,
                    local_capabilities=self.local_capabilities,
                    peer_router_id=self.peer_router_id, peer_as=self.peer_as,
                    peer_capabilities=self.peer_capabilities,
                    hold_time=self.hold_time,
                    connect_retry_time=self.connect_retry_time,
                    keepalive_time=self.keepalive_time,
                    decoder=self.decoder, **_args)

    @abstractmethod
    def make_open_message(self) -> bgpkit.message.OpenMessage: ...

    @abstractmethod
    def decode_message(self, b: ByteString) -> bgpkit.message.Message: ...

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
            f"last_error={self.last_error!r}>"


class Session(BaseSession):
    @property
    def supports_asn4(self) -> bool:
        if self.peer_as is None:
            return self.local_supports_asn4
        return self.peer_supports_asn4 and self.local_supports_asn4

    @property
    def local_supports_asn4(self) -> bool:
        for capability in self.local_capabilities:
            if isinstance(capability, bgpkit.message.FourOctetASNCapability):
                return True
        return False

    @property
    def peer_supports_asn4(self) -> bool:
        for capability in self.peer_capabilities:
            if isinstance(capability, bgpkit.message.FourOctetASNCapability):
                return True
        return False

    @property
    def local_protocols(self) -> Set[ProtocolTuple]:
        protos = set()
        for capability in self.local_capabilities:
            if isinstance(capability, bgpkit.message.MultiprotocolCapability):
                protos.add((capability.afi, capability.safi))
        return protos

    @property
    def peer_protocols(self) -> Set[ProtocolTuple]:
        protos = set()
        for capability in self.local_capabilities:
            if isinstance(capability, bgpkit.message.MultiprotocolCapability):
                protos.add((capability.afi, capability.safi))
        return protos

    def load_peer_data(self, msg: bgpkit.message.OpenMessage) -> None:
        self.peer_capabilities = set(msg.capabilities())
        self.peer_router_id = msg.router_id
        self.peer_as = msg.asn
        if self.supports_asn4:
            for capability in self.peer_capabilities:
                if isinstance(capability,
                              bgpkit.message.FourOctetASNCapability):
                    self.peer_as = capability.asn
            if bgpkit.message.ASPathAttribute in self.decoder:
                self.decoder.register_path_attribute_type(
                    bgpkit.message.AS4PathAttribute)
        else:
            if bgpkit.message.ASPathAttribute in self.decoder:
                self.decoder.register_path_attribute_type(
                    bgpkit.message.ASPathAttribute)

    def decode_message(self, _b: bytes) -> bgpkit.message.Message:
        return self.decoder.decode_message(_b)

    def make_open_message(self) -> bgpkit.message.OpenMessage:
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
    "State"
)
