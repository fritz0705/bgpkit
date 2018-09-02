# coding: utf-8

import enum

import bgpkit.message

AS_TRANS = 23456


class State(enum.Enum):
    IDLE = 1
    ACTIVE = 2
    CONNECT = 3
    OPEN_CONFIRM = 4
    OPEN_SENT = 5
    ESTABLISHED = 6


class Capability(enum.Enum):
    ASN4 = 1
    MP = 2
    BGPSEC = 3

    @classmethod
    def from_capability_msg(cls, cap):
        if isinstance(cap, bgpkit.message.FourOctetASNCapability):
            return cls.ASN4
        elif isinstance(cap, bgpkit.message.MultiprotocolCapability):
            return cls.MP


class Session(object):
    def __init__(self, state=State.IDLE, local_router_id=None,
                 local_as=None, local_capabilities={}, peer_router_id=None,
                 peer_as=None, peer_capabilities={}, hold_time=0,
                 local_protocols=[], peer_protocols=[],
                 connect_retry_time=0, keepalive_time=0):
        self.state = state
        self.local_router_id = local_router_id
        self.local_as = local_as
        self.local_capabilities = set(local_capabilities)
        self.local_protocols = list(local_protocols)
        self.peer_router_id = peer_router_id
        self.peer_as = peer_as
        self.peer_capabilities = set(peer_capabilities)
        self.peer_protocols = list(peer_protocols)
        self.hold_time = hold_time
        self.connect_retry_time = connect_retry_time
        self.keepalive_time = keepalive_time
        self.last_error = None

    def __repr__(self):
        return "<Session state={!r} local_router_id={!r} local_as={!r} " \
            "local_capabilities={!r} local_protocols={!r} "\
            "peer_router_id={!r} peer_as={!r} peer_capabilities={!r}" \
            "peer_protocols={!r} common_capabilities={!r} " \
            "common_protocols={!r} hold_time={!r} " \
            "last_error={!r}>".format(
                self.state,
                self.local_router_id,
                self.local_as,
                self.local_capabilities,
                self.local_protocols,
                self.peer_router_id,
                self.peer_as,
                self.peer_capabilities,
                self.peer_protocols,
                self.common_capabilities,
                self.common_protocols,
                self.hold_time,
                self.last_error)

    @property
    def common_capabilities(self):
        return self.local_capabilities & self.peer_capabilities

    @property
    def common_protocols(self):
        return set(self.local_protocols) & set(self.peer_protocols)

    def create_open_message(self):
        msg = bgpkit.message.OpenMessage()
        if self.local_router_id is not None:
            msg.router_id = self.local_router_id
        if Capability.ASN4 in self.local_capabilities:
            msg.asn = AS_TRANS
            msg.parameters.append(bgpkit.message.FourOctetASNCapability(
                self.local_as).as_param())
        else:
            msg.asn = self.local_as
        for afi, safi in self.local_protocols:
            msg.parameters.append(bgpkit.message.MultiprotocolCapability(
                afi, safi).as_param())
        msg.hold_time = self.hold_time
        return msg

    def handle_message(self, msg):
        if msg.type_ == bgpkit.message.MessageType.OPEN:
            return self.handle_open_message(msg)
        elif msg.type_ == bgpkit.message.MessageType.KEEPALIVE:
            if self.state == State.OPEN_CONFIRM:
                self.state = State.ESTABLISHED
        elif msg.type_ == bgpkit.message.MessageType.NOTIFICATION:
            self.state = State.IDLE
            self.last_error = msg
        elif msg.type_ == bgpkit.message.MessageType.UPDATE:
            if self.state != State.ESTABLISHED:
                self.state = State.IDLE
                return [bgpkit.message.NotificationMessage()]
        return None

    def handle_open_message(self, msg):
        if self.state == State.ESTABLISHED:
            self.state = State.IDLE
            return [bgpkit.message.NotificationMessage()]
        elif self.state == State.OPEN_CONFIRM:
            self.state = State.IDLE
            return [bgpkit.message.NotificationMessage()]
        self.peer_protocols = []
        self.peer_capabilities = set()
        if self.peer_as is None:
            self.peer_as = msg.asn
        elif self.peer_as != msg.asn:
            self.state = State.IDLE
            return [bgpkit.message.NotificationMessage()]
        if self.peer_router_id is None:
            self.peer_router_id = msg.router_id
        elif self.peer_router_id != msg.router_id:
            self.state = State.IDLE
            return [bgpkit.message.NotificationMessage()]
        for capability in msg.capabilities():
            if isinstance(capability, bgpkit.message.MultiprotocolCapability):
                self.peer_protocols.append((capability.afi, capability.safi))
            capability = Capability.from_capability_msg(capability)
            if capability:
                self.peer_capabilities.add(capability)
        if self.state == State.CONNECT:
            self.state = State.OPEN_CONFIRM
            return [self.create_open_message(),
                    bgpkit.message.KeepaliveMessage()]
        elif self.state == State.OPEN_SENT:
            self.state = State.OPEN_CONFIRM
            return [bgpkit.message.KeepaliveMessage()]

    def parse_message(self, msg):
        msg = bgpkit.message.Message.from_bytes(
            msg, coerce=True,
            asn4=Capability.ASN4 in self.common_capabilities)
        return msg
