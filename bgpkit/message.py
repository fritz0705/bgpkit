from __future__ import annotations

import asyncio
import enum
from typing import *

import netaddr


class MessageType(int):
    """A MessageType object represents one of the BGP message types, which are
    defined in RFC 4271. Standard message types are
    `MessageType.OPEN`, `MessageType.UPDATE`, `MessageType.NOTIFICATION`,
    and `MessageType.KEEPALIVE` for OPEN, UPDATE, NOTIFICATION, and KEEPALIVE
    messages, respectively. """

    UNKNOWN: MessageType
    OPEN: MessageType
    UPDATE: MessageType
    NOTIFICATION: MessageType
    KEEPALIVE: MessageType
    ROUTE_REFRESH: MessageType

    def __init__(self, _int: int) -> None:
        if 255 < _int or _int < 0:
            raise ValueError("A MessageType value must be between 0 and 255")
        super().__init__()

    def __str__(self) -> str:
        return repr(self)

    def __repr__(self) -> str:
        if self == self.UNKNOWN:
            return "MessageType.UNKNOWN"
        elif self == self.OPEN:
            return "MessageType.OPEN"
        elif self == self.UPDATE:
            return "MessageType.UPDATE"
        elif self == self.NOTIFICATION:
            return "MessageType.NOTIFICATION"
        elif self == self.KEEPALIVE:
            return "MessageType.KEEPALIVE"
        elif self == self.ROUTE_REFRESH:
            return "MessageType.ROUTE_REFRESH"
        return f"MessageType({int(self)!r})"


MessageType.UNKNOWN = MessageType(0)
MessageType.OPEN = MessageType(1)
MessageType.UPDATE = MessageType(2)
MessageType.NOTIFICATION = MessageType(3)
MessageType.KEEPALIVE = MessageType(4)
MessageType.ROUTE_REFRESH = MessageType(5)


class Message(object):
    """ A Message that represents a single BGP-4 message. The payload is stored
    in the `payload` field and the type of the message is stored in `type_`
    as a `MessageType` value. """

    type_: MessageType
    payload: bytes

    def __init__(self, type_: int, payload: bytes=b"") -> None:
        """Constructs a generic BGP message from `MessageType`, given in
        `type_`, and message payload, given in `payload`."""
        self.type_ = MessageType(type_)
        self.payload = bytes(payload)

    @property
    def length(self) -> int:
        """Length of the encoded BGP message, including the marker and payload.
        """
        return len(self.payload) + 19

    def to_bytes(self) -> bytes:
        """Encodes the BGP message to bytes-like object."""
        b = bytearray()
        b.extend(b"\xff" * 16)
        b.extend(self.length.to_bytes(2, byteorder="big"))
        b.extend(self.type_.to_bytes(1, byteorder="big"))
        b.extend(self.payload)
        return b

    @classmethod
    def from_bytes(cls, b: bytes) -> Message:
        """Decode BGP message from bytes-like object."""
        length = int.from_bytes(b[16:18], byteorder="big")
        type_ = MessageType(int.from_bytes(b[18:19], byteorder="big"))
        msg = cls(type_, b[19:])
        return msg

    def __repr__(self) -> str:
        return f"<Message length={self.length!r} type={self.type_!r} " \
            f"payload={self.payload!r}>"


class OpenMessage(Message):
    type_: MessageType = MessageType.OPEN
    version: int
    asn: int
    hold_time: int
    bgp_identifier: int
    parameters: List[Parameter]

    def __init__(self, version: int=4, asn: int=23456, hold_time: int=0,
                 bgp_identifier: int=0,
                 router_id: Optional[netaddr.IPAddress]=None,
                 parameters: List[Parameter]=[]) -> None:
        self.version = version
        self.asn = asn
        self.hold_time = int(hold_time)
        self.bgp_identifier = int(bgp_identifier)
        if router_id is not None:
            self.router_id = router_id
        self.parameters = list(parameters)

    @property
    def length(self) -> int:
        return 19 + 10 + len(self._to_bytes_parameters())

    @property
    def router_id(self) -> netaddr.IPAddress:
        return netaddr.IPAddress(self.bgp_identifier)

    @router_id.setter
    def router_id(self, val: SupportsInt) -> None:
        self.bgp_identifier = int(val)

    def capabilities(self) -> Generator[Capability, None, None]:
        for param in self.parameters:
            if not isinstance(param, CapabilityParameter):
                continue
            yield from param.capabilities

    def get_capabilities(self, _t: Type[Capability]) \
            -> Generator[Capability, None, None]:
        for cap in self.capabilities():
            if isinstance(cap, _t):
                yield cap

    def __repr__(self) -> str:
        return f"<OpenMessage version={self.version!r} asn={self.asn!r} " \
            f"hold_time={self.hold_time!r} "\
            f"router_id={self.router_id!r} "\
            f"parameters={self.parameters!r}>"

    @property
    def payload(self) -> bytes:
        b = bytearray()
        b.extend(self.version.to_bytes(1, byteorder="big"))
        b.extend(self.asn.to_bytes(2, byteorder="big"))
        b.extend(self.hold_time.to_bytes(2, byteorder="big"))
        b.extend(self.bgp_identifier.to_bytes(4, byteorder="big"))
        params_b = self._to_bytes_parameters()
        b.extend(len(params_b).to_bytes(1, byteorder="big"))
        b.extend(params_b)
        return b

    def _to_bytes_parameters(self) -> bytes:
        b = bytearray()
        for parameter in self.parameters:
            b.extend(parameter.to_bytes())
        return b

    @classmethod
    def from_bytes(cls, b: bytes) -> OpenMessage:
        b = Message.from_bytes(b).payload
        return cls.from_payload(b)

    @classmethod
    def from_payload(cls, b: bytes) -> OpenMessage:
        version = int.from_bytes(b[0:1], "big")
        asn = int.from_bytes(b[1:3], "big")
        hold_time = int.from_bytes(b[3:5], "big")
        bgp_identifier = int.from_bytes(b[5:9], "big")
        msg = cls(version, asn, hold_time, bgp_identifier)

        opt_param_len = int.from_bytes(b[9:10], "big")
        b = b[10:]
        while opt_param_len >= 2:
            param = Parameter.from_bytes(b)
            param_len = len(param.to_bytes())
            msg.parameters.append(param)
            opt_param_len -= param_len
            b = b[param_len:]
        return msg


class Parameter(object):
    type_: int
    payload: bytes

    def __init__(self, type_: int=0, payload: bytes=b"") -> None:
        self.type_ = type_
        self.payload = bytes(payload)

    def __repr__(self) -> str:
        return f"<Parameter type={self.type_!r} " \
            f"payload={self.payload!r}>"

    def to_bytes(self) -> bytes:
        b = bytearray()
        b.append(self.type_)
        b.append(len(self.payload))
        b.extend(self.payload)
        return b

    @classmethod
    def from_bytes(cls, b: bytes) -> Parameter:
        param = cls(b[0])
        param.payload = b[2:2 + b[1]]
        return param


class CapabilityParameter(Parameter):
    type_ = 2

    def __init__(self, capabilities: List[Capability]=[]) -> None:
        self.capabilities = list(capabilities)

    def __repr__(self) -> str:
        return f"<CapabilityParameter capabilities={self.capabilities!r}>"

    @property
    def payload(self) -> bytes:
        b = bytearray()
        for capability in self.capabilities:
            b.extend(capability.to_bytes())
        return b

    @classmethod
    def from_bytes(cls, b: bytes) -> CapabilityParameter:
        return cls.from_parameter(Parameter.from_bytes(b))

    @classmethod
    def from_parameter(cls, param: Parameter) -> CapabilityParameter:
        b = param.payload
        param = cls()
        while len(b) >= 2:
            cap = Capability.from_bytes(b)
            param.capabilities.append(cap)
            b = b[len(cap.to_bytes()):]
        return param


class Capability(object):
    payload: bytes
    type_: int

    def __init__(self, type_: int, payload: bytes=b""):
        self.type_ = type_
        self.payload = payload

    def __repr__(self) -> str:
        return f"<Capability type={self.type_!r} payload={self.payload!r}>"

    def as_param(self) -> CapabilityParameter:
        return CapabilityParameter([self])

    def to_bytes(self) -> bytes:
        b = bytearray()
        b.append(self.type_)
        b.append(len(self.payload))
        b.extend(self.payload)
        return b

    @classmethod
    def from_bytes(cls, b: bytes) -> Capability:
        return cls(b[0], b[2:2 + b[1]])

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, Capability):
            return False
        return self.to_bytes() == other.to_bytes()

    def __hash__(self) -> int:
        return hash(bytes(self.to_bytes()))


class FourOctetASNCapability(Capability):
    type_ = 65

    def __init__(self, asn: int) -> None:
        self.asn = asn

    @property
    def payload(self) -> bytes:
        return self.asn.to_bytes(4, byteorder="big")

    def __repr__(self) -> str:
        return f"<FourOctetASNCapability asn={self.asn!r}>"

    @classmethod
    def from_bytes(cls, b: bytes) -> FourOctetASNCapability:
        b = Capability.from_bytes(b).payload
        return cls(int.from_bytes(b[0:4], byteorder="big"))


class AFI(int):
    AFI_IPV4: ClassVar[AFI]
    AFI_IPV6: ClassVar[AFI]
    AFI_NSAP: ClassVar[AFI]
    AFI_HDLC: ClassVar[AFI]
    AFI_BBN_1822: ClassVar[AFI]
    AFI_802: ClassVar[AFI]
    AFI_E163: ClassVar[AFI]
    AFI_E164: ClassVar[AFI]
    AFI_F69: ClassVar[AFI]
    AFI_BGP_LS: ClassVar[AFI]

    def __init__(self, _int: int) -> None:
        if _int > 65535 or 0 > _int:
            raise ValueError("A AFI value must be between 0 and 65535")
        super().__init__()

    def __str__(self) -> str:
        return repr(self)

    def __repr__(self) -> str:
        if self == self.AFI_IPV4:
            return "AFI.AFI_IPV4"
        elif self == self.AFI_IPV6:
            return "AFI.AFI_IPV6"
        elif self == self.AFI_NSAP:
            return "AFI.AFI_NSAP"
        elif self == self.AFI_HDLC:
            return "AFI.AFI_HDLC"
        elif self == self.AFI_BBN_1822:
            return "AFI.AFI_BBN_1822"
        elif self == self.AFI_802:
            return "AFI.AFI_802"
        elif self == self.AFI_E163:
            return "AFI.AFI_E163"
        elif self == self.AFI_E164:
            return "AFI.AFI_E164"
        elif self == self.AFI_F69:
            return "AFI.AFI_F69"
        elif self == self.AFI_BGP_LS:
            return "AFI.AFI_BGP_LS"
        return f"AFI({int(self)!r})"


AFI.AFI_IPV4 = AFI(1)
AFI.AFI_IPV6 = AFI(2)
AFI.AFI_NSAP = AFI(3)
AFI.AFI_HDLC = AFI(4)
AFI.AFI_BBN_1822 = AFI(5)
AFI.AFI_802 = AFI(6)
AFI.AFI_E163 = AFI(7)
AFI.AFI_E164 = AFI(8)
AFI.AFI_F69 = AFI(9)
AFI.AFI_BGP_LS = AFI(16388)


class SAFI(int):
    SAFI_UNICAST: ClassVar[SAFI]
    SAFI_MULTICAST: ClassVar[SAFI]
    SAFI_BGP_LS: ClassVar[SAFI]
    SAFI_BGP_LS_VPN: ClassVar[SAFI]
    SAFI_FLOW4: ClassVar[SAFI]
    SAFI_FLOW4_VPN: ClassVar[SAFI]

    def __init__(self, _int: int) -> None:
        if 255 < _int or _int < 0:
            raise ValueError("A SAFI value must be between 0 and 255")
        super().__init__()

    def __str__(self) -> str:
        return repr(self)

    def __repr__(self) -> str:
        if self == self.SAFI_UNICAST:
            return "SAFI.SAFI_UNICAST"
        elif self == self.SAFI_MULTICAST:
            return "SAFI.SAFI_MULTICAST"
        elif self == self.SAFI_BGP_LS:
            return "SAFI.SAFI_BGP_LS"
        elif self == self.SAFI_BGP_LS_VPN:
            return "SAFI.SAFI_BGP_LS_VPN"
        elif self == self.SAFI_FLOW4:
            return "SAFI.SAFI_FLOW4"
        elif self == self.SAFI_FLOW4_VPN:
            return "SAFI.SAFI_FLOW4_VPN"
        return f"SAFI({int(self)!r})"


SAFI.SAFI_UNICAST = SAFI(1)
SAFI.SAFI_MULTICAST = SAFI(2)
SAFI.SAFI_BGP_LS = SAFI(71)
SAFI.SAFI_BGP_LS_VPN = SAFI(72)
SAFI.SAFI_FLOW4 = SAFI(133)
SAFI.SAFI_FLOW4_VPN = SAFI(134)

ProtoTuple = Tuple[AFI, SAFI]


class MultiprotocolCapability(Capability):
    type_ = 1

    def __init__(self, afi: int, safi: int) -> None:
        self.afi = AFI(afi)
        self.safi = SAFI(safi)

    @property
    def payload(self) -> bytes:
        return self.afi.to_bytes(2, byteorder="big") + b"\0" + \
            self.safi.to_bytes(1, byteorder="big")

    def __repr__(self) -> str:
        return f"<MultiprotocolCapability afi={self.afi!r} " \
            f"safi={self.safi!r}>" \


    @classmethod
    def from_bytes(cls, b: bytes) -> MultiprotocolCapability:
        b = Capability.from_bytes(b).payload
        return cls(
            int.from_bytes(b[0:2], byteorder="big"),
            int.from_bytes(b[3:4], byteorder="big"))


class GracefulRestartCapability(Capability):
    type_ = 64
    restart_flags: int
    restart_time: int
    tuples: List[Tuple[AFI, SAFI, int]]

    def __init__(self, restart_flags: int=0,
                 restart_time: int=0,
                 tuples: List[Tuple[AFI, SAFI, int]]=[]) -> None:
        self.restart_flags = restart_flags
        self.restart_time = restart_time
        self.tuples = list(tuples)

    def __repr__(self) -> str:
        return f"<GracefulRestartCapability " \
            f"restart_flags={self.restart_flags!r} " \
            f"restart_time={self.restart_time!r} " \
            f"tuples={self.tuples!r}>"

    @property
    def payload(self) -> bytes:
        b = bytearray()
        return b

    @classmethod
    def from_bytes(cls, b: bytes) -> GracefulRestartCapability:
        b = Capability.from_bytes(b).payload
        restart_flags = int.from_bytes(b[0:2], byteorder="big")
        restart_time = restart_flags & 0xfff
        restart_flags = restart_flags >> 12
        cap = cls(restart_flags=restart_flags,
                  restart_time=restart_time)
        b = b[2:]
        while not b and len(b) >= 4:
            afi = int.from_bytes(b[0:2], byteorder="big")
            safi = b[2]
            flags = b[3]
            cap.tuples.append((AFI(afi), SAFI(safi), flags))
            b = b[4:]
        return cap


class AddPathCapability(Capability):
    type_ = 69
    protos: Set[Tuple[AFI, SAFI, int]]

    def __init__(self, protos: Set[Tuple[AFI, SAFI, int]]=set()) -> None:
        self.protos = set(protos)

    def __repr__(self) -> str:
        return f"<AddPathCapability {self.protos!r}>"

    @property
    def payload(self) -> bytes:
        b = bytearray()
        for afi, safi, send_receive in self.protos:
            b.extend(afi.to_bytes(2, byteorder="big"))
            b.extend(safi.to_bytes(1, byteorder="big"))
            b.extend(send_receive.to_bytes(1, byteorder="big"))
        return b

    @classmethod
    def from_bytes(cls, b: bytes) -> AddPathCapability:
        b = Capability.from_bytes(b).payload
        cap = cls()
        while len(b) >= 4:
            afi = AFI(int.from_bytes(b[0:2], byteorder="big"))
            safi = SAFI(int.from_bytes(b[2:3], byteorder="big"))
            send_receive = int.from_bytes(b[3:4], byteorder="big")
            cap.protos.add((afi, safi, send_receive))
            b = b[4:]
        return cap

    def __and__(self, other: AddPathCapability) -> AddPathCapability:
        return AddPathCapability(self.protos & other.protos)


class RouteRefreshCapability(Capability):
    type_ = 2

    def __init__(self) -> None:
        pass

    def __repr__(self) -> str:
        return f"<RouteRefreshCapability>"

    @property
    def payload(self) -> bytes:
        return b""

    @classmethod
    def from_bytes(cls, b: bytes) -> RouteRefreshCapability:
        return cls()


class PathAttribute(object):
    FLAG_EXTENDED_LENGTH: ClassVar[int] = 16
    FLAG_PARTIAL: ClassVar[int] = 32
    FLAG_TRANSITIVE: ClassVar[int] = 64
    FLAG_OPTIONAL: ClassVar[int] = 128

    payload: bytes
    type_: int
    flags: int

    def __init__(self, flags: int=0, type_: int=0, payload: bytes=b"") -> None:
        self.type_ = type_
        self.flags = flags
        self.payload = payload

    @property
    def is_partial(self) -> bool:
        return bool(self.flags & self.FLAG_PARTIAL)

    @is_partial.setter
    def is_partial(self, b: bool) -> None:
        self.flags ^= self.flags & self.FLAG_PARTIAL * (not b)

    @property
    def is_transitive(self) -> bool:
        return bool(self.flags & self.FLAG_TRANSITIVE)

    @is_transitive.setter
    def is_transitive(self, b: bool) -> None:
        self.flags ^= self.flags & self.FLAG_TRANSITIVE * (not b)

    @property
    def is_optional(self) -> bool:
        return bool(self.flags & self.FLAG_OPTIONAL)

    @is_optional.setter
    def is_optional(self, b: bool) -> None:
        self.flags ^= self.flags & self.FLAG_OPTIONAL * (not b)

    @property
    def extended_length(self) -> bool:
        return bool(self.flags & self.FLAG_EXTENDED_LENGTH)

    @extended_length.setter
    def extended_length(self, b: bool) -> None:
        self.flags ^= self.flags & self.FLAG_EXTENDED_LENGTH * (not b)

    @property
    def length(self) -> int:
        return len(self.payload) + 3 + (1 if self.extended_length else 0)

    def to_bytes(self) -> bytes:
        b = bytearray()
        payload = self.payload
        if len(payload) > 255:
            self.extended_length = True
        b.append(self.flags)
        b.append(self.type_)
        if self.extended_length:
            b.extend(len(self.payload).to_bytes(2, byteorder="big"))
        else:
            b.extend(len(self.payload).to_bytes(1, byteorder="big"))
        b.extend(self.payload)
        return b

    @property
    def flag_code(self) -> str:
        return ('O' if self.is_optional else '-') + \
            ('T' if self.is_transitive else '-') + \
            ('P' if self.is_partial else '-') + \
            ('E' if self.extended_length else '-')

    def __repr__(self) -> str:
        return f"<PathAttribute type={self.type_!r} " \
            f"flags={self.flag_code} " \
            f"payload={self.payload!r}>"

    @classmethod
    def from_bytes(cls, b: bytes) -> PathAttribute:
        attr = cls(b[0], b[1])
        if attr.extended_length:
            d_len = int.from_bytes(b[2:4], byteorder="big")
            attr.payload = b[4:4 + d_len]
        else:
            d_len = b[2]
            attr.payload = b[3:3 + d_len]
        return attr


class MultiprotocolReachableNLRI(PathAttribute):
    type_ = 14

    afi: AFI
    safi: SAFI
    next_hop: bytes
    nlri: List[NLRI]
    nlri_raw: Optional[bytes]

    def __init__(self, afi: int, safi: int, next_hop: bytes,
                 nlri: List[NLRI]=[], nlri_raw: Optional[bytes]=None,
                 flags: int=PathAttribute.FLAG_OPTIONAL) -> None:
        self.flags = flags
        self.afi = AFI(afi)
        self.safi = SAFI(safi)
        self.next_hop = next_hop
        self.nlri = list(nlri)
        self.nlri_raw = nlri_raw

    def __repr__(self) -> str:
        if self.nlri_raw is not None:
            return f"<MultiprotocolReachableNLRI afi={self.afi!r} " \
                f"safi={self.safi!r} " \
                f"next_hop={self.next_hop!r} " \
                f"nlri_raw={self.nlri_raw!r}>"
        return f"<MultiprotocolReachableNLRI afi={self.afi!r} " \
            f"safi={self.safi!r} " \
            f"next_hop={self.next_hop!r} " \
            f"nlri={self.nlri!r}>"

    @property
    def payload(self) -> bytes:
        b = bytearray()
        b.extend(self.afi.to_bytes(2, byteorder="big"))
        b.extend(self.safi.to_bytes(1, byteorder="big"))
        next_hop = self.next_hop
        b.extend(len(next_hop).to_bytes(1, byteorder="big"))
        b.extend(next_hop)
        b.extend(b"\0")
        if self.nlri_raw is not None:
            b.extend(self.nlri_raw)
        else:
            for nlri in self.nlri:
                b.extend(nlri.to_bytes())
        return b

    @classmethod
    def from_bytes(cls, b: bytes) -> MultiprotocolReachableNLRI:
        attr = PathAttribute.from_bytes(b)
        return cls.from_attribute(attr)

    @classmethod
    def from_attribute(cls, attr: PathAttribute) -> MultiprotocolReachableNLRI:
        b = attr.payload
        afi, safi = int.from_bytes(b[0:2], byteorder="big"), b[2]
        next_hop_len = b[3]
        next_hop = b[4:4 + next_hop_len]
        nlri_raw = b[5 + next_hop_len:]
        attr = cls(afi, safi, next_hop, nlri_raw=nlri_raw, flags=attr.flags)
        return attr


class MultiprotocolUnreachableNLRI(PathAttribute):
    type_ = 15
    afi: AFI
    safi: SAFI
    nlri: List[NLRI]
    nlri_raw: Optional[bytes]

    def __init__(self, afi: int, safi: int, nlri: List[NLRI]=[],
                 nlri_raw: Optional[bytes]=None,
                 flags: int=PathAttribute.FLAG_OPTIONAL) -> None:
        self.flags = flags
        self.afi = AFI(afi)
        self.safi = SAFI(safi)
        self.nlri = list(nlri)
        self.nlri_raw = nlri_raw

    def __repr__(self) -> str:
        if self.nlri_raw is not None:
            return f"<MultiprotocolUnreachableNLRI afi={self.afi!r} " \
                f"safi={self.safi!r} " \
                f"nlri_raw={self.nlri_raw!r}>"
        return f"<MultiprotocolUnreachableNLRI afi={self.afi!r} " \
            f"safi={self.safi!r} " \
            f"nlri={self.nlri!r}>"

    @property
    def payload(self) -> bytes:
        b = bytearray()
        b.extend(self.afi.to_bytes(2, byteorder="big"))
        b.extend(self.safi.to_bytes(1, byteorder="big"))
        if self.nlri_raw is not None:
            b.extend(self.nlri_raw)
        else:
            for nlri in self.nlri:
                b.extend(nlri.to_bytes())
        return b

    @classmethod
    def from_bytes(cls, b: bytes) -> MultiprotocolUnreachableNLRI:
        attr = PathAttribute.from_bytes(b)
        return cls.from_attribute(attr)

    @classmethod
    def from_attribute(cls, attr: PathAttribute) \
            -> MultiprotocolUnreachableNLRI:
        b = attr.payload
        afi, safi = int.from_bytes(b[0:2], byteorder="big"), b[2]
        return cls(afi, safi, nlri_raw=b[3:], flags=attr.flags)


ORIGIN_IGP = 0
ORIGIN_EGP = 1
ORIGIN_INCOMPLETE = 2

class OriginAttribute(PathAttribute):
    type_ = 1

    def __init__(self, origin: int,
                 flags: int=PathAttribute.FLAG_TRANSITIVE) -> None:
        self.origin = origin
        self.flags = flags

    @property
    def origin_name(self) -> str:
        return {
            0: "IGP",
            1: "EGP",
            2: "INCOMPLETE"
        }[self.origin]

    @origin_name.setter
    def origin_name(self, s: str) -> None:
        self.origin = {
            "IGP": 0,
            "EGP": 1,
            "INCOMPLETE": 2
        }[s]

    @property
    def payload(self) -> bytes:
        return self.origin.to_bytes(1, byteorder="big")

    def __repr__(self) -> str:
        return f"<OriginAttribute origin={self.origin_name}>"

    @classmethod
    def from_bytes(cls, b: bytes) -> OriginAttribute:
        return cls.from_attribute(PathAttribute.from_bytes(b))

    @classmethod
    def from_attribute(cls, attr: PathAttribute) -> OriginAttribute:
        return cls(attr.payload[0], attr.flags)


class ASPathSegmentType(enum.Enum):
    AS_SET = 1
    AS_SEQUENCE = 2


class ASPathAttribute(PathAttribute):
    type_ = 2
    segments: List[Union[Set[int], List[int]]]

    def __init__(self, segments: List[Union[Set[int], List[int]]]=[],
                 flags: int=PathAttribute.FLAG_TRANSITIVE) -> None:
        self.segments = list(segments)
        self.flags = flags

    def __repr__(self) -> str:
        return f"<ASPathAttribute {self.segments!r}>"

    @property
    def payload(self) -> bytes:
        b = bytearray()
        for segment in self.segments:
            segment_type = ASPathSegmentType.AS_SET \
                if isinstance(segment, set) \
                else ASPathSegmentType.AS_SEQUENCE
            b.append(segment_type.value)
            b.append(len(segment))
            for asn in segment:
                b.extend(asn.to_bytes(2, byteorder="big"))
        return b

    @classmethod
    def from_bytes(cls, b: bytes) -> ASPathAttribute:
        attr = PathAttribute.from_bytes(b)
        return cls.from_attribute(attr)

    @classmethod
    def from_attribute(cls, attr: PathAttribute) -> ASPathAttribute:
        b = attr.payload
        attr = cls(flags=attr.flags)
        while b:
            segment = []
            segment_type = ASPathSegmentType(b[0])
            segment_len = b[1]
            b = b[2:]
            for asn in range(segment_len):
                segment.append(int.from_bytes(b[0:2], byteorder="big"))
                b = b[2:]
            if segment_type == ASPathSegmentType.AS_SET:
                attr.segments.append(set(segment))
            else:
                attr.segments.append(segment)
        return attr


class AS4PathAttribute(ASPathAttribute):
    type_ = 2

    def __init__(self, *args, type_: int=2, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.type_ = property(self._get_type, self._set_type)
        self.type_ = type_

    def _get_type(self) -> int:
        return self._type

    def _set_type(self, type_: int) -> None:
        if type_ not in {2, 17}:
            pass
        self._type = type_

    def __repr__(self) -> str:
        return f"<AS4PathAttribute {self.segments!r}>"

    @property
    def payload(self) -> bytes:
        b = bytearray()
        for segment in self.segments:
            segment_type = ASPathSegmentType.AS_SET \
                if isinstance(segment, set) \
                else ASPathSegmentType.AS_SEQUENCE
            b.append(segment_type.value)
            b.append(len(segment))
            for asn in segment:
                b.extend(asn.to_bytes(4, byteorder="big"))
        return b

    @classmethod
    def from_bytes(cls, b: bytes) -> AS4PathAttribute:
        return cls.from_attribute(PathAttribute.from_bytes(b))

    @classmethod
    def from_attribute(cls, attr: PathAttribute) -> AS4PathAttribute:
        b = attr.payload
        attr = cls(flags=attr.flags, type_=attr.type_)
        while b:
            segment = []
            segment_type = ASPathSegmentType(b[0])
            segment_len = b[1]
            b = b[2:]
            for asn in range(segment_len):
                segment.append(int.from_bytes(b[0:4], byteorder="big"))
                b = b[4:]
            if segment_type == ASPathSegmentType.AS_SET:
                attr.segments.append(set(segment))
            else:
                attr.segments.append(segment)
        return attr


class NextHopAttribute(PathAttribute):
    type_ = 3
    next_hop: netaddr.IPAddress

    def __init__(self, next_hop: netaddr.IPAddress,
                 flags: int=PathAttribute.FLAG_TRANSITIVE) -> None:
        self.next_hop = next_hop
        self.flags = flags

    @property
    def payload(self) -> bytes:
        return bytes(self.next_hop.packed)

    def __repr__(self) -> str:
        return f"<NextHopAttribute {self.next_hop!r}>"

    @classmethod
    def from_bytes(cls, b: bytes) -> NextHopAttribute:
        return cls.from_attribute(PathAttribute.from_bytes(b))

    @classmethod
    def from_attribute(cls, attr: PathAttribute) -> NextHopAttribute:
        b = attr.payload
        return cls(netaddr.IPAddress(int.from_bytes(b[0:4], byteorder="big")),
                   flags=attr.flags)


class MultiExitDisc(PathAttribute):
    type_ = 4

    def __init__(self, med: int,
                 flags: int=PathAttribute.FLAG_OPTIONAL) -> None:
        self.med = med
        self.flags = flags

    @property
    def payload(self) -> bytes:
        return self.med.to_bytes(4, byteorder="big")

    def __repr__(self) -> str:
        return f"<MultiExitDisc {self.med!r}>"

    @classmethod
    def from_bytes(cls, b: bytes) -> MultiExitDisc:
        attr = PathAttribute.from_bytes(b)
        return cls.from_attribute(attr)

    @classmethod
    def from_attribute(cls, attr: PathAttribute) -> MultiExitDisc:
        b = attr.payload
        return cls(int.from_bytes(b[0:4], byteorder="big"), flags=attr.flags)


class LocalPrefAttribute(PathAttribute):
    type_ = 5

    def __init__(self, local_pref: int,
                 flags: int=PathAttribute.FLAG_TRANSITIVE) -> None:
        self.local_pref = local_pref
        self.flags = flags

    @property
    def payload(self) -> bytes:
        return self.local_pref.to_bytes(4, byteorder="big")

    def __repr__(self) -> str:
        return f"<LocalPrefAttribute {self.local_pref!r}>"

    @classmethod
    def from_bytes(cls, b: bytes) -> LocalPrefAttribute:
        attr = PathAttribute.from_bytes(b)
        return cls.from_attribute(attr)

    @classmethod
    def from_attribute(cls, attr: PathAttribute) -> LocalPrefAttribute:
        b = attr.payload
        return cls(int.from_bytes(b[0:4], byteorder="big"), flags=attr.flags)


class AtomicAggregateAttribute(PathAttribute):
    type_ = 6

    def __init__(self, flags: int=PathAttribute.FLAG_TRANSITIVE) -> None:
        self.flags = flags

    @property
    def payload(self) -> bytes:
        return b""

    def __repr__(self) -> str:
        return "<AtomicAggregateAttribute>"

    @classmethod
    def from_bytes(cls, b: bytes) -> AtomicAggregateAttribute:
        attr = PathAttribute.from_bytes(b)
        return cls(flags=attr.flags)

    @classmethod
    def from_attribute(cls, attr: PathAttribute) -> AtomicAggregateAttribute:
        return cls(flags=attr.flags)


class AggregatorAttribute(PathAttribute):
    type_ = 7
    asn: int
    ip_address: netaddr.IPAddress

    def __init__(self, asn: int, ip_address: netaddr.IPAddress,
                 flags: int=PathAttribute.FLAG_OPTIONAL |
                 PathAttribute.FLAG_TRANSITIVE) -> None:
        self.asn = asn
        self.ip_address = ip_address
        self.flags = flags

    @property
    def payload(self) -> bytes:
        b = self.asn.to_bytes(2, byteorder="big")
        return bytes(b + self.ip_address.packed)

    def __repr__(self) -> str:
        return f"<AggregatorAttribute asn={self.asn!r} " \
            f"ip_address={self.ip_address!r}>"

    @classmethod
    def from_bytes(cls, b: bytes) -> AggregatorAttribute:
        attr = PathAttribute.from_bytes(b)
        return cls.from_attribute(attr)

    @classmethod
    def from_attribute(cls, attr: PathAttribute) -> AggregatorAttribute:
        b = attr.payload
        asn = int.from_bytes(b[0:2], byteorder="big")
        b = b[2:]
        return cls(asn,
                   netaddr.IPAddress(int.from_bytes(b[0:4], byteorder="big")),
                   flags=attr.flags)


class Aggregator4Attribute(AggregatorAttribute):
    _type: int

    def __init__(self, *args, type_: int=7, **kwargs):
        super().__init__(*args, **kwargs)
        self.type_ = type_

    @property
    def type_(self) -> int:
        return self._type
    
    @type_.setter
    def type_(self, type_: int) -> None:
        if type_ not in {7, 18}:
            # TODO Raise exception
            pass
        self._type = type_

    @property
    def payload(self) -> bytes:
        b = self.asn.to_bytes(4, byteorder="big")
        return bytes(b + self.ip_address.packed)

    def __repr__(self) -> str:
        return f"<Aggregator4Attribute asn={self.asn!r} " \
            f"ip_address={self.ip_address}>"

    @classmethod
    def from_attribute(cls, attr: PathAttribute) -> AggregatorAttribute:
        b = attr.payload
        asn = int.from_bytes(b[0:4], byteorder="big")
        b = b[4:]
        return cls(asn,
                   netaddr.IPAddress(int.from_bytes(b[0:4], byteorder="big")),
                   flags=attr.flags,
                   type_=attr.type_)


class CommunitiesAttribute(PathAttribute):
    type_ = 8
    communities: List[int]

    def __init__(self, communities: List[int]=[],
                 flags: int=PathAttribute.FLAG_TRANSITIVE |
                 PathAttribute.FLAG_OPTIONAL) -> None:
        self.communities = list(communities)
        self.flags = flags

    def __repr__(self) -> str:
        return f"<CommunitiesAttribute {self.pairs!r}>"

    @property
    def pairs(self) -> List[Tuple[int, int]]:
        c = []
        for community in self.communities:
            c.append((community >> 16, community & 0xffff))
        return c

    @pairs.setter
    def pairs(self, pairs: List[Tuple[int, int]]) -> None:
        self.communities = []
        for pair in pairs:
            self.communities.append(pair[0] << 16 | pair[1])

    @property
    def payload(self) -> bytes:
        b = bytearray()
        for community in self.communities:
            b.extend(community.to_bytes(4, byteorder="big"))
        return b

    @classmethod
    def from_bytes(cls, b: bytes) -> CommunitiesAttribute:
        attr = PathAttribute.from_bytes(b)
        return cls.from_attribute(attr)

    @classmethod
    def from_attribute(cls, attr: PathAttribute) -> CommunitiesAttribute:
        b = attr.payload
        attr = cls(flags=attr.flags)
        while b:
            attr.communities.append(int.from_bytes(b[0:4], byteorder="big"))
            b = b[4:]
        return attr


LargeCommunity = Tuple[int, int, int]


class LargeCommunitiesAttribute(PathAttribute):
    type_ = 32
    communities: List[LargeCommunity]

    def __init__(self, communities: List[LargeCommunity]=[],
                 flags: int=PathAttribute.FLAG_OPTIONAL |
                 PathAttribute.FLAG_TRANSITIVE) -> None:
        self.communities = list(communities)
        self.flags = flags

    def __repr__(self) -> str:
        return f"<LargeCommunitiesAttribute {self.communities!r}>"

    @property
    def payload(self) -> bytes:
        b = bytearray()
        for global_admin, local_1, local_2 in self.communities:
            b.extend(global_admin.to_bytes(4, byteorder="big"))
            b.extend(local_1.to_bytes(4, byteorder="big"))
            b.extend(local_2.to_bytes(4, byteorder="big"))
        return b

    @classmethod
    def from_bytes(cls, b: bytes) -> LargeCommunitiesAttribute:
        attr = PathAttribute.from_bytes(b)
        return cls.from_attribute(attr)

    @classmethod
    def from_attribute(cls, attr: PathAttribute) -> LargeCommunitiesAttribute:
        b = attr.payload
        attr = cls(flags=attr.flags)
        while len(b) >= 12:
            global_admin = int.from_bytes(b[0:4], byteorder="big")
            local_1 = int.from_bytes(b[4:8], byteorder="big")
            local_2 = int.from_bytes(b[8:12], byteorder="big")
            attr.communities.append((global_admin, local_1, local_2))
            b = b[12:]
        return attr


def nlri_to_netaddr(prefix, payload, afi: AFI) -> netaddr.IPNetwork:
    addr = payload.ljust(4 if afi == AFI.AFI_IPV4 else 16, b'\0')
    version = 4 if afi == AFI.AFI_IPV4 else 6
    return netaddr.IPNetwork((int.from_bytes(addr, byteorder="big"), prefix),
                             version=version)


def netaddr_to_nlri(network: netaddr.IPNetwork) -> Tuple[int, bytes]:
    return (network.prefixlen, network.packed[:nlri_octets(network.prefixlen)])


def nlri_octets(prefix: int) -> int:
    return ((prefix - 1) >> 3) + 1


class NLRI(object):
    length: int
    payload: bytes

    def __init__(self, length: int, payload: bytes) -> None:
        self.length = length
        self.payload = payload

    def __repr__(self) -> str:
        return f"<NLRI {self.payload!r}/{self.length!r}>"

    def to_bytes(self) -> bytes:
        return self.length.to_bytes(1, "big") + self.payload

    @classmethod
    def from_bytes(cls, afi: AFI, safi: SAFI, b: bytes) -> Tuple[NLRI, int]:
        octets = nlri_octets(b[0])
        payload = b[1:1 + octets]
        return cls(b[0], payload), 1 + octets


class IPNLRI(NLRI):
    protos = {(AFI.AFI_IPV4, SAFI.SAFI_UNICAST),
              (AFI.AFI_IPV6, SAFI.SAFI_UNICAST),
              (AFI.AFI_IPV4, SAFI.SAFI_MULTICAST),
              (AFI.AFI_IPV6, SAFI.SAFI_MULTICAST)}
    net: netaddr.IPNetwork
    path_id: int = 1

    def __init__(self, net: netaddr.IPNetwork) -> None:
        self.net = net

    def __repr__(self) -> str:
        return f"<IPNLRI {self.net!r}>"

    @property
    def payload(self) -> bytes:
        return self.net.packed[:nlri_octets(self.length)]

    @property
    def length(self) -> int:
        return self.net.prefixlen

    @classmethod
    def from_bytes(cls, afi: AFI, safi: SAFI, b: bytes) -> Tuple[IPNLRI, int]:
        octets = nlri_octets(b[0])
        payload = b[1:1 + octets]
        return cls(nlri_to_netaddr(b[0], payload, afi)), 1 + octets


class AddPathIPNLRI(IPNLRI):
    path_id: int

    def __init__(self, net: netaddr.IPNetwork, path_id: int) -> None:
        super().__init__(net)
        self.path_id = path_id

    def __repr__(self) -> str:
        return f"<AddPathIPNLRI {self.net!r} {self.path_id!r}>"

    def to_bytes(self) -> bytes:
        return self.path_id.to_bytes(4, "big") + super().to_bytes()

    @classmethod
    def from_bytes(cls, afi: AFI, safi: SAFI, b: bytes) \
            -> Tuple[AddPathIPNLRI, int]:
        path_id = int.from_bytes(b[0:4], "big")
        octets = nlri_octets(b[4])
        payload = b[5:5 + octets]
        return cls(nlri_to_netaddr(b[4], payload, afi), path_id), 5 + octets


class UpdateMessage(Message):
    type_ = MessageType.UPDATE
    path_attributes: List[PathAttribute]
    nlri: List[NLRI]
    nlri_raw: Optional[bytes]
    withdrawn: List[NLRI]
    withdrawn_raw: Optional[bytes]

    def __init__(self, withdrawn: List[NLRI] = [],
                 path_attributes: List[PathAttribute] = [],
                 nlri: List[NLRI] = [],
                 nlri_raw: Optional[bytes] = None,
                 withdrawn_raw: Optional[bytes] = None):
        self.path_attributes = list(path_attributes)
        self.nlri = list(nlri)
        self.nlri_raw = nlri_raw
        self.withdrawn = list(withdrawn)
        self.withdrawn_raw = withdrawn_raw

    def __repr__(self) -> str:
        s = "<UpdateMessage "
        if self.withdrawn_raw is not None:
            s += f"withdrawn_raw={self.withdrawn_raw!r} "
        else:
            s += f"withdrawn={self.withdrawn!r} "
        if self.nlri_raw is not None:
            s += f"nlri_raw={self.nlri_raw!r} "
        else:
            s += f"nlri={self.nlri!r} "
        s += f"attributes={self.path_attributes!r}>"
        return s

    def _to_bytes_withdrawn(self) -> bytes:
        if self.withdrawn_raw is not None:
            return self.withdrawn_raw
        b = bytearray()
        for withdrawn in self.withdrawn:
            b.extend(withdrawn.to_bytes())
        return b

    def _to_bytes_path_attrs(self) -> bytes:
        b = bytearray()
        for path_attr in self.path_attributes:
            b.extend(path_attr.to_bytes())
        return b

    def _to_bytes_nlri(self) -> bytes:
        if self.nlri_raw is not None:
            return self.nlri_raw
        b = bytearray()
        for nlri in self.nlri:
            b.extend(nlri.to_bytes())
        return b

    @property
    def payload(self) -> bytes:
        b = bytearray()
        withdrawn_b = self._to_bytes_withdrawn()
        path_attrs_b = self._to_bytes_path_attrs()
        b.extend(len(withdrawn_b).to_bytes(2, byteorder="big"))
        b.extend(withdrawn_b)
        b.extend(len(path_attrs_b).to_bytes(2, byteorder="big"))
        b.extend(path_attrs_b)
        b.extend(self._to_bytes_nlri())
        return b

    @classmethod
    def from_bytes(cls, b: bytes) -> UpdateMessage:
        b = Message.from_bytes(b).payload
        return cls.from_payload(b)

    @classmethod
    def from_payload(cls, b: bytes) -> UpdateMessage:
        msg = cls()

        withdrawn_len = int.from_bytes(b[0: 2], byteorder="big")
        withdrawn_raw = b[2: 2 + withdrawn_len]
        path_attrs_len = int.from_bytes(b[2 + withdrawn_len: 4 + withdrawn_len],
                                        byteorder="big")
        path_attrs_b = b[4 + withdrawn_len:4 + withdrawn_len + path_attrs_len]
        nlri_raw = b[4 + withdrawn_len + path_attrs_len:]

        while path_attrs_b:
            attr = PathAttribute.from_bytes(path_attrs_b)
            msg.path_attributes.append(attr)
            path_attrs_b = path_attrs_b[attr.length:]

        msg.nlri_raw = nlri_raw
        msg.withdrawn_raw = withdrawn_raw

        return msg


class NotificationMessage(Message):
    type_ = MessageType.NOTIFICATION
    error_code: int
    error_subcode: int
    data: bytes

    def __init__(self, error_code: int = 0, error_subcode: int = 0,
                 data: bytes = b"") -> None:
        self.error_code = error_code
        self.error_subcode = error_subcode
        self.data = bytes(data)

    def __repr__(self) -> str:
        return f"<NotificationMessage error={self.error_code!r} " \
            f"subcode={self.error_subcode!r} " \
            f"data={self.data!r}>"

    @property
    def payload(self) -> bytes:
        return bytes([self.error_code, self.error_subcode]) + self.data

    @classmethod
    def from_bytes(cls, b: bytes) -> NotificationMessage:
        b = Message.from_bytes(b).payload
        return cls.from_payload(b)

    @classmethod
    def from_payload(cls, b: bytes) -> NotificationMessage:
        return cls(b[0], b[1], b[2:])


class KeepaliveMessage(Message):
    type_ = MessageType.KEEPALIVE

    def __init__(self) -> None:
        pass

    @property
    def payload(self) -> bytes:
        return b""

    @property
    def length(self) -> int:
        return 19

    def __repr__(self) -> str:
        return "<KeepaliveMessage>"

    @classmethod
    def from_bytes(cls, b: bytes) -> KeepaliveMessage:
        return cls()

    @classmethod
    def from_payload(cls, b: bytes) -> KeepaliveMessage:
        return cls()


class RouteRefreshMessage(Message):
    type_ = MessageType.ROUTE_REFRESH
    afi: AFI
    safi: SAFI
    subtype: int

    def __init__(self, afi: int, safi: int, subtype: int) -> None:
        self.afi = AFI(afi)
        self.safi = SAFI(safi)
        self.subtype = subtype

    def __repr__(self) -> str:
        return f"<RouteRefreshMessage afi={self.afi!r} safi={self.safi!r} " \
            f"subtype={self.subtype!r}>"

    @property
    def length(self) -> int:
        return 19 + 4

    @property
    def payload(self) -> bytes:
        b = bytearray()
        b.extend(self.afi.to_bytes(2, byteorder="big"))
        b.extend(self.subtype.to_bytes(1, byteorder="big"))
        b.extend(self.safi.to_bytes(1, byteorder="big"))
        return b

    @classmethod
    def from_bytes(cls, b: bytes) -> RouteRefreshMessage:
        b = Message.from_bytes(b).payload
        return cls.from_payload(b)

    @classmethod
    def from_payload(cls, b: bytes) -> RouteRefreshMessage:
        afi = int.from_bytes(b[0:2], "big")
        subtype = int.from_bytes(b[2:3], "big")
        safi = int.from_bytes(b[3:4], "big")
        return cls(afi, safi, subtype)


class MessageDecoder(object):
    message_types: Mapping[MessageType, Type[Message]]
    path_attribute_types: Mapping[int, Type[PathAttribute]]
    capability_types: Mapping[int, Type[Capability]]
    parameter_types: Mapping[int, Type[Parameter]]
    nlri_types: Mapping[ProtoTuple, Type[NLRI]]
    default_afi: AFI = AFI.AFI_IPV4
    default_safi: SAFI = SAFI.SAFI_UNICAST

    def __init__(self, _decoder: Optional[MessageDecoder] = None,
                 message_types: Mapping[MessageType, Type[Message]] = {},
                 path_attribute_types: Mapping[int, Type[PathAttribute]] = {},
                 capability_types: Mapping[int, Type[Capability]] = {},
                 parameter_types: Mapping[int, Type[Parameter]] = {},
                 nlri_types: Mapping[ProtoTuple, Type[NLRI]] = {}):
        self.message_types = {}
        self.path_attribute_types = {}
        self.capability_types = {}
        self.parameter_types = {}
        self.nlri_types = {}
        if _decoder is not None:
            self.message_types.update(_decoder.message_types)
            self.path_attribute_types.update(_decoder.path_attribute_types)
            self.capability_types.update(_decoder.capability_types)
            self.parameter_types.update(_decoder.parameter_types)
            self.nlri_types.update(_decoder.nlri_types)
        self.message_types.update(message_types)
        self.path_attribute_types.update(path_attribute_types)
        self.capability_types.update(capability_types)
        self.parameter_types.update(parameter_types)
        self.nlri_types.update(nlri_types)

    def decode_message(self, b: bytes) -> Message:
        msg: Message = Message.from_bytes(b)
        msg = self.coerce_message(msg)
        if isinstance(msg, OpenMessage):
            msg.parameters = list(map(self.coerce_parameter,
                                      msg.parameters))
            for param in msg.parameters:
                if isinstance(param, CapabilityParameter):
                    param.capabilities = list(map(self.coerce_capability,
                                                  param.capabilities))
        elif isinstance(msg, UpdateMessage):
            msg.path_attributes = list(map(self.coerce_path_attribute,
                                           msg.path_attributes))
            if msg.nlri_raw is not None:
                msg.nlri = list(self.decode_nlris(
                    self.default_afi, self.default_safi, msg.nlri_raw))
                msg.nlri_raw = None
            if msg.withdrawn_raw is not None:
                msg.withdrawn = list(self.decode_nlris(self.default_afi,
                                                       self.default_safi,
                                                       msg.withdrawn_raw))
                msg.withdrawn_raw = None
            for attr in msg.path_attributes:
                if isinstance(attr, MultiprotocolReachableNLRI):
                    if attr.nlri_raw is None:
                        continue
                    attr.nlri = list(self.decode_nlris(attr.afi, attr.safi,
                                                       attr.nlri_raw))
                    attr.nlri_raw = None
                elif isinstance(attr, MultiprotocolUnreachableNLRI):
                    if attr.nlri_raw is None:
                        continue
                    attr.nlri = list(self.decode_nlris(attr.afi, attr.safi,
                                                       attr.nlri_raw))
                    attr.nlri_raw = None
        elif isinstance(msg, NotificationMessage):
            pass
        elif isinstance(msg, KeepaliveMessage):
            pass
        return msg

    def decode_nlri(self, afi: AFI, safi: SAFI, _b: bytes) -> Tuple[NLRI, int]:
        """Decodes a packed NLRI value. Requires the corresponding AFI and
        SAFI values for the lookup in the `nlri_types` object attribute and
        returns a tuple that consists of a `NLRI` object and the length of the
        consumed bytes in the input."""
        if (afi, safi) not in self.nlri_types:
            return NLRI.from_bytes(afi, safi, _b)
        return self.nlri_types[afi, safi].from_bytes(afi, safi, _b)

    def decode_nlris(self, afi: AFI, safi: SAFI, _b: bytes) \
            -> Generator[NLRI, None, None]:
        while _b:
            nlri, octets = self.decode_nlri(afi, safi, _b)
            _b = _b[octets:]
            yield nlri

    def coerce_message(self, m: Message) -> Message:
        if m.type_ in self.message_types:
            m_cls = self.message_types[m.type_]
            if hasattr(m_cls, "from_payload"):
                return m_cls.from_payload(m.payload)
            return m_cls.from_bytes(m.to_bytes())
        return m

    def coerce_path_attribute(self, p: PathAttribute) -> PathAttribute:
        if p.type_ in self.path_attribute_types:
            p_cls = self.path_attribute_types[p.type_]
            if hasattr(p_cls, "from_attribute"):
                return p_cls.from_attribute(p)
            return p_cls.from_bytes(p.to_bytes())
        return p

    def coerce_capability(self, c: Capability) -> Capability:
        if c.type_ in self.capability_types:
            c_cls = self.capability_types[c.type_]
            if hasattr(c_cls, "from_payload"):
                return c_cls.from_payload(c.payload)
            return c_cls.from_bytes(c.to_bytes())
        return c

    def coerce_parameter(self, p: Parameter) -> Parameter:
        if p.type_ in self.parameter_types:
            p_cls = self.parameter_types[p.type_]
            if hasattr(p_cls, "from_parameter"):
                return p_cls.from_parameter(p)
            return p_cls.from_bytes(p.to_bytes())
        return p

    def register_message_type(self, t: Type[Message]) -> None:
        self.message_types[t.type_] = t

    def register_path_attribute_type(self, t: Type[PathAttribute]) -> None:
        self.path_attribute_types[t.type_] = t

    def register_capability_type(self, t: Type[Capability]) -> None:
        self.capability_types[t.type_] = t

    def register_parameter_type(self, t: Type[Parameter]) -> None:
        self.parameter_types[t.type_] = t

    def __contains__(self, t: Union[Type[Parameter],
                                    Type[Message],
                                    Type[PathAttribute],
                                    Type[Capability]]) -> bool:
        if issubclass(t, Parameter):
            return t.type_ in self.parameter_types
        elif issubclass(t, Message):
            return t.type_ in self.message_types
        elif issubclass(t, PathAttribute):
            return t.type_ in self.path_attribute_types
        elif issubclass(t, Capability):
            return t.type_ in self.capability_types
        return False

    @classmethod
    def for_capabilities(cls, capabilities: Iterable[Capability],
                         base_decoder: Optional[MessageDecoder]=None) \
            -> MessageDecoder:
        """Creates an instance of a `MessageDecoder` that is suitable for the
        capability objects (i.e. objects of a subclass of `Capability`) given
        in the `capabilities` attribute. Creates a new `MessageDecoder`
        instance from the template given in the `base_decoder` attribute, which
        should contain a `MessageDecoder` instance.

        If an empty template is desired, then use `MessageDecoder()` as
        `base_decoder` value.

        This method understands at the moment the `FourOctetASNCapability`
        and `AddPathCapability` types, where the latter one is usable with
        Internet protocol AFI values, and unicast and multicast SAFI values."""
        if base_decoder is None:
            base_decoder = default_decoder
        decoder = cls(base_decoder)
        for cap in capabilities:
            if isinstance(cap, FourOctetASNCapability):
                decoder.register_path_attribute_type(AS4PathAttribute)
                decoder.register_path_attribute_type(Aggregator4Attribute)
            elif isinstance(cap, AddPathCapability):
                for afi, safi, send_receive in cap.protos:
                    if (afi, safi) not in AddPathIPNLRI.protos:
                        continue
                    elif not (send_receive & 1):
                        continue
                    decoder.nlri_types[afi, safi] = AddPathIPNLRI
        return decoder


async def read_message(reader: asyncio.StreamReader) -> bytes:
    marker = await reader.readexactly(16)
    length = await reader.readexactly(2)
    length_ = int.from_bytes(length, byteorder='big')
    type_ = await reader.readexactly(1)
    body = await reader.readexactly(length_ - 16 - 2 - 1)
    return bytearray(marker + length + type_ + body)


def is_full_message(message: bytes) -> bool:
    return len(message) >= message_length(message) and len(message) >= 18


def message_length(message: bytes) -> int:
    return int.from_bytes(message[16:18], byteorder="big")


default_decoder = MessageDecoder(
    message_types={MessageType.OPEN: OpenMessage,
                   MessageType.UPDATE: UpdateMessage,
                   MessageType.NOTIFICATION: NotificationMessage,
                   MessageType.KEEPALIVE: KeepaliveMessage,
                   MessageType.ROUTE_REFRESH: RouteRefreshMessage},
    path_attribute_types={
        1: OriginAttribute,
        2: ASPathAttribute,
        3: NextHopAttribute,
        4: MultiExitDisc,
        5: LocalPrefAttribute,
        6: AtomicAggregateAttribute,
        7: AggregatorAttribute,
        8: CommunitiesAttribute,
        14: MultiprotocolReachableNLRI,
        15: MultiprotocolUnreachableNLRI,
        17: AS4PathAttribute,
        18: Aggregator4Attribute,
        32: LargeCommunitiesAttribute,
    },
    capability_types={
        1: MultiprotocolCapability,
        2: RouteRefreshCapability,
        64: GracefulRestartCapability,
        65: FourOctetASNCapability,
        69: AddPathCapability,
    },
    parameter_types={
        2: CapabilityParameter,
    },
    nlri_types={
        (AFI.AFI_IPV4, SAFI.SAFI_UNICAST): IPNLRI,
        (AFI.AFI_IPV4, SAFI.SAFI_MULTICAST): IPNLRI,
        (AFI.AFI_IPV6, SAFI.SAFI_UNICAST): IPNLRI,
        (AFI.AFI_IPV6, SAFI.SAFI_MULTICAST): IPNLRI})
default_decoder_asn4 = MessageDecoder(
    default_decoder,
    path_attribute_types={
        2: AS4PathAttribute,
        7: Aggregator4Attribute,
    })

decode_message = default_decoder.decode_message


__all__ = (
    "AddPathCapability",
    "AddPathIPNLRI",
    "AFI",
    "AggregatorAttribute",
    "Aggregator4Attribute",
    "ASPathAttribute",
    "ASPathSegmentType",
    "AS4PathAttribute",
    "AtomicAggregateAttribute",
    "Capability",
    "CapabilityParameter",
    "CommunitiesAttribute",
    "FourOctetASNCapability",
    "GracefulRestartCapability",
    "IPNLRI",
    "KeepaliveMessage",
    "LargeCommunitiesAttribute",
    "LocalPrefAttribute",
    "Message",
    "MessageDecoder",
    "MessageType",
    "MultiExitDisc",
    "MultiprotocolCapability",
    "MultiprotocolReachableNLRI",
    "MultiprotocolUnreachableNLRI",
    "NextHopAttribute",
    "NLRI",
    "NotificationMessage",
    "OpenMessage",
    "OriginAttribute",
    "Parameter",
    "PathAttribute",
    "ProtoTuple",
    "RouteRefreshCapability",
    "RouteRefreshMessage",
    "SAFI",
    "UpdateMessage",
    "decode_message",
    "read_message",
)
