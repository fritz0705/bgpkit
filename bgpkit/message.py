# coding: utf-8

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
        return f"MessageType({int(self)!r})"


MessageType.UNKNOWN = MessageType(0)
MessageType.OPEN = MessageType(1)
MessageType.UPDATE = MessageType(2)
MessageType.NOTIFICATION = MessageType(3)
MessageType.KEEPALIVE = MessageType(4)


class Message(object):
    """ A Message that represents a single BGP-4 message. The payload is stored
    in the `payload` field and the type of the message is stored in `type_`
    as a `MessageType` value. """

    type_: MessageType
    payload: bytes

    def __init__(self, type_: int, payload: bytes=b"") -> None:
        self.type_ = MessageType(type_)
        self.payload = bytes(payload)

    @property
    def length(self) -> int:
        return len(self.payload) + 19

    def to_bytes(self) -> bytes:
        b = bytearray()
        b.extend(b"\xff" * 16)
        b.extend(self.length.to_bytes(2, byteorder="big"))
        b.extend(self.type_.to_bytes(1, byteorder="big"))
        b.extend(self.payload)
        return b

    @classmethod
    def from_bytes(cls, b: bytes) -> Message:
        length = int.from_bytes(b[16:18], byteorder="big")
        type_ = MessageType(int.from_bytes(b[18:19], byteorder="big"))
        msg = cls(type_, b[19:])
        return msg

    def __repr__(self) -> str:
        return "<Message length={!r} type={!r} payload={!r}>".format(
            self.length, self.type_, self.payload)


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

    def __repr__(self) -> str:
        return "<OpenMessage version={self.version!r} asn={self.asn!r} " \
            "hold_time={self.hold_time!r} "\
            "router_id={self.router_id!r} "\
            "parameters={self.parameters!r}>".format(self=self)

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
        return "<Parameter param_type={!r} payload={!r}>".format(
            self.type_, self.payload)

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
        return "<CapabilityParameter capabilities={!r}>".format(
            self.capabilities)

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
        return "<Capability code={!r} payload={!r}>".format(
            self.type_, self.payload)

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


class FourOctetASNCapability(Capability):
    type_ = 65

    def __init__(self, asn: int) -> None:
        self.asn = asn

    @property
    def payload(self) -> bytes:
        return self.asn.to_bytes(4, byteorder="big")

    def __repr__(self) -> str:
        return "<FourOctetASNCapability asn={}>".format(self.asn)

    @classmethod
    def from_bytes(cls, b: bytes) -> FourOctetASNCapability:
        b = Capability.from_bytes(b).payload
        return cls(int.from_bytes(b[0:4], byteorder="big"))


class AFI(int):
    AFI_IPV4: AFI
    AFI_IPV6: AFI
    AFI_NSAP: AFI
    AFI_HDLC: AFI
    AFI_BBN_1822: AFI
    AFI_802: AFI
    AFI_E163: AFI
    AFI_E164: AFI
    AFI_F69: AFI
    AFI_BGP_LS: AFI

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
    SAFI_UNICAST: SAFI
    SAFI_MULTICAST: SAFI
    SAFI_BGP_LS: SAFI
    SAFI_FLOW4: SAFI

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
        elif self == self.SAFI_FLOW4:
            return "SAFI.SAFI_FLOW4"
        return f"SAFI({int(self)!r})"


SAFI.SAFI_UNICAST = SAFI(1)
SAFI.SAFI_MULTICAST = SAFI(2)
SAFI.SAFI_BGP_LS = SAFI(71)
SAFI.SAFI_FLOW4 = SAFI(133)


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
        return "<MultiprotocolCapability afi={} safi={}>".format(
            self.afi, self.safi)

    @classmethod
    def from_bytes(cls, b: bytes) -> MultiprotocolCapability:
        b = Capability.from_bytes(b).payload
        return cls(
            int.from_bytes(b[0:2], byteorder="big"),
            int.from_bytes(b[3:4], byteorder="big"))


class PathAttribute(object):
    FLAG_EXTENDED_LENGTH = 16
    FLAG_PARTIAL = 32
    FLAG_TRANSITIVE = 64
    FLAG_OPTIONAL = 128

    payload: bytes
    type_: int
    flags: int

    def __init__(self, flags: int=0, type_: int=0, payload: bytes=b""):
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
        return "<PathAttribute type={} flags={} payload={!r}>".format(
            self.type_, self.flag_code, self.payload)

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

    def __init__(self, afi: int, safi: int, next_hop: bytes,
                 nlri: List[NLRI]=[],
                 flags: int=PathAttribute.FLAG_OPTIONAL) -> None:
        self.flags = flags
        self.afi = AFI(afi)
        self.safi = SAFI(safi)
        self.next_hop = next_hop
        self.nlri = list(nlri)

    @property
    def ip_routes(self) -> List[netaddr.IPNetwork]:
        if not self.ip_version:
            return []
        routes = []
        for nlri in self.nlri:
            routes.append(nlri_to_netaddr(nlri, version=self.ip_version))
        return routes

    @ip_routes.setter
    def ip_routes(self, routes: List[netaddr.IPNetwork]) -> None:
        pass

    @property
    def ip_version(self) -> Optional[int]:
        if self.afi == AFI.AFI_IPV4:
            return 4
        elif self.afi == AFI.AFI_IPV6:
            return 6
        return None

    @property
    def ip_next_hop(self) -> netaddr.IPAddress:
        if not self.ip_version:
            return None
        return netaddr.IPAddress(
            int.from_bytes(self.next_hop,
                           byteorder="big"), version=self.ip_version)

    @ip_next_hop.setter
    def ip_next_hop(self, next_hop: netaddr.IPAddress) -> None:
        pass

    def __repr__(self) -> str:
        if self.afi in {AFI.AFI_IPV4, AFI.AFI_IPV6}:
            return "<MultiprotocolReachableNLRI afi={} safi={} "\
                "ip_next_hop={!r} ip_routes={!r}>".format(self.afi,
                                                          self.safi,
                                                          self.ip_next_hop,
                                                          self.ip_routes)
        return "<MultiprotocolReachableNLRI afi={} safi={} next_hop={!r} " \
            "nlri={!r}>".format(self.afi,
                                self.safi,
                                self.next_hop,
                                self.nlri)

    @property
    def payload(self) -> bytes:
        b = bytearray()
        b.extend(self.afi.to_bytes(2, byteorder="big"))
        b.extend(self.safi.to_bytes(1, byteorder="big"))
        next_hop = self.next_hop
        b.extend(len(next_hop).to_bytes(1, byteorder="big"))
        b.extend(next_hop)
        b.extend(b"\0")
        for length, prefix in self.nlri:
            b.extend(length.to_bytes(1, byteorder="big"))
            b.extend(prefix[0:length])
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
        nlri_base = b[5 + next_hop_len:]
        attr = cls(afi, safi, next_hop, flags=attr.flags)
        while nlri_base:
            n_len = nlri_base[0]
            attr.nlri.append((n_len, nlri_base[1: 1 + nlri_octets(n_len)]))
            nlri_base = nlri_base[1 + nlri_octets(n_len):]
        return attr


class MultiprotocolUnreachableNLRI(PathAttribute):
    type_ = 15

    def __init__(self, afi: int, safi: int, nlri: List[NLRI]=[],
                 flags: int=PathAttribute.FLAG_OPTIONAL) -> None:
        self.flags = flags
        self.afi = AFI(afi)
        self.safi = SAFI(safi)
        self.nlri = list(nlri)

    @property
    def ip_routes(self) -> List[netaddr.IPNetwork]:
        if not self.ip_version:
            return []
        routes = []
        for nlri in self.nlri:
            routes.append(nlri_to_netaddr(nlri, version=self.ip_version))
        return routes

    @property
    def ip_version(self) -> Optional[int]:
        if self.afi == AFI.AFI_IPV4:
            return 4
        elif self.afi == AFI.AFI_IPV6:
            return 6
        return None

    def __repr__(self) -> str:
        if self.afi in {AFI.AFI_IPV4, AFI.AFI_IPV6}:
            return "<MultiprotocolUnreachableNLRI afi={} safi={} "\
                "ip_routes={!r}".format(self.afi,
                                        self.safi,
                                        self.ip_routes)
        return "<MultiprotocolUnreachableNLRI afi={} safi={} "\
            "nlri={!r}>".format(self.afi,
                                self.safi,
                                self.nlri)

    @property
    def payload(self) -> bytes:
        b = bytearray()
        b.extend(self.afi.to_bytes(2, byteorder="big"))
        b.extend(self.safi.to_bytes(1, byteorder="big"))
        for length, prefix in self.nlri:
            b.extend(length.to_bytes(1, byteorder="big"))
            b.extend(prefix[0:length])
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
        attr = cls(AFI(afi), SAFI(safi), flags=attr.flags)
        nlri_b = b[3:]
        while nlri_b:
            n_len = nlri_b[0]
            attr.nlri.append((n_len, nlri_b[1:1 + nlri_octets(n_len)]))
            nlri_b = nlri_b[1 + nlri_octets(n_len):]
        return attr


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
        return "<OriginAttribute origin={}>".format(
            self.origin_name)

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
        return "<ASPathAttribute {!r}>".format(self.segments)

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
    def __init__(self, segments: List[Union[Set[int], List[int]]]=[],
                 flags: int=PathAttribute.FLAG_TRANSITIVE) -> None:
        super().__init__(segments, flags)

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
        attr = cls(flags=attr.flags)
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
        return "<NextHopAttribute {!r}>".format(self.next_hop)

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
        return "<MultiExitDisc {!r}>".format(self.med)

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
        return "<LocalPrefAttribute {!r}>".format(self.local_pref)

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
        return "<AggregatorAttribute asn={!r} ip_address={!r}>".format(
            self.asn,
            self.ip_address)

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


class CommunitiesAttribute(PathAttribute):
    type_ = 8

    communities: List[int]

    def __init__(self, communities: List[int]=[],
                 flags: int=PathAttribute.FLAG_TRANSITIVE |
                 PathAttribute.FLAG_OPTIONAL) -> None:
        self.communities = list(communities)
        self.flags = flags

    def __repr__(self) -> str:
        return "<CommunitiesAttribute {!r}>".format(self.pairs)

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

    def __init__(self, communities: List[LargeCommunity]=[],
                 flags: int=PathAttribute.FLAG_OPTIONAL |
                 PathAttribute.FLAG_TRANSITIVE) -> None:
        self.communities = list(communities)
        self.flags = flags

    def __repr__(self) -> str:
        return "<LargeCommunitiesAttribute {!r}>".format(self.communities)

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


def nlri_to_netaddr(nlri: NLRI, version: int=4) -> netaddr.IPNetwork:
    prefix = nlri[0]
    addr = nlri[1].ljust(4 if version == 4 else 16, b'\0')
    return netaddr.IPNetwork((int.from_bytes(addr, byteorder="big"), prefix),
                             version=version)


def netaddr_to_nlri(network: netaddr.IPNetwork) -> NLRI:
    return (network.prefixlen, network.packed[:nlri_octets(network.prefixlen)])


def nlri_octets(prefix: int) -> int:
    return ((prefix - 1) >> 3) + 1


NLRI = Tuple[int, bytes]


class UpdateMessage(Message):
    type_ = MessageType.UPDATE
    path_attributes: List[PathAttribute]
    nlri: List[NLRI]
    withdrawn: List[NLRI]

    def __init__(self, withdrawn: List[NLRI]=[],
                 path_attributes: List[PathAttribute]=[],
                 nlri: List[NLRI]=[]):
        self.withdrawn = list(withdrawn)
        self.path_attributes = list(path_attributes)
        self.nlri = list(nlri)

    @property
    def ip_nlri(self) -> List[netaddr.IPNetwork]:
        networks = []
        for nlri in self.nlri:
            networks.append(nlri_to_netaddr(nlri))
        return networks

    @ip_nlri.setter
    def ip_nlri(self, nlri: List[netaddr.IPNetwork]) -> None:
        pass

    @property
    def ip_withdrawn(self) -> List[netaddr.IPNetwork]:
        networks = []
        for withdrawn in self.withdrawn:
            networks.append(nlri_to_netaddr(withdrawn))
        return networks

    @ip_withdrawn.setter
    def ip_withdrawn(self, withdrawn: List[netaddr.IPNetwork]) -> None:
        pass

    def mp_nlri(self) -> Generator[Tuple[AFI, SAFI, netaddr.IPNetwork],
                                   None, None]:
        for net in self.ip_nlri:
            yield (AFI.AFI_IPV4, SAFI.SAFI_UNICAST, net)
        for attr in self.path_attributes:
            if not isinstance(attr, MultiprotocolReachableNLRI):
                continue
            if attr.ip_version:
                for net in attr.ip_routes:
                    yield (attr.afi, attr.safi, net)
            else:
                for nlri in attr.nlri:
                    yield (attr.afi, attr.safi, nlri)

    def mp_withdrawn(self) -> Generator[Tuple[AFI, SAFI, netaddr.IPNetwork],
                                        None, None]:
        for net in self.ip_withdrawn:
            yield (AFI.AFI_IPV4, SAFI.SAFI_UNICAST, net)
        for attr in self.path_attributes:
            if not isinstance(attr, MultiprotocolUnreachableNLRI):
                continue
            if attr.ip_version:
                for net in attr.ip_routes:
                    yield (attr.afi, attr.safi, net)
            else:
                for nlri in attr.nlri:
                    yield (attr.afi, attr.safi, nlri)

    def __repr__(self) -> str:
        return "<UpdateMessage ip_withdrawn={self.ip_withdrawn!r} " \
            "attributes={self.path_attributes!r} " \
            "ip_nlri={self.ip_nlri!r}>".format(self=self)

    def _to_bytes_withdrawn(self) -> bytes:
        b = bytearray()
        for withdrawn in self.withdrawn:
            b.append(withdrawn[0])
            b.extend(withdrawn[1])
        return b

    def _to_bytes_path_attrs(self) -> bytes:
        b = bytearray()
        for path_attr in self.path_attributes:
            b.extend(path_attr.to_bytes())
        return b

    def _to_bytes_nlri(self) -> bytes:
        b = bytearray()
        for nlri in self.nlri:
            b.append(nlri[0])
            b.extend(nlri[1])
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

        withdrawn_len = int.from_bytes(b[0:2], byteorder="big")
        withdrawn_b = b[2:2 + withdrawn_len]
        path_attrs_len = int.from_bytes(b[2 + withdrawn_len:4 + withdrawn_len],
                                        byteorder="big")
        path_attrs_b = b[4 + withdrawn_len:4 + withdrawn_len + path_attrs_len]
        nlri_b = b[4 + withdrawn_len + path_attrs_len:]

        while withdrawn_b:
            w_len = withdrawn_b[0]
            msg.withdrawn.append((w_len,
                                  withdrawn_b[1:1 + nlri_octets(w_len)]))
            withdrawn_b = withdrawn_b[1 + nlri_octets(w_len):]
        while path_attrs_b:
            attr = PathAttribute.from_bytes(path_attrs_b)
            msg.path_attributes.append(attr)
            path_attrs_b = path_attrs_b[attr.length:]
        while nlri_b:
            n_len = nlri_b[0]
            msg.nlri.append((n_len, nlri_b[1:1 + nlri_octets(n_len)]))
            nlri_b = nlri_b[1 + nlri_octets(n_len):]

        return msg


class NotificationMessage(Message):
    type_ = MessageType.NOTIFICATION
    error_code: int
    error_subcode: int
    data: bytes

    def __init__(self, error_code: int=0, error_subcode: int=0,
                 data: bytes=b"") -> None:
        self.error_code = error_code
        self.error_subcode = error_subcode
        self.data = bytes(data)

    def __repr__(self) -> str:
        return "<NotificationMessage error={self.error_code!r} "\
            "subcode={self.error_subcode!r} " \
            "data={self.data!r}>".format(self=self)

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


class MessageDecoder(object):
    message_types: Mapping[MessageType, Type[Message]]
    path_attribute_types: Mapping[int, Type[PathAttribute]]
    capability_types: Mapping[int, Type[Capability]]
    parameter_types: Mapping[int, Type[Parameter]]

    def __init__(self, _decoder: Optional[MessageDecoder]=None,
                 message_types: Mapping[MessageType, Type[Message]]={},
                 path_attribute_types: Mapping[int, Type[PathAttribute]]={},
                 capability_types: Mapping[int, Type[Capability]]={},
                 parameter_types: Mapping[int, Type[Parameter]]={}):
        self.message_types = {}
        self.path_attribute_types = {}
        self.capability_types = {}
        self.parameter_types = {}
        if _decoder is not None:
            self.message_types.update(_decoder.message_types)
            self.path_attribute_types.update(_decoder.path_attribute_types)
            self.capability_types.update(_decoder.capability_types)
            self.parameter_types.update(_decoder.parameter_types)
        self.message_types.update(message_types)
        self.path_attribute_types.update(path_attribute_types)
        self.capability_types.update(capability_types)
        self.parameter_types.update(parameter_types)

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
        elif isinstance(msg, NotificationMessage):
            pass
        elif isinstance(msg, KeepaliveMessage):
            pass
        return msg

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


defaultDecoder = MessageDecoder(
    message_types={MessageType.OPEN: OpenMessage,
                   MessageType.UPDATE: UpdateMessage,
                   MessageType.NOTIFICATION: NotificationMessage,
                   MessageType.KEEPALIVE: KeepaliveMessage},
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
        32: LargeCommunitiesAttribute,
    },
    capability_types={
        1: MultiprotocolCapability,
        65: FourOctetASNCapability,
    },
    parameter_types={
        2: CapabilityParameter,
    })
defaultDecoderASN4 = MessageDecoder(
    defaultDecoder,
    path_attribute_types={
        2: AS4PathAttribute,
    })

decode_message = defaultDecoder.decode_message


__all__ = (
    "MessageType",
    "Message",
    "OpenMessage",
    "Parameter",
    "CapabilityParameter",
    "Capability",
    "FourOctetASNCapability",
    "AFI",
    "SAFI",
    "MultiprotocolCapability",
    "PathAttributes",
    "MultiprotocolReachableNLRI",
    "MultiprotocolUnreachableNLRI",
    "OriginAttribute",
    "ASPathSegmentType",
    "ASPathAttribute",
    "NextHopAttribute",
    "MultiExitDisc",
    "LocalPrefAttribute",
    "AtomicAggregateAttribute",
    "AggregatorAttribute",
    "CommunitiesAttribute",
    "LargeCommunitiesAttribute",
    "UpdateMessage",
    "NotificationMessage",
    "KeepaliveMessage",
    "read_message",
    "decode_message",
    "MessageDecoder"
)
