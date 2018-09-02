# coding: utf-8

import enum

import netaddr


class MessageType(enum.Enum):
    UNKNOWN = 0
    OPEN = 1
    UPDATE = 2
    NOTIFICATION = 3
    KEEPALIVE = 4


class Message(object):
    type_ = MessageType.UNKNOWN
    payload = None

    def __init__(self, type_, payload=b""):
        self.type_ = type_
        self.payload = bytes(payload)

    @property
    def length(self):
        return len(self.payload) + 19

    def to_bytes(self):
        b = bytearray()
        b.extend(b"\xff" * 16)
        b.extend(self.length.to_bytes(2, byteorder="big"))
        b.extend(self.type_.value.to_bytes(1, byteorder="big"))
        b.extend(self.payload)
        return b

    @classmethod
    def from_bytes(cls, b, coerce=False, **kwargs):
        length = int.from_bytes(b[16:18], byteorder="big")
        type_ = MessageType(int.from_bytes(b[18:19], byteorder="big"))
        msg = cls(type_, b[19:])
        if coerce:
            if msg.type_ == MessageType.OPEN:
                return OpenMessage.from_bytes(b, **kwargs)
            elif msg.type_ == MessageType.UPDATE:
                return UpdateMessage.from_bytes(b, **kwargs)
            elif msg.type_ == MessageType.NOTIFICATION:
                return NotificationMessage.from_bytes(b, **kwargs)
            elif msg.type_ == MessageType.KEEPALIVE:
                return KeepaliveMessage.from_bytes(b, **kwargs)
        return msg

    def __repr__(self):
        return "<Message length={!r} type={!r} payload={!r}>".format(
            self.length, self.type_, self.payload)


class OpenMessage(Message):
    type_ = MessageType.OPEN
    parameter_types = {}

    def __init__(self, version=4, asn=23456, hold_time=0, bgp_identifier=0,
                 router_id=None, parameters=[]):
        self.version = version
        self.asn = asn
        self.hold_time = int(hold_time)
        self.bgp_identifier = int(bgp_identifier)
        if router_id is not None:
            self.router_id = router_id
        self.parameters = list(parameters)

    @property
    def asn4(self):
        return False

    @property
    def length(self):
        return 19 + 10 + len(self._to_bytes_parameters())

    @property
    def router_id(self):
        return netaddr.IPAddress(self.bgp_identifier)

    @router_id.setter
    def router_id(self, val):
        self.bgp_identifier = int(val)

    def __repr__(self):
        return "<OpenMessage version={self.version!r} asn={self.asn!r} " \
            "hold_time={self.hold_time!r} "\
            "router_id={self.router_id!r} "\
            "parameters={self.parameters!r}>".format(self=self)

    @property
    def payload(self):
        b = bytearray()
        b.extend(self.version.to_bytes(1, byteorder="big"))
        b.extend(self.asn.to_bytes(2, byteorder="big"))
        b.extend(self.hold_time.to_bytes(2, byteorder="big"))
        b.extend(self.bgp_identifier.to_bytes(4, byteorder="big"))
        params_b = self._to_bytes_parameters()
        b.extend(len(params_b).to_bytes(1, byteorder="big"))
        b.extend(params_b)
        return b

    def _to_bytes_parameters(self):
        b = bytearray()
        for parameter in self.parameters:
            b.extend(parameter.param_type.to_bytes(1, byteorder="big"))
            param_b = parameter.to_bytes()
            b.extend(len(param_b).to_bytes(1, byteorder="big"))
            b.extend(param_b)
        return b

    @classmethod
    def from_bytes(cls, b, **kwargs):
        msg = Message.from_bytes(b)
        b = msg.payload

        version = int.from_bytes(b[0:1], "big")
        asn = int.from_bytes(b[1:3], "big")
        hold_time = int.from_bytes(b[3:5], "big")
        bgp_identifier = int.from_bytes(b[5:9], "big")
        msg = cls(version, asn, hold_time, bgp_identifier)

        opt_param_len = int.from_bytes(b[9:10], "big")
        b = b[10:]
        while opt_param_len > 0:
            param_type = int(b[0])
            param_length = int(b[1])
            param_cls = cls.parameter_types.get(param_type)
            if param_cls is not None:
                msg.parameters.append(
                    param_cls.from_bytes(b[2:param_length + 2], coerce=True,
                                         **kwargs))
            opt_param_len -= 2 + param_length
            b = b[param_length+2:]
            assert opt_param_len >= 0

        return msg


class Capability(object):
    capability_types = {}

    param_type = 2

    def __init__(self, code, payload=b""):
        self.code = int(code)
        self.payload = bytes(payload)

    def to_bytes(self):
        b = bytearray()
        b.extend(self.code.to_bytes(1, byteorder="big"))
        if self.payload is not None:
            b.extend(len(self.payload).to_bytes(1, byteorder="big"))
            b.extend(self.payload)
        return b

    def __repr__(self):
        return "<Capability code={} payload={}>".format(
            self.code, self.payload)

    @classmethod
    def from_bytes(cls, b, coerce=False, **kwargs):
        cap = Capability(int(b[0]), b[2:])
        if coerce:
            cap_cls = cls.capability_types.get(cap.code)
            if cap_cls:
                return cap_cls.from_bytes(b)
        return cap


OpenMessage.parameter_types[2] = Capability


class FourOctetASNCapability(Capability):
    code = 65

    def __init__(self, asn):
        self.asn = asn

    @property
    def payload(self):
        return self.asn.to_bytes(4, byteorder="big")

    def __repr__(self):
        return "<FourOctetASNCapability asn={}>".format(self.asn)

    @classmethod
    def from_bytes(cls, b, **kwargs):
        cap = super().from_bytes(b)
        return cls(int.from_bytes(cap.payload[0:4], byteorder="big"))


Capability.capability_types[65] = FourOctetASNCapability


class AFI(enum.Enum):
    AFI_IPV4 = 1
    AFI_IPV6 = 2
    AFI_NSAP = 3
    AFI_HDLC = 4
    AFI_BBN_1822 = 5
    AFI_802 = 6
    AFI_E163 = 7
    AFI_E164 = 8
    AFI_F69 = 9
    AFI_BGP_LS = 16388


class SAFI(enum.Enum):
    SAFI_UNICAST = 1
    SAFI_MULTICAST = 2


class MultiprotocolCapability(Capability):
    code = 1

    def __init__(self, afi, safi):
        self.afi = afi
        self.safi = safi

    @property
    def payload(self):
        return self.afi.value.to_bytes(2, byteorder="big") + b"\0" + \
            self.safi.value.to_bytes(1, byteorder="big")

    def __repr__(self):
        return "<MultiprotocolCapability afi={} safi={}>".format(
            self.afi, self.safi)

    @classmethod
    def from_bytes(cls, b, **kwargs):
        cap = super().from_bytes(b)
        return cls(
            int.from_bytes(cap.payload[0:2], byteorder="big"),
            int.from_bytes(cap.payload[3:4], byteorder="big"))


Capability.capability_types[1] = MultiprotocolCapability


class PathAttribute(object):
    attribute_types = {}

    type_code = 0
    flags = 0

    def __init__(self, flags=0, type_code=0, payload=b""):
        self.type_code = type_code
        self.flags = flags
        self.payload = bytes(payload)

    @property
    def is_partial(self):
        return self.flags & 32

    @is_partial.setter
    def is_partial(self, b):
        pass

    @property
    def is_transitive(self):
        return self.flags & 64

    @is_transitive.setter
    def is_transitive(self, b):
        pass

    @property
    def is_optional(self):
        return self.flags & 128

    @is_optional.setter
    def is_optional(self, b):
        pass

    @property
    def extended_length(self):
        return self.flags & 16

    @extended_length.setter
    def extended_length(self, b):
        pass

    @property
    def length(self):
        return len(self.payload) + 3 + (1 if self.extended_length else 0)

    def to_bytes(self):
        b = bytearray()
        b.append(self.flags)
        b.append(self.type_code)
        if self.extended_length:
            b.extend(len(self.payload).to_bytes(2, byteorder="big"))
        else:
            b.extend(len(self.payload).to_bytes(1, byteorder="big"))
        b.extend(self.payload)
        return b

    @property
    def flag_code(self):
        return ('O' if self.is_optional else '-') + \
            ('T' if self.is_transitive else '-') + \
            ('P' if self.is_partial else '-') + \
            ('E' if self.extended_length else '-')

    def __repr__(self):
        return "<PathAttribute type={} flags={} payload={!r}>".format(
            self.type_code, self.flag_code, self.payload)

    @classmethod
    def from_bytes(cls, b, coerce=False, **kwargs):
        attr = cls(b[0], b[1])
        if attr.extended_length:
            d_len = int.from_bytes(b[2:4], byteorder="big")
            attr.payload = b[4:4 + d_len]
        else:
            d_len = b[2]
            attr.payload = b[3:3 + d_len]
        if coerce:
            if attr.type_code in cls.attribute_types:
                return cls.attribute_types[attr.type_code].from_bytes(
                    b, **kwargs)
        return attr


class MultiprotocolReachableNLRI(PathAttribute):
    type_code = 14

    def __init__(self, afi, safi, next_hop, nlri=[], flags=0):
        self.flags = flags
        self.afi = afi
        self.safi = safi
        self.next_hop = next_hop
        self.nlri = list(nlri)

    def __repr__(self):
        return "<MultiprotocolReachableNLRI afi={} safi={} next_hop={!r} " \
            "nlri={!r}>".format(self.afi,
                                self.safi,
                                self.next_hop,
                                self.nlri)

    @property
    def payload(self):
        b = bytearray()
        b.extend(self.afi.to_bytes(2, byteorder="big"))
        b.extend(self.safi.to_bytes(1, byteorder="big"))
        next_hop = self.next_hop.packed
        b.extend(len(next_hop).to_bytes(1, byteorder="big"))
        b.extend(next_hop)
        b.extend(0)
        for length, prefix in self.nlri:
            b.extend(length.to_bytes(1, byteorder="big"))
            b.extend(prefix[0:length])
        return b

    @classmethod
    def from_bytes(cls, b, **kwargs):
        attr = PathAttribute.from_bytes(b, **kwargs)
        b = attr.payload
        afi, safi = int.from_bytes(b[0:2], byteorder="big"), b[2]
        next_hop = b[4:4+b[3]]
        nlri_b = b[5+b[3]:]
        attr = cls(AFI(afi), SAFI(safi), next_hop, flags=attr.flags)
        while nlri_b:
            n_len = nlri_b[0]
            attr.nlri.append((n_len, nlri_b[1:1 + (n_len >> 3)]))
            nlri_b = nlri_b[1 + (n_len >> 3):]
        return attr


PathAttribute.attribute_types[14] = MultiprotocolReachableNLRI


class MultiprotocolUnreachableNLRI(PathAttribute):
    type_code = 15

    def __init__(self, afi, safi, nlri=[], flags=0):
        self.flags = flags
        self.afi = AFI(afi)
        self.safi = SAFI(safi)
        self.nlri = list(nlri)

    def __repr__(self):
        return "<MultiprotocolUnreachableNLRI afi={} safi={} "\
            "nlri={!r}>".format(self.afi,
                                self.safi,
                                self.nlri)

    @property
    def payload(self):
        b = bytearray()
        b.extend(self.afi.value.to_bytes(2, byteorder="big"))
        b.extend(self.safi.value.to_bytes(1, byteorder="big"))
        for length, prefix in self.nlri:
            b.extend(length.to_bytes(1, byteorder="big"))
            b.extend(prefix[0:length])
        return b

    @classmethod
    def from_bytes(cls, b, **kwargs):
        b = PathAttribute.from_bytes(b, **kwargs).payload
        afi, safi = int.from_bytes(b[0:2], byteorder="big"), b[2]
        attr = cls(AFI(afi), SAFI(safi))
        nlri_b = b[3:]
        while nlri_b:
            n_len = nlri_b[0]
            attr.nlri.append((n_len, nlri_b[1:1 + (n_len >> 3)]))
            nlri_b = nlri_b[1 + (n_len >> 3):]
        return attr


PathAttribute.attribute_types[15] = MultiprotocolUnreachableNLRI


class OriginAttribute(PathAttribute):
    type_code = 1

    def __init__(self, origin, flags=0):
        self.origin = origin
        self.flags = flags

    @property
    def origin_name(self):
        return {
            0: "IGP",
            1: "EGP",
            2: "INCOMPLETE"
        }[self.origin]

    @origin_name.setter
    def origin_name(self, s):
        self.origin = {
            "IGP": 0,
            "EGP": 1,
            "INCOMPLETE": 2
        }[s]

    @property
    def payload(self):
        return self.origin.to_bytes(1, byteorder="big")

    def __repr__(self):
        return "<OriginAttribute origin={}>".format(
            self.origin_name)

    @classmethod
    def from_bytes(cls, b, **kwargs):
        b = PathAttribute.from_bytes(b, **kwargs).payload
        return cls(b[0])


PathAttribute.attribute_types[1] = OriginAttribute


class ASPathSegmentType(enum.Enum):
    AS_SET = 1
    AS_SEQUENCE = 2


class ASPathAttribute(PathAttribute):
    type_code = 2

    def __init__(self, segments=[], asn4=False, flags=0):
        self.segments = list(segments)
        self.asn4 = asn4
        self.flags = flags

    def __repr__(self):
        return "<ASPathAttribute {!r}>".format(self.segments)

    @property
    def payload(self):
        b = bytearray()
        for segment in self.segments:
            segment_type = ASPathSegmentType.AS_SET \
                if isinstance(segment, set) \
                else ASPathSegmentType.AS_SEQUENCE
            b.append(segment_type.value)
            b.append(len(segment))
            for asn in segment:
                if self.asn4:
                    b.extend(asn.to_bytes(4, byteorder="big"))
                else:
                    b.extend(asn.to_bytes(2, byteorder="big"))
        return b

    @classmethod
    def from_bytes(cls, b, asn4=False, **kwargs):
        attr = PathAttribute.from_bytes(b, **kwargs)
        b = attr.payload
        attr = cls(asn4=asn4, flags=attr.flags)
        while b:
            segment = []
            segment_type = ASPathSegmentType(b[0])
            segment_len = b[1]
            b = b[2:]
            for asn in range(segment_len):
                if asn4:
                    segment.append(int.from_bytes(b[0:4], byteorder="big"))
                    b = b[4:]
                else:
                    segment.append(int.from_bytes(b[0:2], byteorder="big"))
                    b = b[2:]
            if segment_type == ASPathSegmentType.AS_SET:
                attr.segments.append(set(segment))
            else:
                attr.segments.append(segment)
        return attr


PathAttribute.attribute_types[2] = ASPathAttribute


class NextHopAttribute(PathAttribute):
    type_code = 3

    def __init__(self, next_hop, flags=0):
        self.next_hop = next_hop
        self.flags = flags

    @property
    def payload(self):
        return self.next_hop.packed

    def __repr__(self):
        return "<NextHopAttribute {!r}>".format(self.next_hop)

    @classmethod
    def from_bytes(cls, b, **kwargs):
        b = PathAttribute.from_bytes(b, **kwargs).payload
        return cls(netaddr.IPAddress(int.from_bytes(b[0:4], byteorder="big")))


PathAttribute.attribute_types[3] = NextHopAttribute


class MultiExitDisc(PathAttribute):
    type_code = 4

    def __init__(self, med, flags=0):
        self.med = med
        self.flags = flags

    @property
    def payload(self):
        return self.med.to_bytes(4, byteorder="big")

    def __repr__(self):
        return "<MultiExitDisc {!r}>".format(self.med)

    @classmethod
    def from_bytes(cls, b, **kwargs):
        attr = PathAttribute.from_bytes(b)
        b = attr.payload
        return cls(int.from_bytes(b[0:4], byteorder="big"), attr.flags)


PathAttribute.attribute_types[4] = MultiExitDisc


class LocalPrefAttribute(PathAttribute):
    type_code = 5

    def __init__(self, local_pref, flags=0):
        self.local_pref = local_pref
        self.flags = flags

    @property
    def payload(self):
        return self.local_pref.to_bytes(4, byteorder="big")

    def __repr__(self):
        return "<LocalPrefAttribute {!r}>".format(self.local_pref)

    @classmethod
    def from_bytes(cls, b, **kwargs):
        attr = PathAttribute.from_bytes(b)
        b = attr.payload
        return cls(int.from_bytes(b[0:4], byteorder="big"), flags=attr.flags)


PathAttribute.attribute_types[5] = LocalPrefAttribute


class AtomicAggregateAttribute(PathAttribute):
    type_code = 6

    @property
    def payload(self):
        return b""

    def __repr__(self):
        return "<AtomicAggregateAttribute>"

    @classmethod
    def from_bytes(cls, b, **kwargs):
        attr = PathAttribute.from_bytes(b)
        return cls(flags=attr.flags)


PathAttribute.attribute_types[6] = AtomicAggregateAttribute


class AggregatorAttribute(PathAttribute):
    type_code = 7

    def __init__(self, asn, ip_address, asn4=False, flags=None):
        self.asn = asn
        self.ip_address = ip_address
        self.asn4 = asn4

    @property
    def payload(self):
        if self.asn4:
            b = self.asn.to_bytes(4, byteorder="big")
        else:
            b = self.asn.to_bytes(2, byteorder="big")
        return b + self.ip_address.packed

    def __repr__(self):
        return "<AggregatorAttribute asn={!r} ip_address={!r}>".format(
            self.asn,
            self.ip_address)

    @classmethod
    def from_bytes(cls, b, asn4=False, **kwargs):
        attr = PathAttribute.from_bytes(b)
        b = attr.payload
        if asn4:
            asn = int.from_bytes(b[0:4], byteorder="big")
            b = b[4:]
        else:
            asn = int.from_bytes(b[0:2], byteorder="big")
            b = b[2:]
        return cls(asn,
                   netaddr.IPAddress(int.from_bytes(b[0:4], byteorder="big")),
                   flags=attr.flags)


PathAttribute.attribute_types[7] = AggregatorAttribute


class CommunitiesAttribute(PathAttribute):
    type_code = 8

    def __init__(self, communities=[], flags=0):
        self.communities = list(communities)
        self.flags = flags

    def __repr__(self):
        return "<CommunitiesAttribute {!r}>".format(
            self.communities)

    @classmethod
    def from_bytes(cls, b, **kwargs):
        attr = PathAttribute.from_bytes(b)
        b = attr.payload
        attr = cls(flags=attr.flags)
        while b:
            attr.communities.append(int.from_bytes(b[0:4], byteorder="big"))
            b = b[4:]
        return attr


PathAttribute.attribute_types[8] = CommunitiesAttribute


class ExtendedCommunitiesAttribute(PathAttribute):
    type_code = 16

    def __init__(self, communities=[], flags=0):
        self.communities = list(communities)
        self.flags = flags

    def __repr__(self):
        return "<ExtendedCommunitiesAttribute {!r}>".format(self.communities)

    @classmethod
    def from_bytes(cls, b, **kwargs):
        pass


PathAttribute.attribute_types[16] = ExtendedCommunitiesAttribute


class LargeCommunitiesAttribute(PathAttribute):
    type_code = 32

    def __init__(self, communities=[], flags=0):
        self.communities = list(communities)
        self.flags = flags

    def __repr__(self):
        return "<LargeCommunitiesAttribute {!r}>".format(self.communities)

    @classmethod
    def from_bytes(cls, b, **kwargs):
        pass


PathAttribute.attribute_types[32] = LargeCommunitiesAttribute


class UpdateMessage(Message):
    type_ = MessageType.UPDATE

    def __init__(self, withdrawn=[], path_attributes=[], nlri=[]):
        self.withdrawn = list(withdrawn)
        self.path_attributes = list(path_attributes)
        self.nlri = list(nlri)

    @property
    def withdrawn_routes(self):
        pass

    @property
    def nlri_routes(self):
        pass

    def __repr__(self):
        return "<UpdateMessage withdrawn={self.withdrawn!r} " \
            "attributes={self.path_attributes!r} " \
            "nlri={self.nlri!r}>".format(self=self)

    def _to_bytes_withdrawn(self):
        return b""

    def _to_bytes_path_attrs(self):
        b = bytearray()
        for path_attr in self.path_attributes:
            b.extend(path_attr.to_bytes())
        return b

    def _to_bytes_nlri(self):
        return b""

    @property
    def payload(self):
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
    def from_bytes(cls, b, asn4=False, **kwargs):
        b = Message.from_bytes(b).payload
        msg = cls()

        withdrawn_len = int.from_bytes(b[0:2], byteorder="big")
        withdrawn_b = b[2:2 + withdrawn_len]
        path_attrs_len = int.from_bytes(b[2 + withdrawn_len:4 + withdrawn_len],
                                        byteorder="big")
        path_attrs_b = b[4 + withdrawn_len:4 + withdrawn_len + path_attrs_len]
        nlri_b = b[4 + withdrawn_len + path_attrs_len:]

        while withdrawn_b:
            w_len = withdrawn_b[0]
            msg.withdrawn.append((w_len, withdrawn_b[1:1 + (w_len >> 3)]))
            withdrawn_b = withdrawn_b[1 + (w_len >> 3):]
        while path_attrs_b:
            attr1 = PathAttribute.from_bytes(path_attrs_b,
                                             asn4=asn4,
                                             **kwargs)
            attr = PathAttribute.from_bytes(path_attrs_b,
                                            asn4=asn4,
                                            coerce=True,
                                            **kwargs)
            msg.path_attributes.append(attr)
            path_attrs_b = path_attrs_b[attr1.length:]
        while nlri_b:
            n_len = nlri_b[0]
            msg.nlri.append((n_len, nlri_b[1:1 + (n_len >> 3)]))
            nlri_b = nlri_b[1 + (n_len >> 3):]

        return msg


class NotificationMessage(Message):
    type_ = MessageType.NOTIFICATION

    def __init__(self, error_code=0, error_subcode=0, data=b""):
        self.error_code = error_code
        self.error_subcode = error_subcode
        self.data = bytes(data)

    def __repr__(self):
        return "<NotificationMessage error={self.error_code!r} "\
            "subcode={self.error_subcode!r} " \
            "data={self.data!r}>".format(self=self)

    @property
    def payload(self):
        return bytes([self.error_code, self.error_subcode]) + self.data

    @classmethod
    def from_bytes(cls, b, **kwargs):
        b = Message.from_bytes(b).payload
        return cls(b[0], b[1], b[2:])


class KeepaliveMessage(Message):
    type_ = MessageType.KEEPALIVE

    def __init__(self):
        pass

    @property
    def payload(self):
        return b""

    @property
    def length(self):
        return 19

    def __repr__(self):
        return "<KeepaliveMessage>"

    @classmethod
    def from_bytes(cls, b, **kwargs):
        return KeepaliveMessage()


async def read_message(reader):
    marker = await reader.readexactly(16)
    length = await reader.readexactly(2)
    length_ = int.from_bytes(length, byteorder='big')
    type_ = await reader.readexactly(1)
    body = await reader.readexactly(length_ - 16 - 2 - 1)
    return marker + length + type_ + body
