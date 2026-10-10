from __future__ import annotations

import re
import struct
from ipaddress import ip_address

from ..issues import Issue, Issues, ParseError, jsonable
from ..model import DnsCounts, DnsFlags, DnsMessage, DnsQuestion, DnsRecord

NAME = "DNS"
PORTS = frozenset((53, 5353))

HEADER_LENGTH = 12
MAX_POINTER_JUMPS = 64

QTYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    13: "HINFO",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    35: "NAPTR",
    41: "OPT",
    43: "DS",
    46: "RRSIG",
    47: "NSEC",
    48: "DNSKEY",
    64: "SVCB",
    65: "HTTPS",
    99: "SPF",
    251: "IXFR",
    252: "AXFR",
    255: "ANY",
}

QCLASSES = {1: "IN", 3: "CH", 4: "HS", 254: "NONE", 255: "ANY"}

RCODES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
    6: "YXDOMAIN",
    7: "YXRRSET",
    8: "NXRRSET",
    9: "NOTAUTH",
    10: "NOTZONE",
    16: "BADVERS",
}

OPCODES = {0: "QUERY", 1: "IQUERY", 2: "STATUS", 4: "NOTIFY", 5: "UPDATE"}

NAME_TYPES = frozenset((2, 5, 12))
ADDRESS_TYPES = {1: 4, 28: 16}
TYPE_OPT = 41

PLAUSIBLE_LABEL = re.compile(rb"^[A-Za-z0-9_-]{1,63}$")


def type_name(value: int) -> str:
    return QTYPES.get(value, f"TYPE{value}")


def class_name(value: int) -> str:
    return QCLASSES.get(value, f"CLASS{value}")


def read_name(data: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    jumps = 0
    end = None
    while True:
        if offset >= len(data):
            raise ParseError(
                "decode_error",
                "DNS name extends past the end of the message",
                offset=offset,
                length=len(data),
            )
        length = data[offset]
        if length == 0:
            offset += 1
            if end is None:
                end = offset
            break
        if length & 0xC0 == 0xC0:
            if offset + 2 > len(data):
                raise ParseError("decode_error", "truncated DNS compression pointer", offset=offset)
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if end is None:
                end = offset + 2
            jumps += 1
            if jumps > MAX_POINTER_JUMPS:
                raise ParseError("decode_error", "DNS compression pointer loop", offset=offset)
            offset = pointer
            continue
        if length & 0xC0:
            raise ParseError(
                "decode_error",
                "invalid DNS label length byte",
                offset=offset,
                value=hex(length),
            )
        if offset + 1 + length > len(data):
            raise ParseError(
                "decode_error", "truncated DNS label", offset=offset, label_length=length
            )
        labels.append(data[offset + 1 : offset + 1 + length].decode("latin-1"))
        offset += 1 + length
    return ".".join(labels) if labels else ".", end


def _character_strings(data: bytes, offset: int, end: int) -> list[str]:
    strings = []
    while offset < end:
        length = data[offset]
        offset += 1
        strings.append(data[offset : offset + length].decode("latin-1"))
        offset += length
    return strings


def read_rdata(data: bytes, offset: int, rtype: int, rdlength: int) -> object:
    if rtype in ADDRESS_TYPES:
        expected = ADDRESS_TYPES[rtype]
        if rdlength != expected:
            raise ParseError(
                "decode_error",
                f"{type_name(rtype)} record has rdlength {rdlength}, expected {expected}",
            )
        return str(ip_address(data[offset : offset + rdlength]))
    if rtype in NAME_TYPES:
        return read_name(data, offset)[0]
    if rtype == 15:
        if rdlength < 3:
            raise ParseError("decode_error", "MX record is too short", rdlength=rdlength)
        return {
            "preference": struct.unpack_from("!H", data, offset)[0],
            "exchange": read_name(data, offset + 2)[0],
        }
    if rtype == 33:
        if rdlength < 7:
            raise ParseError("decode_error", "SRV record is too short", rdlength=rdlength)
        priority, weight, port = struct.unpack_from("!HHH", data, offset)
        return {
            "priority": priority,
            "weight": weight,
            "port": port,
            "target": read_name(data, offset + 6)[0],
        }
    if rtype == 16:
        return _character_strings(data, offset, offset + rdlength)
    if rtype == 6:
        mname, cursor = read_name(data, offset)
        rname, cursor = read_name(data, cursor)
        if cursor + 20 > len(data):
            raise ParseError("decode_error", "SOA record is too short", rdlength=rdlength)
        serial, refresh, retry, expire, minimum = struct.unpack_from("!IIIII", data, cursor)
        return {
            "mname": mname,
            "rname": rname,
            "serial": serial,
            "refresh": refresh,
            "retry": retry,
            "expire": expire,
            "minimum": minimum,
        }
    return None


def _read_record(data: bytes, offset: int, stage: str) -> tuple[DnsRecord, int]:
    name, offset = read_name(data, offset)
    if offset + 10 > len(data):
        raise ParseError(
            "truncated_packet",
            "DNS resource record header truncated",
            offset=offset,
            captured=len(data),
        )
    rtype, rclass, ttl, rdlength = struct.unpack_from("!HHIH", data, offset)
    offset += 10
    if offset + rdlength > len(data):
        raise ParseError(
            "truncated_packet",
            "DNS resource record rdata truncated",
            declared=rdlength,
            available=len(data) - offset,
        )
    record = DnsRecord(
        name=name,
        type=rtype,
        type_name=type_name(rtype),
        class_=rclass,
        class_name=class_name(rclass),
        ttl=ttl,
        rdlength=rdlength,
    )
    try:
        record.value = read_rdata(data, offset, rtype, rdlength)
    except ParseError as error:
        record.rdata_error = Issue(stage, error.code, error.message, jsonable(error.context))
    if record.value is None:
        record.rdata = data[offset : offset + rdlength].hex()
    if rtype == TYPE_OPT:
        record.udp_payload_size = rclass
    return record, offset + rdlength


def _unwrap_tcp(data: bytes) -> bytes:
    if len(data) < 2:
        raise ParseError("truncated_packet", "DNS over TCP message has no length prefix")
    declared = struct.unpack_from("!H", data, 0)[0]
    if declared < HEADER_LENGTH:
        raise ParseError(
            "decode_error", f"DNS over TCP length prefix {declared} is below the header size"
        )
    if declared > len(data) - 2:
        raise ParseError(
            "truncated_packet",
            "DNS over TCP message truncated",
            declared=declared,
            captured=len(data) - 2,
        )
    return data[2 : 2 + declared]


def parse(payload: bytes, *, tcp: bool, issues: Issues) -> DnsMessage:
    data = _unwrap_tcp(payload) if tcp else payload
    if len(data) < HEADER_LENGTH:
        raise ParseError(
            "truncated_packet",
            "DNS header shorter than 12 bytes",
            declared=HEADER_LENGTH,
            captured=len(data),
        )

    identifier, flags, qdcount, ancount, nscount, arcount = struct.unpack_from("!HHHHHH", data, 0)
    if qdcount + ancount + nscount + arcount == 0:
        raise ParseError("decode_error", "DNS message declares no sections")

    opcode = (flags >> 11) & 0x0F
    rcode = flags & 0x0F
    message = DnsMessage(
        kind="response" if flags & 0x8000 else "query",
        id=identifier,
        flags=DnsFlags(
            qr=bool(flags & 0x8000),
            opcode=opcode,
            aa=bool(flags & 0x0400),
            tc=bool(flags & 0x0200),
            rd=bool(flags & 0x0100),
            ra=bool(flags & 0x0080),
            z=bool(flags & 0x0040),
            ad=bool(flags & 0x0020),
            cd=bool(flags & 0x0010),
            rcode=rcode,
        ),
        opcode=opcode,
        opcode_name=OPCODES.get(opcode, f"OPCODE{opcode}"),
        rcode=rcode,
        rcode_name=RCODES.get(rcode, f"RCODE{rcode}"),
        counts=DnsCounts(
            questions=qdcount, answers=ancount, authorities=nscount, additionals=arcount
        ),
        tcp=tcp,
    )

    offset = HEADER_LENGTH
    for _ in range(qdcount):
        name, offset = read_name(data, offset)
        if offset + 4 > len(data):
            raise ParseError("truncated_packet", "DNS question truncated", offset=offset)
        qtype, qclass = struct.unpack_from("!HH", data, offset)
        offset += 4
        message.questions.append(
            DnsQuestion(
                name=name,
                type=qtype,
                type_name=type_name(qtype),
                class_=qclass,
                class_name=class_name(qclass),
            )
        )

    for section, count in (
        (message.answers, ancount),
        (message.authorities, nscount),
        (message.additionals, arcount),
    ):
        for _ in range(count):
            record, offset = _read_record(data, offset, issues.stage)
            section.append(record)
    return message


def _plausible_name(name: str | None) -> bool:
    if not name or name == ".":
        return False
    return all(
        PLAUSIBLE_LABEL.match(label.encode("latin-1", "replace"))
        for label in name.rstrip(".").split(".")
        if label
    )


def score(payload: bytes, tcp: bool) -> tuple[float, str | None]:
    if tcp:
        if len(payload) < HEADER_LENGTH + 2:
            return 0.0, None
        declared = int.from_bytes(payload[:2], "big")
        if declared < HEADER_LENGTH or declared + 2 > len(payload):
            return 0.0, None
    elif len(payload) < HEADER_LENGTH:
        return 0.0, None

    try:
        message = parse(payload, tcp=tcp, issues=Issues("detect"))
    except ParseError:
        return 0.0, None

    if message.opcode not in OPCODES:
        return 0.2, "DNS header with an unknown opcode"

    confidence = 0.45
    evidence = ["DNS header"]
    if message.questions:
        question = message.questions[0]
        if _plausible_name(question.name):
            confidence += 0.25
            evidence.append("plausible question name")
        if question.type in QTYPES:
            confidence += 0.15
            evidence.append(f"known qtype {question.type_name}")
        if question.class_ in QCLASSES:
            confidence += 0.05
    if message.kind == "response" and message.counts.answers:
        confidence += 0.10
        evidence.append("response with answers")
    return min(confidence, 1.0), ", ".join(evidence)
