from __future__ import annotations

import struct
from ipaddress import ip_address

from ..errors import DecodeError, TruncatedPacketError

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
            raise DecodeError(
                "DNS name extends past the end of the message",
                stage="application",
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
                raise DecodeError(
                    "truncated DNS compression pointer", stage="application", offset=offset
                )
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if end is None:
                end = offset + 2
            jumps += 1
            if jumps > MAX_POINTER_JUMPS:
                raise DecodeError(
                    "DNS compression pointer loop", stage="application", offset=offset
                )
            offset = pointer
            continue
        if length & 0xC0:
            raise DecodeError(
                "invalid DNS label length byte",
                stage="application",
                offset=offset,
                value=hex(length),
            )
        if offset + 1 + length > len(data):
            raise DecodeError(
                "truncated DNS label", stage="application", offset=offset, label_length=length
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
            raise DecodeError(
                f"{type_name(rtype)} record has rdlength {rdlength}, expected {expected}",
                stage="application",
            )
        return str(ip_address(data[offset : offset + rdlength]))
    if rtype in NAME_TYPES:
        return read_name(data, offset)[0]
    if rtype == 15:
        if rdlength < 3:
            raise DecodeError("MX record is too short", stage="application", rdlength=rdlength)
        return {
            "preference": struct.unpack_from("!H", data, offset)[0],
            "exchange": read_name(data, offset + 2)[0],
        }
    if rtype == 33:
        if rdlength < 7:
            raise DecodeError("SRV record is too short", stage="application", rdlength=rdlength)
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
            raise DecodeError("SOA record is too short", stage="application", rdlength=rdlength)
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


def _read_record(data: bytes, offset: int) -> tuple[dict, int]:
    name, offset = read_name(data, offset)
    if offset + 10 > len(data):
        raise TruncatedPacketError(
            "DNS resource record header truncated",
            stage="application",
            offset=offset,
            captured=len(data),
        )
    rtype, rclass, ttl, rdlength = struct.unpack_from("!HHIH", data, offset)
    offset += 10
    if offset + rdlength > len(data):
        raise TruncatedPacketError(
            "DNS resource record rdata truncated",
            stage="application",
            declared=rdlength,
            available=len(data) - offset,
        )
    record = {
        "name": name,
        "type": rtype,
        "type_name": type_name(rtype),
        "class": rclass,
        "class_name": class_name(rclass),
        "ttl": ttl,
        "rdlength": rdlength,
    }
    try:
        value = read_rdata(data, offset, rtype, rdlength)
    except DecodeError as error:
        record["rdata_error"] = error.to_dict()
        value = None
    if value is None:
        record["rdata"] = data[offset : offset + rdlength].hex()
    else:
        record["value"] = value
    if rtype == 41:
        record["udp_payload_size"] = rclass
    return record, offset + rdlength


def parse(data: bytes, *, tcp: bool = False) -> dict:
    if tcp:
        if len(data) < 2:
            raise TruncatedPacketError(
                "DNS over TCP message has no length prefix", stage="application"
            )
        declared = struct.unpack_from("!H", data, 0)[0]
        if declared < HEADER_LENGTH:
            raise DecodeError(
                f"DNS over TCP length prefix {declared} is below the header size",
                stage="application",
            )
        if declared > len(data) - 2:
            raise TruncatedPacketError(
                "DNS over TCP message truncated",
                stage="application",
                declared=declared,
                captured=len(data) - 2,
            )
        data = data[2 : 2 + declared]

    if len(data) < HEADER_LENGTH:
        raise TruncatedPacketError(
            "DNS header shorter than 12 bytes",
            stage="application",
            declared=HEADER_LENGTH,
            captured=len(data),
        )

    identifier, flags, qdcount, ancount, nscount, arcount = struct.unpack_from("!HHHHHH", data, 0)
    counts = {
        "questions": qdcount,
        "answers": ancount,
        "authorities": nscount,
        "additionals": arcount,
    }
    total = qdcount + ancount + nscount + arcount
    if total == 0:
        raise DecodeError("DNS message declares no sections", stage="application", counts=counts)

    opcode = (flags >> 11) & 0x0F
    rcode = flags & 0x0F
    info: dict = {
        "kind": "response" if flags & 0x8000 else "query",
        "id": identifier,
        "flags": {
            "qr": bool(flags & 0x8000),
            "opcode": opcode,
            "aa": bool(flags & 0x0400),
            "tc": bool(flags & 0x0200),
            "rd": bool(flags & 0x0100),
            "ra": bool(flags & 0x0080),
            "z": bool(flags & 0x0040),
            "ad": bool(flags & 0x0020),
            "cd": bool(flags & 0x0010),
            "rcode": rcode,
        },
        "opcode": opcode,
        "opcode_name": OPCODES.get(opcode, f"OPCODE{opcode}"),
        "rcode": rcode,
        "rcode_name": RCODES.get(rcode, f"RCODE{rcode}"),
        "counts": counts,
        "questions": [],
        "answers": [],
        "authorities": [],
        "additionals": [],
        "tcp": tcp,
    }

    offset = HEADER_LENGTH
    for _ in range(qdcount):
        name, offset = read_name(data, offset)
        if offset + 4 > len(data):
            raise TruncatedPacketError("DNS question truncated", stage="application", offset=offset)
        qtype, qclass = struct.unpack_from("!HH", data, offset)
        offset += 4
        info["questions"].append(
            {
                "name": name,
                "type": qtype,
                "type_name": type_name(qtype),
                "class": qclass,
                "class_name": class_name(qclass),
            }
        )

    for section, count in (
        ("answers", ancount),
        ("authorities", nscount),
        ("additionals", arcount),
    ):
        for _ in range(count):
            record, offset = _read_record(data, offset)
            info[section].append(record)

    return info
