from __future__ import annotations

import struct
from dataclasses import dataclass
from ipaddress import IPv4Address

from ..issues import Issues, ParseError
from ..model import IpOption, Ipv4Flags, Ipv4Info
from .checksum import internet_checksum

IPV4_MIN_HEADER = 20
IPV4_MAX_HEADER = 60

IPPROTO_TCP = 6
IPPROTO_UDP = 17

IP_PROTOCOLS = {
    1: "ICMP",
    2: "IGMP",
    IPPROTO_TCP: "TCP",
    IPPROTO_UDP: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
    103: "PIM",
    112: "VRRP",
    132: "SCTP",
}

IP_OPTION_NAMES = {
    0: "EOL",
    1: "NOP",
    7: "RR",
    25: "QS",
    30: "EXP",
    68: "TS",
    94: "ADDRESS-EXT",
    130: "SEC",
    131: "LSR",
    136: "SID",
    137: "SSR",
    148: "RTRALT",
}

FLAG_RESERVED = 0x8000
FLAG_DF = 0x4000
FLAG_MF = 0x2000


@dataclass(frozen=True, slots=True)
class NetworkResult:
    info: Ipv4Info
    payload: bytes


def protocol_name(number: int) -> str:
    return IP_PROTOCOLS.get(number, f"UNKNOWN({number})")


def option_name(kind: int) -> str:
    return IP_OPTION_NAMES.get(kind, f"UNKNOWN({kind})")


def parse_options(raw: bytes) -> list[IpOption]:
    options: list[IpOption] = []
    offset = 0
    while offset < len(raw):
        kind = raw[offset]
        if kind == 0:
            options.append(IpOption(type=0, name="EOL"))
            remaining = raw[offset + 1 :]
            if any(remaining):
                options.append(IpOption(type=0, name="PADDING", length=len(remaining)))
            break
        if kind == 1:
            options.append(IpOption(type=1, name="NOP"))
            offset += 1
            continue
        if offset + 2 > len(raw):
            options.append(IpOption(type=kind, name="TRUNCATED"))
            break
        length = raw[offset + 1]
        if length < 2 or offset + length > len(raw):
            options.append(
                IpOption(
                    type=kind,
                    name=option_name(kind),
                    malformed=True,
                    declared_length=length,
                    available=len(raw) - offset,
                )
            )
            break
        options.append(
            IpOption(
                type=kind,
                name=option_name(kind),
                length=length,
                data=raw[offset + 2 : offset + length].hex(),
            )
        )
        offset += length
    return options


def parse_ipv4(data: bytes, issues: Issues) -> NetworkResult:
    if not data:
        raise ParseError("truncated_packet", "empty network layer payload", captured=0)

    version = data[0] >> 4
    if version == 6:
        raise ParseError("unsupported_protocol", "IPv6 is not supported", version=6)
    if version != 4:
        raise ParseError(
            "unsupported_protocol", f"unsupported IP version {version}", version=version
        )
    if len(data) < IPV4_MIN_HEADER:
        raise ParseError(
            "truncated_packet",
            "IPv4 header shorter than 20 bytes",
            declared=IPV4_MIN_HEADER,
            captured=len(data),
        )

    ihl = data[0] & 0x0F
    if ihl < 5:
        raise ParseError("malformed_header", f"IPv4 IHL {ihl} is below the minimum of 5", ihl=ihl)
    header_length = ihl * 4
    if header_length > IPV4_MAX_HEADER:
        raise ParseError(
            "malformed_header", f"IPv4 header length {header_length} exceeds 60 bytes", ihl=ihl
        )
    if len(data) < header_length:
        raise ParseError(
            "truncated_packet",
            "IPv4 header options truncated",
            declared=header_length,
            captured=len(data),
        )

    total_length, identification, flags_fragment, ttl, protocol, checksum, src_raw, dst_raw = (
        struct.unpack_from("!HHHBBH4s4s", data, 2)
    )
    if total_length < header_length:
        raise ParseError(
            "malformed_header",
            f"IPv4 total length {total_length} is smaller than its header length {header_length}",
            total_length=total_length,
            header_length=header_length,
        )

    truncated = total_length > len(data)
    if truncated:
        issues.add(
            "truncated_packet",
            "captured bytes are shorter than the IPv4 total length",
            declared=total_length,
            captured=len(data),
        )
    payload = data[header_length:] if truncated else data[header_length:total_length]
    fragment_offset = flags_fragment & 0x1FFF
    more_fragments = bool(flags_fragment & FLAG_MF)
    info = Ipv4Info(
        protocol="IPv4",
        version=4,
        header_length=header_length,
        dscp=data[1] >> 2,
        ecn=data[1] & 0x03,
        tos=data[1],
        total_length=total_length,
        identification=identification,
        flags=Ipv4Flags(
            reserved=bool(flags_fragment & FLAG_RESERVED),
            df=bool(flags_fragment & FLAG_DF),
            mf=more_fragments,
        ),
        fragment_offset=fragment_offset,
        fragmented=fragment_offset > 0 or more_fragments,
        ttl=ttl,
        protocol_number=protocol,
        protocol_name=protocol_name(protocol),
        header_checksum=f"0x{checksum:04x}",
        header_checksum_valid=internet_checksum(data[:header_length]) == 0,
        src_ip=str(IPv4Address(src_raw)),
        dst_ip=str(IPv4Address(dst_raw)),
        options=(
            parse_options(data[IPV4_MIN_HEADER:header_length])
            if header_length > IPV4_MIN_HEADER
            else []
        ),
        captured_truncated=truncated,
        declared_payload_length=total_length - header_length,
        captured_payload_length=len(payload),
    )
    return NetworkResult(info, payload)
