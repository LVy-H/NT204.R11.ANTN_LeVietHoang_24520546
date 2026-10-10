from __future__ import annotations

import struct
from collections.abc import Callable
from dataclasses import dataclass
from ipaddress import IPv4Address

from ..issues import ParseError
from ..model import TcpFlags, TcpInfo, TcpOption, UdpInfo
from .checksum import internet_checksum, pseudo_header
from .network import IPPROTO_TCP, IPPROTO_UDP

TCP_MIN_HEADER = 20
TCP_MAX_HEADER = 60
UDP_HEADER = 8

TCP_OPTION_NAMES = {
    0: "EOL",
    1: "NOP",
    2: "MSS",
    3: "WScale",
    4: "SACK-Permitted",
    5: "SACK",
    8: "Timestamps",
    28: "UTO",
    29: "AO",
    30: "MPTCP",
    34: "FASTOPEN",
}

TCP_FLAG_BITS = (
    (0x0001, "fin", "F"),
    (0x0002, "syn", "S"),
    (0x0004, "rst", "R"),
    (0x0008, "psh", "P"),
    (0x0010, "ack", "A"),
    (0x0020, "urg", "U"),
    (0x0040, "ece", "E"),
    (0x0080, "cwr", "W"),
    (0x0100, "ns", "N"),
)


@dataclass(frozen=True, slots=True)
class TransportResult:
    info: TcpInfo | UdpInfo
    payload: bytes


def tcp_options(raw: bytes) -> list[TcpOption]:
    options: list[TcpOption] = []
    offset = 0
    while offset < len(raw):
        kind = raw[offset]
        if kind == 0:
            options.append(TcpOption(type=0, name="EOL"))
            break
        if kind == 1:
            options.append(TcpOption(type=1, name="NOP"))
            offset += 1
            continue
        name = TCP_OPTION_NAMES.get(kind, f"UNKNOWN({kind})")
        if offset + 2 > len(raw):
            options.append(TcpOption(type=kind, name=name, malformed=True))
            break
        length = raw[offset + 1]
        if length < 2 or offset + length > len(raw):
            options.append(
                TcpOption(
                    type=kind,
                    name=name,
                    malformed=True,
                    declared_length=length,
                    available=len(raw) - offset,
                )
            )
            break
        value = raw[offset + 2 : offset + length]
        option = TcpOption(type=kind, name=name, length=length)
        if kind == 2 and length == 4:
            option.mss = int.from_bytes(value, "big")
        elif kind == 3 and length == 3:
            option.shift = value[0]
        elif kind == 8 and length == 10:
            option.tsval = int.from_bytes(value[0:4], "big")
            option.tsecr = int.from_bytes(value[4:8], "big")
        elif kind == 5 and length >= 10:
            option.blocks = [
                [
                    int.from_bytes(value[i : i + 4], "big"),
                    int.from_bytes(value[i + 4 : i + 8], "big"),
                ]
                for i in range(0, len(value) - 7, 8)
            ]
        else:
            option.data = value.hex()
        options.append(option)
        offset += length
    return options


def _checksum_state(
    data: bytes, src_ip: str, dst_ip: str, protocol: int, declared_length: int | None
) -> bool | None:
    if declared_length is None or declared_length != len(data):
        return None
    header = pseudo_header(
        IPv4Address(src_ip).packed, IPv4Address(dst_ip).packed, protocol, declared_length
    )
    return internet_checksum(header + data) == 0


def parse_tcp(
    data: bytes, *, src_ip: str, dst_ip: str, declared_length: int | None = None
) -> TransportResult:
    if len(data) < TCP_MIN_HEADER:
        raise ParseError(
            "truncated_packet",
            "TCP header shorter than 20 bytes",
            declared=TCP_MIN_HEADER,
            captured=len(data),
        )

    src_port, dst_port, seq, ack, offset_flags, window, checksum, urgent = struct.unpack_from(
        "!HHIIHHHH", data, 0
    )
    data_offset = (offset_flags >> 12) & 0x0F
    header_length = data_offset * 4
    if data_offset < 5:
        raise ParseError(
            "malformed_header",
            f"TCP data offset {data_offset} is below the minimum of 5",
            data_offset=data_offset,
        )
    if header_length > TCP_MAX_HEADER:
        raise ParseError(
            "malformed_header",
            f"TCP header length {header_length} exceeds 60 bytes",
            data_offset=data_offset,
        )
    if len(data) < header_length:
        raise ParseError(
            "truncated_packet",
            "TCP header options truncated",
            declared=header_length,
            captured=len(data),
        )

    present = [(name, letter) for bit, name, letter in TCP_FLAG_BITS if offset_flags & bit]
    payload = data[header_length:]
    info = TcpInfo(
        src_port=src_port,
        dst_port=dst_port,
        seq=seq,
        ack=ack,
        header_length=header_length,
        reserved=(offset_flags >> 9) & 0x07,
        flags=TcpFlags(**{name: bool(offset_flags & bit) for bit, name, _ in TCP_FLAG_BITS}),
        flags_list=[name.upper() for name, _ in present],
        flags_string="".join(letter for _, letter in present),
        window=window,
        checksum=f"0x{checksum:04x}",
        checksum_valid=_checksum_state(data, src_ip, dst_ip, IPPROTO_TCP, declared_length),
        urgent_pointer=urgent,
        options=(
            tcp_options(data[TCP_MIN_HEADER:header_length])
            if header_length > TCP_MIN_HEADER
            else []
        ),
        payload_length=len(payload),
    )
    return TransportResult(info, payload)


def parse_udp(
    data: bytes, *, src_ip: str, dst_ip: str, declared_length: int | None = None
) -> TransportResult:
    if len(data) < UDP_HEADER:
        raise ParseError(
            "truncated_packet",
            "UDP header shorter than 8 bytes",
            declared=UDP_HEADER,
            captured=len(data),
        )

    src_port, dst_port, length, checksum = struct.unpack_from("!HHHH", data, 0)
    if length < UDP_HEADER:
        raise ParseError(
            "malformed_header", f"UDP length {length} is below the minimum of 8", length=length
        )

    truncated = length > len(data)
    payload = data[UDP_HEADER:] if truncated else data[UDP_HEADER:length]
    if checksum == 0 or truncated or length != len(data):
        checksum_valid = None
    else:
        checksum_valid = _checksum_state(data, src_ip, dst_ip, IPPROTO_UDP, length)

    info = UdpInfo(
        src_port=src_port,
        dst_port=dst_port,
        length=length,
        checksum=f"0x{checksum:04x}",
        checksum_valid=checksum_valid,
        declared_payload_length=length - UDP_HEADER,
        payload_length=len(payload),
        captured_truncated=truncated,
    )
    return TransportResult(info, payload)


_PARSERS: dict[int, Callable[..., TransportResult]] = {
    IPPROTO_TCP: parse_tcp,
    IPPROTO_UDP: parse_udp,
}


def parse_transport(
    protocol_number: int,
    data: bytes,
    *,
    src_ip: str,
    dst_ip: str,
    declared_length: int | None = None,
    fragment_offset: int = 0,
) -> TransportResult:
    if fragment_offset:
        raise ParseError(
            "unsupported_protocol",
            "non-first IPv4 fragment has no transport header",
            fragment_offset=fragment_offset,
        )
    parser = _PARSERS.get(protocol_number)
    if parser is None:
        raise ParseError(
            "unsupported_protocol",
            f"IP protocol {protocol_number} has no transport parser",
            protocol_number=protocol_number,
        )
    return parser(data, src_ip=src_ip, dst_ip=dst_ip, declared_length=declared_length)
