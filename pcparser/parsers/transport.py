from __future__ import annotations

import struct
from collections import namedtuple
from ipaddress import IPv4Address

from ..errors import MalformedHeaderError, TruncatedPacketError, UnsupportedProtocolError
from .checksum import internet_checksum, pseudo_header

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

TransportParse = namedtuple("TransportParse", "info payload")


def tcp_options(raw: bytes) -> list[dict]:
    options: list[dict] = []
    offset = 0
    while offset < len(raw):
        kind = raw[offset]
        if kind == 0:
            options.append({"type": 0, "name": "EOL"})
            break
        if kind == 1:
            options.append({"type": 1, "name": "NOP"})
            offset += 1
            continue
        name = TCP_OPTION_NAMES.get(kind, f"UNKNOWN({kind})")
        if offset + 2 > len(raw):
            options.append({"type": kind, "name": name, "malformed": True, "declared_length": None})
            break
        length = raw[offset + 1]
        if length < 2 or offset + length > len(raw):
            options.append(
                {
                    "type": kind,
                    "name": name,
                    "malformed": True,
                    "declared_length": length,
                    "available": len(raw) - offset,
                }
            )
            break
        value = raw[offset + 2 : offset + length]
        entry: dict = {"type": kind, "name": name, "length": length}
        if kind == 2 and length == 4:
            entry["mss"] = int.from_bytes(value, "big")
        elif kind == 3 and length == 3:
            entry["shift"] = value[0]
        elif kind == 8 and length == 10:
            entry["tsval"] = int.from_bytes(value[0:4], "big")
            entry["tsecr"] = int.from_bytes(value[4:8], "big")
        elif kind == 5 and length >= 10:
            entry["blocks"] = [
                [int.from_bytes(value[i : i + 4], "big"), int.from_bytes(value[i + 4 : i + 8], "big")]
                for i in range(0, len(value) - 7, 8)
            ]
        else:
            entry["data"] = value.hex()
        options.append(entry)
        offset += length
    return options


def _checksum_state(data: bytes, src_ip: str, dst_ip: str, protocol: int, declared_length: int | None):
    if declared_length is None or declared_length != len(data):
        return None
    header = pseudo_header(IPv4Address(src_ip).packed, IPv4Address(dst_ip).packed, protocol, declared_length)
    return internet_checksum(header + data) == 0


def parse_tcp(data: bytes, *, src_ip: str, dst_ip: str, declared_length: int | None = None) -> TransportParse:
    if len(data) < TCP_MIN_HEADER:
        raise TruncatedPacketError(
            "TCP header shorter than 20 bytes", stage="transport", declared=TCP_MIN_HEADER, captured=len(data)
        )

    src_port, dst_port, seq, ack, offset_flags, window, checksum, urgent = struct.unpack_from(
        "!HHIIHHHH", data, 0
    )
    data_offset = (offset_flags >> 12) & 0x0F
    header_length = data_offset * 4
    if data_offset < 5:
        raise MalformedHeaderError(
            f"TCP data offset {data_offset} is below the minimum of 5", stage="transport", data_offset=data_offset
        )
    if header_length > TCP_MAX_HEADER:
        raise MalformedHeaderError(
            f"TCP header length {header_length} exceeds 60 bytes", stage="transport", data_offset=data_offset
        )
    if len(data) < header_length:
        raise TruncatedPacketError(
            "TCP header options truncated", stage="transport", declared=header_length, captured=len(data)
        )

    flags = {name: bool(offset_flags & bit) for bit, name, _ in TCP_FLAG_BITS}
    options = tcp_options(data[TCP_MIN_HEADER:header_length]) if header_length > TCP_MIN_HEADER else []
    payload = data[header_length:]
    info = {
        "protocol": "TCP",
        "src_port": src_port,
        "dst_port": dst_port,
        "seq": seq,
        "ack": ack,
        "header_length": header_length,
        "reserved": (offset_flags >> 9) & 0x07,
        "flags": flags,
        "flags_list": [name.upper() for _, name, _ in TCP_FLAG_BITS if flags[name]],
        "flags_string": "".join(letter for bit, name, letter in TCP_FLAG_BITS if flags[name]),
        "window": window,
        "checksum": f"0x{checksum:04x}",
        "checksum_valid": _checksum_state(data, src_ip, dst_ip, 6, declared_length),
        "urgent_pointer": urgent,
        "options": options,
        "payload_length": len(payload),
    }
    return TransportParse(info, payload)


def parse_udp(data: bytes, *, src_ip: str, dst_ip: str, declared_length: int | None = None) -> TransportParse:
    if len(data) < UDP_HEADER:
        raise TruncatedPacketError(
            "UDP header shorter than 8 bytes", stage="transport", declared=UDP_HEADER, captured=len(data)
        )

    src_port, dst_port, length, checksum = struct.unpack_from("!HHHH", data, 0)
    if length < UDP_HEADER:
        raise MalformedHeaderError(
            f"UDP length {length} is below the minimum of 8", stage="transport", length=length
        )

    truncation = length > len(data)
    payload = data[UDP_HEADER:length] if not truncation else data[UDP_HEADER:]
    if checksum == 0:
        checksum_valid = None
    elif truncation or length != len(data):
        checksum_valid = None
    else:
        checksum_valid = _checksum_state(data, src_ip, dst_ip, 17, length)

    info = {
        "protocol": "UDP",
        "src_port": src_port,
        "dst_port": dst_port,
        "length": length,
        "checksum": f"0x{checksum:04x}",
        "checksum_valid": checksum_valid,
        "declared_payload_length": length - UDP_HEADER,
        "payload_length": len(payload),
        "captured_truncated": truncation,
    }
    return TransportParse(info, payload)


def parse_transport(
    protocol_number: int,
    data: bytes,
    *,
    src_ip: str,
    dst_ip: str,
    declared_length: int | None = None,
    fragment_offset: int = 0,
    more_fragments: bool = False,
) -> TransportParse:
    if fragment_offset:
        raise UnsupportedProtocolError(
            "non-first IPv4 fragment has no transport header",
            stage="transport",
            fragment_offset=fragment_offset,
        )
    if protocol_number == 6:
        return parse_tcp(data, src_ip=src_ip, dst_ip=dst_ip, declared_length=declared_length)
    if protocol_number == 17:
        return parse_udp(data, src_ip=src_ip, dst_ip=dst_ip, declared_length=declared_length)
    raise UnsupportedProtocolError(
        f"IP protocol {protocol_number} has no transport parser",
        stage="transport",
        protocol_number=protocol_number,
        more_fragments=more_fragments,
    )
