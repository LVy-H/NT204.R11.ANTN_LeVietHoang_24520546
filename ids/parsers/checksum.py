from __future__ import annotations


def internet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data = data + b"\x00"
    total = 0
    for offset in range(0, len(data), 2):
        total += (data[offset] << 8) | data[offset + 1]
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def pseudo_header(src: bytes, dst: bytes, protocol: int, length: int) -> bytes:
    return src + dst + bytes((0, protocol)) + length.to_bytes(2, "big")
