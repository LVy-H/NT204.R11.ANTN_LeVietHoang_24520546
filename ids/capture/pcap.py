from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from ..issues import ParseError
from ..model import RawPacket
from .base import linktype_name

MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}

NG_SHB = b"\x0a\x0d\x0d\x0a"
NG_BOM_BE = b"\x1a\x2b\x3c\x4d"
NG_BOM_LE = b"\x4d\x3c\x2b\x1a"
NG_IDB = 1
NG_SPB = 3
NG_EPB = 6
NG_TSRESOL = 9
NG_IDB_MIN_BODY = 8


@dataclass(frozen=True, slots=True)
class _Record:
    timestamp: float
    linktype: int
    data: bytes
    original_length: int
    declared_capture_length: int


@dataclass(frozen=True, slots=True)
class _Interface:
    linktype: int
    snaplen: int
    divisor: int


def _options(data: bytes, endian: str) -> Iterator[tuple[int, bytes]]:
    offset = 0
    while offset + 4 <= len(data):
        code, length = struct.unpack_from(endian + "HH", data, offset)
        if code == 0:
            return
        yield code, data[offset + 4 : offset + 4 + length]
        offset += 4 + length + (-length % 4)


def _interface(body: bytes, endian: str) -> _Interface:
    linktype, _, snaplen = struct.unpack_from(endian + "HHI", body, 0)
    divisor = 1_000_000
    for code, value in _options(body[NG_IDB_MIN_BODY:], endian):
        if code == NG_TSRESOL and value:
            exponent = value[0] & 0x7F
            divisor = 2**exponent if value[0] & 0x80 else 10**exponent
    return _Interface(linktype, snaplen, divisor)


class PcapSource:
    source = "pcap"

    def __init__(self, path: str | Path, *, count: int | None = None) -> None:
        self.path = Path(path)
        self.origin = str(self.path)
        self.count = count
        self.linktype: int | None = None
        self.snaplen: int | None = None
        self.format: str | None = None
        self.warnings: list[str] = []

    def close(self) -> None:
        """The file handle lives inside items(); nothing else is held open."""

    def describe(self) -> dict[str, object]:
        return {
            "source": self.source,
            "origin": self.origin,
            "format": self.format,
            "linktype": self.linktype,
            "linktype_name": linktype_name(self.linktype),
            "snaplen": self.snaplen,
            "count_limit": self.count,
        }

    def items(self) -> Iterator[RawPacket]:
        with self.path.open("rb") as handle:
            magic = handle.read(4)
            if len(magic) < 4:
                raise ParseError("malformed_header", "capture file is empty", path=self.origin)
            if magic == NG_SHB:
                records = self._pcapng(handle, magic)
            elif magic in MAGIC:
                records = self._classic(handle, magic)
            else:
                raise ParseError(
                    "malformed_header", "unrecognised capture file format", magic=magic.hex()
                )
            for index, record in enumerate(records, start=1):
                if self.count is not None and index > self.count:
                    return
                if self.linktype is None:
                    self.linktype = record.linktype
                yield RawPacket(
                    packet_id=index,
                    timestamp=record.timestamp,
                    data=record.data,
                    linktype=record.linktype,
                    source=self.source,
                    origin=self.origin,
                    original_length=record.original_length,
                    declared_capture_length=record.declared_capture_length,
                )

    def _classic(self, handle: BinaryIO, magic: bytes) -> Iterator[_Record]:
        endian, divisor = MAGIC[magic]
        header = handle.read(20)
        if len(header) < 20:
            raise ParseError("malformed_header", "truncated pcap global header", path=self.origin)
        _, _, _, _, snaplen, network = struct.unpack(endian + "HHiIII", header)
        linktype = network & 0xFFFF
        self.format = "pcap"
        self.linktype = linktype
        self.snaplen = snaplen
        while True:
            raw = handle.read(16)
            if not raw:
                return
            if len(raw) < 16:
                self.warnings.append("truncated pcap record header at end of file")
                return
            ts_sec, ts_frac, cap_len, orig_len = struct.unpack(endian + "IIII", raw)
            data = handle.read(cap_len)
            short = len(data) < cap_len
            if short:
                self.warnings.append(
                    f"record {ts_sec}.{ts_frac} declares {cap_len} captured bytes, "
                    f"{len(data)} present"
                )
            yield _Record(ts_sec + ts_frac / divisor, linktype, data, orig_len, cap_len)
            if short:
                self.warnings.append(
                    "stopping at the truncated record, the file position is unreliable"
                )
                return

    def _pcapng(self, handle: BinaryIO, first_block_type: bytes) -> Iterator[_Record]:
        self.format = "pcapng"
        endian = "<"
        interfaces: list[_Interface | None] = []
        pending: bytes | None = first_block_type
        while True:
            if pending is not None:
                block_type_raw, pending = pending, None
            else:
                block_type_raw = handle.read(4)
                if not block_type_raw:
                    return
                if len(block_type_raw) < 4:
                    self.warnings.append("truncated pcapng block type")
                    return
            if block_type_raw == NG_SHB:
                rest = handle.read(8)
                if len(rest) < 8:
                    self.warnings.append("truncated pcapng section header")
                    return
                if rest[4:] == NG_BOM_LE:
                    endian = "<"
                elif rest[4:] == NG_BOM_BE:
                    endian = ">"
                else:
                    self.warnings.append("pcapng section header without byte-order magic")
                    return
                total_len = struct.unpack(endian + "I", rest[:4])[0]
                if total_len < 28:
                    self.warnings.append(f"invalid pcapng section length {total_len}")
                    return
                body = handle.read(total_len - 16)
                if len(body) < total_len - 16 or len(handle.read(4)) < 4:
                    self.warnings.append("truncated pcapng section header")
                    return
                interfaces = []
                continue
            length_raw = handle.read(4)
            if len(length_raw) < 4:
                self.warnings.append("truncated pcapng block length")
                return
            block_type = struct.unpack(endian + "I", block_type_raw)[0]
            total_len = struct.unpack(endian + "I", length_raw)[0]
            if total_len < 12 or total_len % 4:
                self.warnings.append(f"invalid pcapng block length {total_len}")
                return
            body = handle.read(total_len - 12)
            if len(body) < total_len - 12 or len(handle.read(4)) < 4:
                self.warnings.append("truncated pcapng block body")
                return
            if block_type == NG_IDB:
                if len(body) < NG_IDB_MIN_BODY:
                    self.warnings.append("truncated pcapng interface description block")
                    interfaces.append(None)
                    continue
                interface = _interface(body, endian)
                interfaces.append(interface)
                if self.linktype is None:
                    self.linktype = interface.linktype
            elif block_type == NG_EPB:
                record = self._enhanced(body, endian, interfaces)
                if record is not None:
                    yield record
            elif block_type == NG_SPB:
                record = self._simple(body, endian, interfaces)
                if record is not None:
                    yield record

    def _enhanced(
        self, body: bytes, endian: str, interfaces: list[_Interface | None]
    ) -> _Record | None:
        if len(body) < 20:
            self.warnings.append("truncated pcapng enhanced packet block")
            return None
        iface_id, ts_high, ts_low, cap_len, orig_len = struct.unpack_from(endian + "IIIII", body, 0)
        if iface_id >= len(interfaces):
            self.warnings.append(f"pcapng packet references undefined interface {iface_id}")
            return None
        interface = interfaces[iface_id]
        if interface is None:
            self.warnings.append(f"pcapng packet references unusable interface {iface_id}")
            return None
        data = body[20 : 20 + cap_len]
        if len(data) < cap_len:
            self.warnings.append(f"pcapng packet declares {cap_len} bytes, {len(data)} present")
        timestamp = ((ts_high << 32) | ts_low) / interface.divisor
        return _Record(timestamp, interface.linktype, data, orig_len, cap_len)

    def _simple(
        self, body: bytes, endian: str, interfaces: list[_Interface | None]
    ) -> _Record | None:
        interface = interfaces[0] if interfaces else None
        if len(body) < 4 or interface is None:
            self.warnings.append("pcapng simple packet block without a usable interface")
            return None
        orig_len = struct.unpack_from(endian + "I", body, 0)[0]
        captured = min(orig_len, interface.snaplen, len(body) - 4)
        return _Record(0.0, interface.linktype, body[4 : 4 + captured], orig_len, captured)
