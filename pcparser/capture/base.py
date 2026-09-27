from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator, Protocol, runtime_checkable

DLT_NULL = 0
DLT_EN10MB = 1
DLT_RAW_BSD = 12
DLT_RAW = 101
DLT_IEEE802_11 = 105
DLT_LOOP = 108
DLT_LINUX_SLL = 113
DLT_IPV4 = 228
DLT_IPV6 = 229
DLT_LINUX_SLL2 = 276

LINKTYPE_NAMES = {
    DLT_NULL: "NULL",
    DLT_EN10MB: "EN10MB",
    DLT_RAW_BSD: "RAW",
    DLT_RAW: "RAW",
    DLT_IEEE802_11: "IEEE802_11",
    DLT_LOOP: "LOOP",
    DLT_LINUX_SLL: "LINUX_SLL",
    DLT_IPV4: "IPV4",
    DLT_IPV6: "IPV6",
    DLT_LINUX_SLL2: "LINUX_SLL2",
}


def linktype_name(linktype):
    if linktype is None:
        return None
    return LINKTYPE_NAMES.get(linktype, f"UNKNOWN({linktype})")


@dataclass(frozen=True, slots=True)
class RawPacket:
    packet_id: int
    timestamp: float
    data: bytes
    linktype: int
    source: str
    origin: str
    original_length: int | None = None
    declared_capture_length: int | None = None

    @property
    def captured_length(self):
        return len(self.data)

    @property
    def truncated(self):
        return self.declared_capture_length is not None and self.declared_capture_length > len(self.data)


@runtime_checkable
class CaptureSource(Protocol):
    source: str
    origin: str
    linktype: int

    def packets(self) -> Iterator[RawPacket]: ...

    def describe(self) -> dict: ...

    def close(self) -> None: ...
