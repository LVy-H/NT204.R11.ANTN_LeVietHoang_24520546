from __future__ import annotations

from dataclasses import dataclass, field
from typing import ClassVar


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
    def captured_length(self) -> int:
        return len(self.data)

    @property
    def truncated(self) -> bool:
        return self.declared_capture_length is not None and self.declared_capture_length > len(
            self.data
        )


@dataclass(frozen=True, slots=True)
class Tick:
    now: float


@dataclass(slots=True)
class CaptureInfo:
    source: str | None = None
    origin: str | None = None
    linktype: int | None = None
    linktype_name: str | None = None
    captured_length: int | None = None
    original_length: int | None = None
    declared_capture_length: int | None = None
    truncated_by_capture: bool | None = None


@dataclass(slots=True)
class VlanTag:
    tpid: str | None = None
    pcp: int | None = None
    dei: bool | None = None
    vid: int | None = None


@dataclass(slots=True)
class LlcHeader:
    dsap: str | None = None
    ssap: str | None = None
    control: int | None = None


@dataclass(slots=True)
class SnapHeader:
    oui: str | None = None
    protocol: int | None = None


@dataclass(slots=True)
class LinkInfo:
    protocol: str | None = None
    src_mac: str | None = None
    dst_mac: str | None = None
    ethertype: int | None = None
    ethertype_name: str | None = None
    vlan: list[VlanTag] = field(default_factory=list)
    length_field: int | None = None
    llc: LlcHeader | None = None
    snap: SnapHeader | None = None
    address_family: int | None = None
    packet_type: int | None = None
    address_type: int | None = None
    address: str | None = None
    interface_index: int | None = None


@dataclass(slots=True)
class IpOption:
    type: int | None = None
    name: str | None = None
    length: int | None = None
    data: str | None = None  # hex
    malformed: bool | None = None
    declared_length: int | None = None
    available: int | None = None


@dataclass(slots=True)
class Ipv4Flags:
    reserved: bool | None = None
    df: bool | None = None
    mf: bool | None = None


@dataclass(slots=True)
class Ipv4Info:
    protocol: str | None = None  # "IPv4" when produced by the parser
    version: int | None = None
    header_length: int | None = None
    dscp: int | None = None
    ecn: int | None = None
    tos: int | None = None
    total_length: int | None = None
    identification: int | None = None
    flags: Ipv4Flags | None = None
    fragment_offset: int | None = None
    fragmented: bool | None = None
    ttl: int | None = None
    protocol_number: int | None = None
    protocol_name: str | None = None
    header_checksum: str | None = None
    header_checksum_valid: bool | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    options: list[IpOption] = field(default_factory=list)
    captured_truncated: bool | None = None
    declared_payload_length: int | None = None
    captured_payload_length: int | None = None


@dataclass(slots=True)
class TcpFlags:
    fin: bool | None = None
    syn: bool | None = None
    rst: bool | None = None
    psh: bool | None = None
    ack: bool | None = None
    urg: bool | None = None
    ece: bool | None = None
    cwr: bool | None = None
    ns: bool | None = None


@dataclass(slots=True)
class TcpOption:
    type: int | None = None
    name: str | None = None
    length: int | None = None
    malformed: bool | None = None
    declared_length: int | None = None
    available: int | None = None
    mss: int | None = None
    shift: int | None = None
    tsval: int | None = None
    tsecr: int | None = None
    blocks: list[list[int]] = field(default_factory=list)
    data: str | None = None  # hex


@dataclass(slots=True)
class TcpInfo:
    TAG: ClassVar[tuple[str, str]] = ("protocol", "TCP")
    protocol: str | None = "TCP"
    src_port: int | None = None
    dst_port: int | None = None
    seq: int | None = None
    ack: int | None = None
    header_length: int | None = None
    reserved: int | None = None
    flags: TcpFlags | None = None
    flags_list: list[str] = field(default_factory=list)
    flags_string: str | None = None
    window: int | None = None
    checksum: str | None = None
    checksum_valid: bool | None = None
    urgent_pointer: int | None = None
    options: list[TcpOption] = field(default_factory=list)
    payload_length: int | None = None


@dataclass(slots=True)
class UdpInfo:
    TAG: ClassVar[tuple[str, str]] = ("protocol", "UDP")
    protocol: str | None = "UDP"
    src_port: int | None = None
    dst_port: int | None = None
    length: int | None = None
    checksum: str | None = None
    checksum_valid: bool | None = None
    declared_payload_length: int | None = None
    payload_length: int | None = None
    captured_truncated: bool | None = None


@dataclass(slots=True)
class Payload:
    length: int | None = None  # full captured L7 length
    sha256: str | None = None  # of the full captured L7 bytes
    data: bytes | None = None  # first `max_payload_bytes` bytes
    data_truncated: bool | None = None
    preview: str | None = None
    preview_truncated: bool | None = None
    preview_encoding: str | None = None  # "utf-8" | "latin-1" | "binary"
    binary: bool | None = None
    preview_hex: str | None = None
