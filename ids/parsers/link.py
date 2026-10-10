from __future__ import annotations

from dataclasses import dataclass

from ..capture.base import (
    DLT_EN10MB,
    DLT_IPV4,
    DLT_IPV6,
    DLT_LINUX_SLL,
    DLT_LINUX_SLL2,
    DLT_LOOP,
    DLT_NULL,
    DLT_RAW,
    DLT_RAW_BSD,
)
from ..issues import ParseError
from ..model import LinkInfo, LlcHeader, SnapHeader, VlanTag

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD

ETHERTYPES = {
    ETHERTYPE_IPV4: "IPv4",
    0x0806: "ARP",
    ETHERTYPE_IPV6: "IPv6",
    0x8100: "VLAN",
    0x8847: "MPLS",
    0x8848: "MPLS-MC",
    0x8863: "PPPoE-Discovery",
    0x8864: "PPPoE-Session",
    0x88A8: "QinQ",
    0x88CC: "LLDP",
    0x9100: "QinQ",
}

VLAN_TPIDS = frozenset((0x8100, 0x88A8, 0x9100))
MAX_VLAN_TAGS = 3
MAX_8023_LENGTH = 1500

_AF_INET = frozenset((2,))
_AF_INET6 = frozenset((10, 23, 24, 28, 30))


@dataclass(frozen=True, slots=True)
class LinkResult:
    info: LinkInfo
    payload: bytes
    network_protocol: str | None


def mac_str(raw: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in raw)


def ethertype_name(value: int) -> str:
    return ETHERTYPES.get(value, f"0x{value:04x}")


def _truncated(message: str, declared: int, captured: int) -> ParseError:
    return ParseError("truncated_packet", message, declared=declared, captured=captured)


def _llc(info: LinkInfo, data: bytes, offset: int) -> tuple[int, int]:
    if len(data) < offset + 3:
        raise _truncated("802.3 LLC header truncated", offset + 3, len(data))
    dsap, ssap = data[offset], data[offset + 1]
    info.llc = LlcHeader(dsap=f"0x{dsap:02x}", ssap=f"0x{ssap:02x}", control=data[offset + 2])
    offset += 3
    if dsap != 0xAA or ssap != 0xAA:
        return 0, offset
    if len(data) < offset + 5:
        raise _truncated("SNAP header truncated", offset + 5, len(data))
    oui = data[offset : offset + 3]
    protocol = int.from_bytes(data[offset + 3 : offset + 5], "big")
    info.snap = SnapHeader(oui=oui.hex(), protocol=protocol)
    return (protocol if oui == b"\x00\x00\x00" else 0), offset + 5


def _ethernet(data: bytes) -> LinkResult:
    if len(data) < 14:
        raise _truncated("ethernet frame shorter than 14 bytes", 14, len(data))
    info = LinkInfo(protocol="Ethernet", dst_mac=mac_str(data[0:6]), src_mac=mac_str(data[6:12]))
    ethertype = int.from_bytes(data[12:14], "big")
    offset = 14
    while ethertype in VLAN_TPIDS:
        if len(info.vlan) >= MAX_VLAN_TAGS:
            raise ParseError(
                "malformed_header",
                f"more than {MAX_VLAN_TAGS} stacked VLAN tags",
                limit=MAX_VLAN_TAGS,
            )
        if len(data) < offset + 4:
            raise _truncated("VLAN tag truncated", offset + 4, len(data))
        tci = int.from_bytes(data[offset : offset + 2], "big")
        info.vlan.append(
            VlanTag(
                tpid=f"0x{ethertype:04x}",
                pcp=(tci >> 13) & 0x07,
                dei=bool(tci & 0x1000),
                vid=tci & 0x0FFF,
            )
        )
        ethertype = int.from_bytes(data[offset + 2 : offset + 4], "big")
        offset += 4
    if ethertype <= MAX_8023_LENGTH:
        info.length_field = ethertype
        ethertype, offset = _llc(info, data, offset)
    info.ethertype = ethertype
    info.ethertype_name = ethertype_name(ethertype)
    return LinkResult(info, data[offset:], ETHERTYPES.get(ethertype))


def _null(data: bytes, big_endian: bool, protocol: str) -> LinkResult:
    if len(data) < 4:
        raise _truncated(f"{protocol} header truncated", 4, len(data))
    family = int.from_bytes(data[0:4], "big" if big_endian else "little")
    info = LinkInfo(protocol=protocol, address_family=family)
    if family in _AF_INET:
        info.ethertype, info.ethertype_name = ETHERTYPE_IPV4, "IPv4"
        return LinkResult(info, data[4:], "IPv4")
    if family in _AF_INET6:
        info.ethertype, info.ethertype_name = ETHERTYPE_IPV6, "IPv6"
        return LinkResult(info, data[4:], "IPv6")
    info.ethertype_name = f"AF_{family}"
    return LinkResult(info, data[4:], None)


def _sll(data: bytes) -> LinkResult:
    if len(data) < 16:
        raise _truncated("linux cooked header truncated", 16, len(data))
    addr_len = int.from_bytes(data[4:6], "big")
    ethertype = int.from_bytes(data[14:16], "big")
    info = LinkInfo(
        protocol="LINUX_SLL",
        packet_type=int.from_bytes(data[0:2], "big"),
        address_type=int.from_bytes(data[2:4], "big"),
        address=mac_str(data[6 : 6 + min(addr_len, 8)]),
        ethertype=ethertype,
        ethertype_name=ethertype_name(ethertype),
    )
    return LinkResult(info, data[16:], ETHERTYPES.get(ethertype))


def _sll2(data: bytes) -> LinkResult:
    if len(data) < 20:
        raise _truncated("linux cooked v2 header truncated", 20, len(data))
    ethertype = int.from_bytes(data[0:2], "big")
    info = LinkInfo(
        protocol="LINUX_SLL2",
        ethertype=ethertype,
        ethertype_name=ethertype_name(ethertype),
        interface_index=int.from_bytes(data[4:8], "big"),
        address_type=int.from_bytes(data[8:10], "big"),
        packet_type=data[10],
        address=mac_str(data[12 : 12 + min(data[11], 8)]),
    )
    return LinkResult(info, data[20:], ETHERTYPES.get(ethertype))


def _ip_only(protocol: str, data: bytes, version: int) -> LinkResult:
    if version == 4:
        info = LinkInfo(protocol=protocol, ethertype=ETHERTYPE_IPV4, ethertype_name="IPv4")
        return LinkResult(info, data, "IPv4")
    info = LinkInfo(protocol=protocol, ethertype=ETHERTYPE_IPV6, ethertype_name="IPv6")
    return LinkResult(info, data, "IPv6")


def _raw_ip(data: bytes) -> LinkResult:
    if not data:
        raise ParseError("truncated_packet", "empty raw IP payload", captured=0)
    version = data[0] >> 4
    if version not in (4, 6):
        raise ParseError(
            "malformed_header",
            f"raw link payload starts with IP version {version}",
            version=version,
        )
    return _ip_only("RAW", data, version)


def parse_link(data: bytes, linktype: int) -> LinkResult:
    if linktype == DLT_EN10MB:
        return _ethernet(data)
    if linktype in (DLT_RAW, DLT_RAW_BSD):
        return _raw_ip(data)
    if linktype == DLT_NULL:
        return _null(data, False, "NULL")
    if linktype == DLT_LOOP:
        return _null(data, True, "LOOP")
    if linktype == DLT_IPV4:
        return _ip_only("IPV4", data, 4)
    if linktype == DLT_IPV6:
        return _ip_only("IPV6", data, 6)
    if linktype == DLT_LINUX_SLL:
        return _sll(data)
    if linktype == DLT_LINUX_SLL2:
        return _sll2(data)
    raise ParseError("unsupported_protocol", "link layer type is not supported", linktype=linktype)
