from __future__ import annotations

from collections import namedtuple
from typing import Iterable

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
from ..errors import MalformedHeaderError, TruncatedPacketError, UnsupportedProtocolError

ETHERTYPES = {
    0x0800: "IPv4",
    0x0806: "ARP",
    0x86DD: "IPv6",
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

LinkParse = namedtuple("LinkParse", "info payload network_protocol")

_AF_INET = frozenset((2,))
_AF_INET6 = frozenset((10, 23, 24, 28, 30))


def mac_str(raw: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in raw)


def ethertype_name(value: int) -> str:
    return ETHERTYPES.get(value, f"0x{value:04x}")


def _llc(labels: dict, data: bytes, offset: int) -> tuple[int, int]:
    if len(data) < offset + 3:
        raise TruncatedPacketError(
            "802.3 LLC header truncated", stage="link", declared=offset + 3, captured=len(data)
        )
    dsap, ssap = data[offset], data[offset + 1]
    labels["llc"] = {"dsap": f"0x{dsap:02x}", "ssap": f"0x{ssap:02x}", "control": data[offset + 2]}
    offset += 3
    if dsap == 0xAA and ssap == 0xAA:
        if len(data) < offset + 5:
            raise TruncatedPacketError(
                "SNAP header truncated", stage="link", declared=offset + 5, captured=len(data)
            )
        oui = data[offset : offset + 3]
        protocol = int.from_bytes(data[offset + 3 : offset + 5], "big")
        labels["snap"] = {"oui": oui.hex(), "protocol": protocol}
        offset += 5
        return (protocol if oui == b"\x00\x00\x00" else 0), offset
    return 0, offset


def _ethernet(data: bytes) -> LinkParse:
    if len(data) < 14:
        raise TruncatedPacketError(
            "ethernet frame shorter than 14 bytes", stage="link", declared=14, captured=len(data)
        )
    info = {"protocol": "Ethernet", "dst_mac": mac_str(data[0:6]), "src_mac": mac_str(data[6:12])}
    ethertype = int.from_bytes(data[12:14], "big")
    offset = 14
    tags: list[dict] = []
    while ethertype in VLAN_TPIDS:
        if len(tags) >= MAX_VLAN_TAGS:
            raise MalformedHeaderError(
                "more than 3 stacked VLAN tags", stage="link", limit=MAX_VLAN_TAGS
            )
        if len(data) < offset + 4:
            raise TruncatedPacketError(
                "VLAN tag truncated", stage="link", declared=offset + 4, captured=len(data)
            )
        tci = int.from_bytes(data[offset : offset + 2], "big")
        tags.append(
            {
                "tpid": f"0x{ethertype:04x}",
                "pcp": (tci >> 13) & 0x07,
                "dei": bool(tci & 0x1000),
                "vid": tci & 0x0FFF,
            }
        )
        ethertype = int.from_bytes(data[offset + 2 : offset + 4], "big")
        offset += 4
    if tags:
        info["vlan"] = tags
    if ethertype <= 1500:
        info["length_field"] = ethertype
        ethertype, offset = _llc(info, data, offset)
    info["ethertype"] = ethertype
    info["ethertype_name"] = ethertype_name(ethertype)
    return LinkParse(info, data[offset:], ETHERTYPES.get(ethertype))


def _null(data: bytes, big_endian: bool, protocol: str) -> LinkParse:
    if len(data) < 4:
        raise TruncatedPacketError(
            f"{protocol} header truncated", stage="link", declared=4, captured=len(data)
        )
    family = int.from_bytes(data[0:4], "big" if big_endian else "little")
    info = {"protocol": protocol, "address_family": family}
    if family in _AF_INET:
        return LinkParse(info | {"ethertype": 0x0800, "ethertype_name": "IPv4"}, data[4:], "IPv4")
    if family in _AF_INET6:
        return LinkParse(info | {"ethertype": 0x86DD, "ethertype_name": "IPv6"}, data[4:], "IPv6")
    info["ethertype_name"] = f"AF_{family}"
    return LinkParse(info, data[4:], None)


def _sll(data: bytes) -> LinkParse:
    if len(data) < 16:
        raise TruncatedPacketError(
            "linux cooked header truncated", stage="link", declared=16, captured=len(data)
        )
    packet_type, arphrd, addr_len = int.from_bytes(data[0:2], "big"), int.from_bytes(data[2:4], "big"), int.from_bytes(data[4:6], "big")
    address = data[6:14][: min(addr_len, 8)]
    ethertype = int.from_bytes(data[14:16], "big")
    info = {
        "protocol": "LINUX_SLL",
        "packet_type": packet_type,
        "address_type": arphrd,
        "address": mac_str(address),
        "ethertype": ethertype,
        "ethertype_name": ethertype_name(ethertype),
    }
    return LinkParse(info, data[16:], ETHERTYPES.get(ethertype))


def _sll2(data: bytes) -> LinkParse:
    if len(data) < 20:
        raise TruncatedPacketError(
            "linux cooked v2 header truncated", stage="link", declared=20, captured=len(data)
        )
    ethertype = int.from_bytes(data[0:2], "big")
    interface_index = int.from_bytes(data[4:8], "big")
    arphrd, packet_type = int.from_bytes(data[8:10], "big"), data[10]
    addr_len = data[11]
    address = data[12:20][: min(addr_len, 8)]
    info = {
        "protocol": "LINUX_SLL2",
        "ethertype": ethertype,
        "ethertype_name": ethertype_name(ethertype),
        "interface_index": interface_index,
        "address_type": arphrd,
        "packet_type": packet_type,
        "address": mac_str(address),
    }
    return LinkParse(info, data[20:], ETHERTYPES.get(ethertype))


def _raw_ip(data: bytes) -> LinkParse:
    if not data:
        raise TruncatedPacketError("empty raw IP payload", stage="link", captured=0)
    version = data[0] >> 4
    if version == 4:
        return LinkParse({"protocol": "RAW", "ethertype": 0x0800, "ethertype_name": "IPv4"}, data, "IPv4")
    if version == 6:
        return LinkParse({"protocol": "RAW", "ethertype": 0x86DD, "ethertype_name": "IPv6"}, data, "IPv6")
    raise MalformedHeaderError(
        f"raw link payload starts with IP version {version}", stage="link", version=version
    )


def parse_link(data: bytes, linktype: int) -> LinkParse:
    if linktype == DLT_EN10MB:
        return _ethernet(data)
    if linktype in (DLT_RAW, DLT_RAW_BSD):
        return _raw_ip(data)
    if linktype == DLT_NULL:
        return _null(data, False, "NULL")
    if linktype == DLT_LOOP:
        return _null(data, True, "LOOP")
    if linktype == DLT_IPV4:
        return LinkParse({"protocol": "IPV4", "ethertype": 0x0800, "ethertype_name": "IPv4"}, data, "IPv4")
    if linktype == DLT_IPV6:
        return LinkParse({"protocol": "IPV6", "ethertype": 0x86DD, "ethertype_name": "IPv6"}, data, "IPv6")
    if linktype == DLT_LINUX_SLL:
        return _sll(data)
    if linktype == DLT_LINUX_SLL2:
        return _sll2(data)
    raise UnsupportedProtocolError(
        "link layer type is not supported", stage="link", linktype=linktype
    )


def supported_linktypes() -> Iterable[int]:
    return (
        DLT_EN10MB,
        DLT_RAW,
        DLT_RAW_BSD,
        DLT_NULL,
        DLT_LOOP,
        DLT_IPV4,
        DLT_IPV6,
        DLT_LINUX_SLL,
        DLT_LINUX_SLL2,
    )
