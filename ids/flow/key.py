from __future__ import annotations

import hashlib
from dataclasses import dataclass
from ipaddress import IPv4Address

from ..model import Endpoint, PacketEvent, TcpInfo, UdpInfo


@dataclass(frozen=True, slots=True)
class FlowKey:
    """Direction-free identity of a flow: (ip, port) endpoints sorted numerically."""

    proto: str
    lo_ip: int
    lo_port: int
    hi_ip: int
    hi_port: int


def _ip_int(value: object) -> int | None:
    if not isinstance(value, str):
        return None
    try:
        return int(IPv4Address(value))
    except ValueError:
        return None


def _port(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 65535:
        return None
    return value


def _prefer(normalized: object, raw: object) -> object:
    return raw if normalized is None else normalized


def make_key(event: PacketEvent) -> tuple[FlowKey, Endpoint, Endpoint] | None:
    """Return (key, source endpoint, destination endpoint), or None without a usable 5-tuple.

    Normalized addresses and ports win over the raw ones field by field.
    """
    transport = event.transport
    if isinstance(transport, TcpInfo):
        proto = "TCP"
    elif isinstance(transport, UdpInfo):
        proto = "UDP"
    else:
        return None
    src_ip: object = event.network.src_ip if event.network is not None else None
    dst_ip: object = event.network.dst_ip if event.network is not None else None
    src_port: object = transport.src_port
    dst_port: object = transport.dst_port
    normalized = event.normalized
    if normalized is not None:
        src_ip = _prefer(normalized.src_ip, src_ip)
        dst_ip = _prefer(normalized.dst_ip, dst_ip)
        src_port = _prefer(normalized.src_port, src_port)
        dst_port = _prefer(normalized.dst_port, dst_port)
    src_int = _ip_int(src_ip)
    dst_int = _ip_int(dst_ip)
    sport = _port(src_port)
    dport = _port(dst_port)
    if src_int is None or dst_int is None or sport is None or dport is None:
        return None
    if (src_int, sport) <= (dst_int, dport):
        key = FlowKey(proto, src_int, sport, dst_int, dport)
    else:
        key = FlowKey(proto, dst_int, dport, src_int, sport)
    # _ip_int succeeded, so both addresses are canonical dotted-quad strings.
    return key, Endpoint(str(src_ip), sport), Endpoint(str(dst_ip), dport)


def flow_id(key: FlowKey, start_time: float) -> str:
    """First 16 hex chars of sha1 over the key and the start time in microseconds."""
    text = (
        f"{key.proto}|{IPv4Address(key.lo_ip)}:{key.lo_port}"
        f"|{IPv4Address(key.hi_ip)}:{key.hi_port}|{round(start_time * 1e6)}"
    )
    return hashlib.sha1(text.encode("ascii")).hexdigest()[:16]
