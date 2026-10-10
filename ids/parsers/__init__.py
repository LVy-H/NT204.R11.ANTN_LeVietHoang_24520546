from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, TypeVar

from ..capture.base import linktype_name
from ..issues import Issues
from ..model import (
    UNKNOWN,
    ApplicationInfo,
    CaptureInfo,
    DnsMessage,
    HttpMessage,
    PacketEvent,
    RawPacket,
    SmtpSession,
    TcpInfo,
)
from ..payload import make_payload
from .detector import detect
from .link import parse_link
from .network import IPPROTO_TCP, IPPROTO_UDP, parse_ipv4
from .registry import by_name
from .transport import parse_transport

__all__ = ["PacketParser", "ParserConfig"]

TRANSPORT_PROTOCOLS = frozenset((IPPROTO_TCP, IPPROTO_UDP))

T = TypeVar("T")


@dataclass(slots=True)
class ParserConfig:
    max_payload_bytes: int = 65535
    preview_limit: int = 256


def _guarded(issues: Issues, function: Callable[..., T], /, *args: Any, **kwargs: Any) -> T | None:
    try:
        return function(*args, **kwargs)
    except Exception as error:
        issues.capture(error)
        return None


def _capture_info(raw: RawPacket) -> CaptureInfo:
    return CaptureInfo(
        source=raw.source,
        origin=raw.origin,
        linktype=raw.linktype,
        linktype_name=linktype_name(raw.linktype),
        captured_length=raw.captured_length,
        original_length=raw.original_length,
        declared_capture_length=raw.declared_capture_length,
        truncated_by_capture=raw.truncated,
    )


def _parse_application(
    protocol: str, payload: bytes, tcp: bool, issues: Issues
) -> HttpMessage | DnsMessage | SmtpSession:
    application = by_name(protocol)
    if application is None:
        raise LookupError(f"no application parser registered for {protocol}")
    return application.parse(payload, tcp=tcp, issues=issues)


def _layers(raw: RawPacket, event: PacketEvent, issues: Issues) -> bytes:
    """Parse as deep as possible into `event`; return the deepest bytes reached."""
    link = _guarded(issues.scoped("link"), parse_link, raw.data, raw.linktype)
    if link is None:
        return raw.data
    event.link = link.info
    if link.network_protocol != "IPv4":
        return link.payload

    network_issues = issues.scoped("network")
    network = _guarded(network_issues, parse_ipv4, link.payload, network_issues)
    if network is None:
        return link.payload
    ip = network.info
    event.network = ip
    if ip.protocol_number not in TRANSPORT_PROTOCOLS:
        return network.payload

    transport = _guarded(
        issues.scoped("transport"),
        parse_transport,
        ip.protocol_number,
        network.payload,
        src_ip=ip.src_ip,
        dst_ip=ip.dst_ip,
        declared_length=ip.declared_payload_length,
        fragment_offset=ip.fragment_offset or 0,
    )
    if transport is None:
        return network.payload
    segment = transport.info
    event.transport = segment
    payload = transport.payload
    tcp = isinstance(segment, TcpInfo)

    detection = _guarded(
        issues.scoped("detect"),
        detect,
        payload,
        src_port=segment.src_port,
        dst_port=segment.dst_port,
        tcp=tcp,
    )
    protocol = detection.protocol if detection is not None and detection.protocol else UNKNOWN
    message = None
    if protocol != UNKNOWN and payload:
        application_issues = issues.scoped("application")
        message = _guarded(
            application_issues, _parse_application, protocol, payload, tcp, application_issues
        )
    event.application = ApplicationInfo(protocol=protocol, detection=detection, message=message)
    return payload


class PacketParser:
    __slots__ = ("config",)

    def __init__(self, config: ParserConfig | None = None) -> None:
        self.config = config if config is not None else ParserConfig()

    def parse(self, raw: RawPacket) -> PacketEvent:
        try:
            return self._parse(raw)
        except Exception as error:
            issues = Issues("pipeline")
            issues.capture(error)
            return PacketEvent(
                packet_id=raw.packet_id,
                timestamp=raw.timestamp,
                capture=_capture_info(raw),
                issues=issues.records,
            )

    def _parse(self, raw: RawPacket) -> PacketEvent:
        issues = Issues("capture")
        if raw.truncated:
            issues.add(
                "truncated_packet",
                "the capture file holds fewer bytes than the record declares",
                declared=raw.declared_capture_length,
                captured=raw.captured_length,
            )
        event = PacketEvent(
            packet_id=raw.packet_id,
            timestamp=raw.timestamp,
            capture=_capture_info(raw),
            issues=issues.records,
        )
        deepest = _layers(raw, event, issues)
        config = self.config
        event.payload = make_payload(
            deepest, max_bytes=config.max_payload_bytes, preview_limit=config.preview_limit
        )
        return event
