"""Hand-built PacketEvents for the flow tracker unit tests."""

from __future__ import annotations

from ids.flow.table import FlowTable
from ids.model import (
    ApplicationInfo,
    Detection,
    Ipv4Info,
    PacketEvent,
    Payload,
    SmtpSession,
    TcpFlags,
    TcpInfo,
    UdpInfo,
)

T0 = 1759000000.0
CLIENT = ("10.0.0.1", 40000)
SERVER = ("10.0.0.2", 80)


def flags(spec: str) -> TcpFlags:
    """'S' syn, 'A' ack, 'F' fin, 'R' rst, 'P' psh; e.g. flags('SA') is a SYN-ACK."""
    return TcpFlags(
        fin="F" in spec, syn="S" in spec, rst="R" in spec, psh="P" in spec, ack="A" in spec
    )


def app(protocol: str, method: str, confidence: float, message=None) -> ApplicationInfo:
    return ApplicationInfo(
        protocol=protocol,
        detection=Detection(protocol=protocol, method=method, confidence=confidence),
        message=message,
    )


def smtp_app(message: SmtpSession | None = None) -> ApplicationInfo:
    return app("SMTP", "port+payload", 1.0, message)


def tcp_event(
    packet_id: int,
    timestamp: float,
    src: tuple[str, int],
    dst: tuple[str, int],
    spec: str = "A",
    *,
    seq: int | None = 0,
    ack: int | None = 0,
    payload: bytes = b"",
    application: ApplicationInfo | None = None,
) -> PacketEvent:
    return PacketEvent(
        packet_id=packet_id,
        timestamp=timestamp,
        network=Ipv4Info(
            protocol="IPv4", src_ip=src[0], dst_ip=dst[0], total_length=40 + len(payload)
        ),
        transport=TcpInfo(
            src_port=src[1],
            dst_port=dst[1],
            seq=seq,
            ack=ack,
            flags=flags(spec),
            payload_length=len(payload),
        ),
        application=application,
        payload=Payload(length=len(payload), data=payload),
    )


def udp_event(
    packet_id: int,
    timestamp: float,
    src: tuple[str, int],
    dst: tuple[str, int],
    *,
    payload: bytes = b"",
    application: ApplicationInfo | None = None,
) -> PacketEvent:
    return PacketEvent(
        packet_id=packet_id,
        timestamp=timestamp,
        network=Ipv4Info(
            protocol="IPv4", src_ip=src[0], dst_ip=dst[0], total_length=28 + len(payload)
        ),
        transport=UdpInfo(
            src_port=src[1], dst_port=dst[1], length=8 + len(payload), payload_length=len(payload)
        ),
        application=application,
        payload=Payload(length=len(payload), data=payload),
    )


def make_table(**overrides) -> FlowTable:
    config = {
        "tcp_idle_timeout": 300.0,
        "udp_idle_timeout": 60.0,
        "tcp_closed_timeout": 5.0,
        "max_flows": 100,
        "max_message_bytes": 1_048_576,
    }
    config.update(overrides)
    return FlowTable(**config)
