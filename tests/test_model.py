from __future__ import annotations

import pytest

from ids.model import (
    UNKNOWN,
    ApplicationInfo,
    DecodedHttp,
    DecodedMime,
    DecodeStatus,
    DnsMessage,
    FlowRecord,
    HttpHeader,
    HttpMessage,
    Ipv4Info,
    MessageEvent,
    PacketEvent,
    Payload,
    RawPacket,
    SmtpSession,
    TcpInfo,
    UdpInfo,
    worst_status,
)

NETWORK = Ipv4Info(protocol="IPv4", src_ip="10.0.0.1", dst_ip="10.0.0.2")


def event(**fields) -> PacketEvent:
    return PacketEvent(packet_id=1, timestamp=1759000000.0, network=NETWORK, **fields)


@pytest.mark.parametrize(
    ("packet", "expected"),
    [
        (PacketEvent(packet_id=1), "unparsed"),
        (event(), "network_only"),
        (
            event(
                transport=TcpInfo(src_port=51234, dst_port=80),
                application=ApplicationInfo("HTTP", None, HttpMessage(kind="request")),
            ),
            "http_request",
        ),
        (
            event(
                transport=UdpInfo(src_port=53, dst_port=40000),
                application=ApplicationInfo("DNS", None, DnsMessage(kind="response")),
            ),
            "dns_response",
        ),
        (
            event(
                transport=TcpInfo(src_port=40000, dst_port=25),
                application=ApplicationInfo("SMTP", None, SmtpSession(kind="data")),
            ),
            "smtp_data",
        ),
        (
            event(transport=TcpInfo(), application=ApplicationInfo("HTTP", None, None)),
            "http_unparsed",
        ),
        (
            event(transport=TcpInfo(), application=ApplicationInfo("SMTP", None, SmtpSession())),
            "smtp_unparsed",
        ),
        (
            event(
                transport=TcpInfo(),
                application=ApplicationInfo(UNKNOWN, None, None),
                payload=Payload(length=12),
            ),
            "unknown_payload",
        ),
        (event(transport=TcpInfo(), payload=Payload(length=0)), "tcp_segment"),
        (event(transport=UdpInfo(), payload=None), "udp_segment"),
        (event(transport=TcpInfo(protocol=None)), "transport_segment"),
    ],
)
def test_event_type_covers_every_branch(packet, expected):
    assert packet.event_type == expected


def test_missing_network_is_unparsed_even_with_upper_layers():
    packet = PacketEvent(transport=TcpInfo(), application=ApplicationInfo("HTTP"))
    assert packet.event_type == "unparsed"


@pytest.mark.parametrize(
    "application",
    [None, ApplicationInfo(protocol=None), ApplicationInfo(protocol="")],
)
def test_application_protocol_falls_back_to_unknown(application):
    assert PacketEvent(application=application).application_protocol == UNKNOWN


def test_application_protocol_reports_the_detected_name():
    assert PacketEvent(application=ApplicationInfo("DNS")).application_protocol == "DNS"


def test_convenience_properties_read_the_nested_blocks():
    packet = event(transport=TcpInfo(src_port=51234, dst_port=80))
    assert (packet.src_ip, packet.dst_ip, packet.src_port, packet.dst_port) == (
        "10.0.0.1",
        "10.0.0.2",
        51234,
        80,
    )
    assert packet.protocol == "TCP"
    assert packet.is_tcp is True


def test_convenience_properties_are_none_without_blocks():
    packet = PacketEvent()
    assert (packet.src_ip, packet.dst_ip, packet.src_port, packet.dst_port) == (
        None,
        None,
        None,
        None,
    )
    assert packet.protocol is None
    assert packet.is_tcp is False


def test_udp_transport_is_not_tcp():
    packet = event(transport=UdpInfo(src_port=1, dst_port=2))
    assert packet.protocol == "UDP"
    assert packet.is_tcp is False


def test_union_tag_fields_default_to_their_tag():
    assert TcpInfo().protocol == "TCP"
    assert UdpInfo().protocol == "UDP"
    assert HttpMessage().protocol == "HTTP"
    assert DnsMessage().protocol == "DNS"
    assert SmtpSession().protocol == "SMTP"
    assert DecodedHttp().kind == "http"
    assert DecodedMime().kind == "mime"
    assert (PacketEvent.RECORD_TYPE, MessageEvent.RECORD_TYPE, FlowRecord.RECORD_TYPE) == (
        "packet",
        "message",
        "flow",
    )


def test_mutable_defaults_are_not_shared():
    first, second = PacketEvent(), PacketEvent()
    first.reason.append("x")
    first.issues.append(None)
    assert second.reason == []
    assert second.issues == []
    flow_a, flow_b = FlowRecord(), FlowRecord()
    flow_a.forward.packet_count += 1
    assert flow_b.forward.packet_count == 0
    assert flow_a.backward is not flow_a.forward


def http(*headers: tuple[str | None, str | None]) -> HttpMessage:
    return HttpMessage(headers=[HttpHeader(name, value) for name, value in headers])


def test_header_lookup_is_case_insensitive_and_last_value_wins():
    message = http(("Host", "a.example"), ("X-Tag", "1"), ("HOST", "b.example"))
    assert message.header("host") == "b.example"
    assert message.header("HoSt") == "b.example"
    assert message.header_values("host") == ["a.example", "b.example"]


def test_header_lookup_misses_return_none_and_empty_list():
    message = http(("Host", "a.example"))
    assert message.header("cookie") is None
    assert message.header_values("cookie") == []


def test_header_lookup_skips_entries_with_missing_name_or_value():
    message = http((None, "x"), ("Host", None), ("Host", "kept"))
    assert message.header_values("host") == ["kept"]
    assert message.header("host") == "kept"


def test_header_lookup_keeps_original_order_and_case_of_values():
    message = http(("Set-Cookie", "A=1"), ("set-cookie", "b=2"))
    assert message.header_values("SET-COOKIE") == ["A=1", "b=2"]


def test_worst_status_of_nothing_is_not_applicable():
    assert worst_status([]) is DecodeStatus.NOT_APPLICABLE
    assert worst_status([None, None]) is DecodeStatus.NOT_APPLICABLE


@pytest.mark.parametrize(
    ("statuses", "expected"),
    [
        ([DecodeStatus.NOT_APPLICABLE, DecodeStatus.UNCHANGED], DecodeStatus.UNCHANGED),
        ([DecodeStatus.DECODED, DecodeStatus.UNCHANGED], DecodeStatus.DECODED),
        ([DecodeStatus.DECODED, DecodeStatus.PARTIAL], DecodeStatus.PARTIAL),
        ([DecodeStatus.FAILED, DecodeStatus.PARTIAL], DecodeStatus.FAILED),
        ([None, DecodeStatus.UNCHANGED, None], DecodeStatus.UNCHANGED),
        (
            [DecodeStatus.PARTIAL, DecodeStatus.FAILED, DecodeStatus.DECODED],
            DecodeStatus.FAILED,
        ),
    ],
)
def test_worst_status_picks_the_most_severe(statuses, expected):
    assert worst_status(statuses) is expected


def test_worst_status_accepts_a_generator():
    parts = [DecodeStatus.DECODED, DecodeStatus.PARTIAL]
    assert worst_status(status for status in parts) is DecodeStatus.PARTIAL


def raw(data: bytes, declared: int | None) -> RawPacket:
    return RawPacket(1, 0.0, data, 1, "pcap", "x.pcap", 60, declared)


def test_raw_packet_captured_length_is_the_data_length():
    assert raw(b"\x00" * 42, 42).captured_length == 42


@pytest.mark.parametrize(
    ("declared", "truncated"),
    [(None, False), (41, False), (42, False), (43, True)],
)
def test_raw_packet_is_truncated_only_when_declared_exceeds_data(declared, truncated):
    assert raw(b"\x00" * 42, declared).truncated is truncated
