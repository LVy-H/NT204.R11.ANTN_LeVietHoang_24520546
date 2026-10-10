from __future__ import annotations

import json
from pathlib import Path

import pytest

from ids.capture import EventsSource
from ids.issues import Issue
from ids.model import (
    DecodedForm,
    DecodedHttp,
    DecodedMime,
    DecodedText,
    DecodedUri,
    DecodeStatus,
    Ipv4Info,
    LinkInfo,
    PacketEvent,
    PreprocessStatus,
    TcpInfo,
    UdpInfo,
)
from ids.preprocess.normalize import normalize
from ids.preprocess.validate import validate

NOW = 1759000100.0
VALID, PARTIAL, INVALID = PreprocessStatus.VALID, PreprocessStatus.PARTIAL, PreprocessStatus.INVALID


def event(**overrides: object) -> PacketEvent:
    fields: dict[str, object] = {
        "packet_id": 1,
        "timestamp": 1759000000.0,
        "network": Ipv4Info(src_ip="10.0.0.1", dst_ip="10.0.0.2"),
        "transport": TcpInfo(src_port=40000, dst_port=80),
    }
    fields.update(overrides)
    return PacketEvent(**fields)


def check(record: PacketEvent) -> tuple[PreprocessStatus, list[str], bool]:
    return validate(record, normalize(record)[0], now=NOW)


def test_t06_minimal_flat_event_without_optional_fields_is_valid():
    assert check(event()) == (VALID, [], False)


def test_udp_is_supported():
    assert check(event(transport=UdpInfo(src_port=5353, dst_port=53))) == (VALID, [], False)


@pytest.mark.parametrize(
    ("packet_id", "reason"),
    [
        (None, "missing_field:packet_id"),
        (0, "invalid_field:packet_id"),
        (-3, "invalid_field:packet_id"),
        (True, "invalid_field:packet_id"),
        ("7", "invalid_field:packet_id"),
    ],
)
def test_packet_id_must_be_a_positive_int(packet_id, reason):
    assert check(event(packet_id=packet_id)) == (INVALID, [reason], False)


def test_packet_id_one_is_the_lower_bound():
    assert check(event(packet_id=1))[0] is VALID


def test_missing_timestamp():
    assert check(event(timestamp=None)) == (INVALID, ["missing_field:timestamp"], False)


@pytest.mark.parametrize("stamp", [0.0, -1.0, float("nan"), float("inf"), "yesterday"])
def test_timestamp_must_be_finite_and_positive(stamp):
    assert check(event(timestamp=stamp)) == (INVALID, ["invalid_timestamp"], False)


def test_timestamp_may_be_up_to_one_day_ahead_of_now():
    assert check(event(timestamp=NOW + 86400))[0] is VALID
    assert check(event(timestamp=NOW + 86400.5)) == (INVALID, ["invalid_timestamp"], False)


def test_millisecond_timestamps_are_bounded_after_scaling():
    assert check(event(timestamp=1759000000000))[0] is VALID


@pytest.mark.parametrize("field", ["src_ip", "dst_ip"])
def test_missing_ip(field):
    network = Ipv4Info(src_ip="10.0.0.1", dst_ip="10.0.0.2")
    setattr(network, field, None)
    assert check(event(network=network)) == (INVALID, [f"missing_field:{field}"], False)


def test_ip_validity_uses_the_normalized_value():
    padded = event(network=Ipv4Info(src_ip="010.000.000.001", dst_ip="10.0.0.2"))
    assert check(padded) == (VALID, [], False)
    broken = event(network=Ipv4Info(src_ip="10.0.0.1", dst_ip="10.0.0.300"))
    assert check(broken) == (INVALID, ["invalid_ip:dst_ip"], False)


def test_transport_without_network_reports_both_ips_missing():
    assert check(event(network=None)) == (
        INVALID,
        ["missing_field:src_ip", "missing_field:dst_ip"],
        False,
    )


@pytest.mark.parametrize(
    ("ports", "status", "reasons"),
    [
        ((65535, 1), VALID, []),
        ((0, 80), PARTIAL, ["reserved_port:src_port"]),
        ((40000, 0), PARTIAL, ["reserved_port:dst_port"]),
        ((40000, 70000), INVALID, ["invalid_port:dst_port"]),
        ((-1, 80), INVALID, ["invalid_port:src_port"]),
        ((None, 80), INVALID, ["missing_field:src_port"]),
        ((40000, True), INVALID, ["invalid_port:dst_port"]),
    ],
)
def test_port_rules(ports, status, reasons):
    transport = TcpInfo(src_port=ports[0], dst_port=ports[1])
    assert check(event(transport=transport)) == (status, reasons, False)


def test_no_transport_layer_is_unsupported_and_named_after_the_ip_protocol():
    icmp = event(network=Ipv4Info(src_ip="10.0.0.1", dst_ip="10.0.0.2", protocol_name="ICMP"))
    icmp.transport = None
    assert check(icmp) == (PARTIAL, ["unsupported_protocol:ICMP"], True)


def test_non_first_fragment_is_unsupported_as_fragment():
    fragment = event(
        network=Ipv4Info(
            src_ip="10.0.0.1", dst_ip="10.0.0.2", protocol_name="TCP", fragment_offset=185
        ),
        transport=None,
    )
    assert check(fragment) == (PARTIAL, ["unsupported_protocol:fragment"], True)


def test_no_ipv4_layer_is_unsupported_and_named_after_the_ethertype():
    ipv6 = event(network=None, transport=None, link=LinkInfo(ethertype_name="IPv6"))
    assert check(ipv6) == (PARTIAL, ["unsupported_protocol:IPv6"], True)
    assert check(event(network=None, transport=None)) == (
        PARTIAL,
        ["unsupported_protocol:unknown"],
        True,
    )


def test_each_issue_adds_one_stage_code_reason_in_order_without_duplicates():
    issues = [
        Issue("application", "truncated_body", "x"),
        Issue("network", "truncated_packet", "y"),
        Issue("application", "truncated_body", "z"),
    ]
    assert check(event(issues=issues)) == (
        PARTIAL,
        ["application/truncated_body", "network/truncated_packet"],
        False,
    )


def test_load_issue_on_an_optional_field_is_partial():
    issue = Issue("load", "invalid_type", "bad", {"field": "network.ttl"})
    assert check(event(issues=[issue])) == (PARTIAL, ["load/invalid_type"], False)


def test_unsupported_schema_alone_is_partial():
    issue = Issue("load", "unsupported_schema", "schema_version 9")
    assert check(event(issues=[issue])) == (PARTIAL, ["load/unsupported_schema"], False)


@pytest.mark.parametrize(
    ("path", "overrides", "reason"),
    [
        ("packet_id", {"packet_id": None}, "invalid_field:packet_id"),
        ("timestamp", {"timestamp": None}, "invalid_timestamp"),
        ("network.src_ip", {"network": Ipv4Info(dst_ip="10.0.0.2")}, "invalid_ip:src_ip"),
        ("dst_ip", {"network": Ipv4Info(src_ip="10.0.0.1")}, "invalid_ip:dst_ip"),
        ("transport.src_port", {"transport": TcpInfo(dst_port=80)}, "invalid_port:src_port"),
        ("dst_port", {"transport": TcpInfo(src_port=1)}, "invalid_port:dst_port"),
    ],
)
def test_load_issue_on_a_required_field_is_invalid(path, overrides, reason):
    issue = Issue("load", "invalid_type", "wrong type", {"field": path})
    record = event(issues=[issue], **overrides)
    assert check(record) == (INVALID, [reason, "load/invalid_type"], False)


def test_load_issue_on_src_ip_without_any_layer_is_invalid():
    issue = Issue("load", "invalid_type", "wrong type", {"field": "src_ip"})
    record = event(network=None, transport=None, issues=[issue])
    assert check(record) == (
        INVALID,
        [
            "invalid_ip:src_ip",
            "missing_field:dst_ip",
            "unsupported_protocol:unknown",
            "load/invalid_type",
        ],
        True,
    )


@pytest.mark.parametrize("name", ["TCP", "udp"])
def test_ipv4_tcp_or_udp_without_a_parsed_transport_header_is_invalid_not_unsupported(name):
    broken = event(
        network=Ipv4Info(src_ip="10.0.0.1", dst_ip="10.0.0.2", protocol_name=name),
        transport=None,
        issues=[Issue("transport", "truncated_packet", "TCP header shorter than 20 bytes")],
    )
    assert check(broken) == (
        INVALID,
        ["missing_field:src_port", "missing_field:dst_port", "transport/truncated_packet"],
        False,
    )


@pytest.mark.parametrize(
    ("decoded", "reasons"),
    [
        (DecodedHttp(uri=DecodedUri(status=DecodeStatus.PARTIAL)), ["decode_partial:uri"]),
        (DecodedHttp(form=DecodedForm(status=DecodeStatus.FAILED)), ["decode_failed:form"]),
        (
            DecodedHttp(
                uri=DecodedUri(status=DecodeStatus.DECODED),
                body=DecodedText(status=DecodeStatus.PARTIAL),
            ),
            ["decode_partial:body"],
        ),
        (DecodedMime(status=DecodeStatus.FAILED), ["decode_failed:mime"]),
        (DecodedMime(status=DecodeStatus.PARTIAL), ["decode_partial:mime"]),
    ],
)
def test_partial_or_failed_decoding_marks_the_event_partial(decoded, reasons):
    assert check(event(decoded=decoded)) == (PARTIAL, reasons, False)


def test_unchanged_and_decoded_parts_add_nothing():
    decoded = DecodedHttp(
        uri=DecodedUri(status=DecodeStatus.UNCHANGED),
        body=DecodedText(status=DecodeStatus.DECODED),
        status=DecodeStatus.DECODED,
    )
    assert check(event(decoded=decoded)) == (VALID, [], False)


def test_invalid_wins_over_partial_and_reasons_follow_check_order():
    record = event(
        timestamp=None,
        transport=TcpInfo(src_port=0, dst_port=70000),
        issues=[Issue("application", "decode_error", "x")],
        decoded=DecodedHttp(uri=DecodedUri(status=DecodeStatus.PARTIAL)),
    )
    assert check(record) == (
        INVALID,
        [
            "missing_field:timestamp",
            "reserved_port:src_port",
            "invalid_port:dst_port",
            "application/decode_error",
            "decode_partial:uri",
        ],
        False,
    )


def test_review_absurd_timestamp_is_invalid_and_has_no_iso_form():
    record = event(timestamp=1e20)
    normalized = normalize(record)[0]
    assert normalized.timestamp_iso is None
    assert validate(record, normalized, now=NOW) == (INVALID, ["invalid_timestamp"], False)


MISSING = object()
FLAT = {
    "packet_id": 1,
    "timestamp": 1759000000.0,
    "src_ip": "10.0.0.1",
    "dst_ip": "10.0.0.2",
    "protocol": "TCP",
    "src_port": 40000,
    "dst_port": 80,
}


def flat(**changes: object) -> str:
    fields = {**FLAT, **changes}
    return json.dumps({key: value for key, value in fields.items() if value is not MISSING})


def load_line(tmp_path: Path, line: str) -> PacketEvent:
    path = tmp_path / "events.jsonl"
    path.write_text(line + "\n", encoding="utf-8")
    source = EventsSource(path)
    try:
        (loaded,) = list(source.items())
    finally:
        source.close()
    return loaded


@pytest.mark.parametrize(
    ("line", "status", "reasons"),
    [
        (flat(), VALID, []),
        (flat(timestamp="2025-09-27T19:06:40Z"), VALID, []),
        (
            "not json at all",
            INVALID,
            ["missing_field:timestamp", "unsupported_protocol:unknown", "load/invalid_json"],
        ),
        (flat(src_port="abc"), INVALID, ["invalid_port:src_port", "load/invalid_type"]),
        (flat(packet_id="one"), INVALID, ["invalid_field:packet_id", "load/invalid_type"]),
        (flat(timestamp="yesterday"), INVALID, ["invalid_timestamp", "load/invalid_type"]),
        (flat(dst_port=70000), INVALID, ["invalid_port:dst_port"]),
        (flat(src_ip=MISSING), INVALID, ["missing_field:src_ip"]),
        (flat(schema_version=9), PARTIAL, ["load/unsupported_schema"]),
        (flat(record_type="bogus"), PARTIAL, ["load/unsupported_schema"]),
        (
            flat(protocol=6),
            INVALID,
            ["invalid_port:src_port", "invalid_port:dst_port", "load/invalid_type"],
        ),
        (
            flat(transport="tcp"),
            INVALID,
            ["invalid_port:src_port", "invalid_port:dst_port", "load/invalid_type"],
        ),
        (
            flat(src_ip=MISSING, dst_ip=MISSING, network="10.0.0.1", protocol=MISSING),
            INVALID,
            [
                "invalid_ip:src_ip",
                "invalid_ip:dst_ip",
                "unsupported_protocol:unknown",
                "load/invalid_type",
            ],
        ),
    ],
    ids=[
        "flat-valid",
        "iso-timestamp",
        "non-json",
        "wrong-type-port",
        "wrong-type-packet-id",
        "wrong-type-timestamp",
        "port-70000",
        "missing-src-ip",
        "schema-version-9",
        "unknown-record-type",
        "wrong-type-protocol",
        "wrong-type-transport",
        "wrong-type-network",
    ],
)
def test_t14_loaded_event_shapes(tmp_path, line, status, reasons):
    loaded = load_line(tmp_path, line)
    assert validate(loaded, normalize(loaded)[0], now=NOW)[:2] == (status, reasons)


def test_transport_tag_mismatch_stays_unsupported(tmp_path):
    loaded = load_line(tmp_path, flat(transport={"protocol": "SCTP"}, protocol="SCTP"))
    status, _, unsupported = validate(loaded, normalize(loaded)[0], now=NOW)
    assert (status, unsupported) == (PARTIAL, True)
