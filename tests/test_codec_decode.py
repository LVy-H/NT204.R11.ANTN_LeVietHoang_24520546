from __future__ import annotations

import json

import pytest
from codec_samples import (
    TS,
    flow_record,
    message_event,
    rich_dns_event,
    rich_http_event,
    rich_smtp_event,
)

from ids.codec import decode_packet, encode_line, from_jsonable
from ids.issues import Issue, Issues
from ids.model import (
    DecodedMime,
    DecodeStatus,
    Direction,
    DirectionStats,
    DnsMessage,
    DnsRecord,
    FlowRecord,
    Ipv4Info,
    MessageEvent,
    PacketEvent,
    Payload,
    PreprocessStatus,
    TcpFlags,
    TcpInfo,
    TcpOption,
    UdpInfo,
)

FLAT = {
    "packet_id": 3,
    "timestamp": 1759000000.5,
    "src_ip": "10.0.0.1",
    "dst_ip": "10.0.0.2",
    "src_port": 51234,
    "dst_port": 80,
    "protocol": "tcp",
}


def load(record: dict) -> tuple[PacketEvent, list[Issue]]:
    return decode_packet(json.loads(json.dumps(record)))


def invalid_fields(issues: list[Issue]) -> list[str]:
    return [issue.context["field"] for issue in issues if issue.code == "invalid_type"]


@pytest.mark.parametrize("build", [rich_http_event, rich_dns_event, rich_smtp_event, PacketEvent])
def test_packet_round_trip_through_json(build):
    event = build()
    assert decode_packet(json.loads(encode_line(event))) == (event, [])


def test_network_only_packet_round_trip_does_not_invent_a_transport():
    event = PacketEvent(
        packet_id=2, timestamp=TS, network=Ipv4Info(src_ip="1.1.1.1", dst_ip="2.2.2.2")
    )
    assert decode_packet(json.loads(encode_line(event))) == (event, [])


def test_message_and_flow_records_round_trip_through_from_jsonable():
    issues = Issues("load")
    message = json.loads(encode_line(message_event()))
    flow = json.loads(encode_line(flow_record()))
    assert from_jsonable(MessageEvent, message, issues, "") == message_event()
    assert from_jsonable(FlowRecord, flow, issues, "") == flow_record()
    assert issues.records == []


def test_wrong_types_fall_back_to_defaults_with_dotted_paths():
    event, issues = load(
        {
            "packet_id": "7",
            "timestamp": True,
            "network": {
                "src_ip": 5,
                "ttl": True,
                "flags": {"df": "yes"},
                "options": [{"type": "x"}],
            },
            "transport": {"protocol": "TCP", "src_port": 80.0, "flags_list": ["SYN", 2]},
        }
    )
    assert invalid_fields(issues) == [
        "packet_id",
        "timestamp",
        "network.flags.df",
        "network.ttl",
        "network.src_ip",
        "network.options[0].type",
        "transport.src_port",
        "transport.flags_list[1]",
    ]
    assert event.packet_id is None
    assert event.timestamp is None
    assert event.network.src_ip is None
    assert event.network.ttl is None
    assert event.network.flags.df is None
    assert event.network.options[0].type is None
    assert event.transport.src_port is None
    assert event.transport.flags_list == ["SYN"]
    assert all(issue.stage == "load" for issue in issues)


def test_invalid_type_issue_context_names_field_expected_and_got():
    _, issues = load({"packet_id": "7"})
    assert issues == [
        Issue(
            "load",
            "invalid_type",
            "packet_id: expected int, got str",
            {"field": "packet_id", "expected": "int", "got": "str"},
        )
    ]


def test_int_is_accepted_for_float_and_converted():
    event, issues = load({"timestamp": 1759000000})
    assert issues == []
    assert event.timestamp == 1759000000.0
    assert type(event.timestamp) is float


def test_bool_is_rejected_for_int_fields():
    event, issues = load({"packet_id": True})
    assert event.packet_id is None
    assert invalid_fields(issues) == ["packet_id"]


@pytest.mark.parametrize("text", ['{"timestamp": NaN}', '{"timestamp": Infinity}'])
def test_non_finite_floats_are_rejected(text):
    event, issues = decode_packet(json.loads(text))
    assert event.timestamp is None
    assert invalid_fields(issues) == ["timestamp"]
    assert json.loads(encode_line(event))["timestamp"] is None


def test_integer_too_large_for_float_is_rejected():
    event, issues = decode_packet({"timestamp": 10**400})
    assert event.timestamp is None
    assert invalid_fields(issues) == ["timestamp"]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("2025-09-27T19:06:40.100000Z", TS),
        ("2025-09-27T19:06:40.100000+00:00", TS),
        ("2025-09-28T02:06:40.100000+07:00", TS),
        ("2025-09-27T19:06:40", 1759000000.0),
        (" 2025-09-27T19:06:40z ", 1759000000.0),
    ],
)
def test_iso_timestamp_strings_are_converted_to_epoch_seconds(text, expected):
    event, issues = decode_packet({"timestamp": text})
    assert issues == []
    assert event.timestamp == expected


def test_unparsable_timestamp_string_is_invalid():
    event, issues = decode_packet({"timestamp": "yesterday"})
    assert event.timestamp is None
    assert issues[0].context == {
        "field": "timestamp",
        "expected": "float or ISO-8601 str",
        "got": "str",
    }


def test_non_optional_fields_keep_their_default_on_null_or_wrong_type():
    issues = Issues("load")
    flow = from_jsonable(
        FlowRecord,
        {"packet_count": None, "forward": "x", "tcp": {"handshake_complete": 1}},
        issues,
        "",
    )
    assert flow.packet_count == 0
    assert flow.forward == DirectionStats()
    assert flow.tcp.handshake_complete is False
    assert invalid_fields(issues.records) == ["packet_count", "forward", "tcp.handshake_complete"]


@pytest.mark.parametrize("value", ["!!!!", "QQ", "QQ==QQ==", "QUJD\n", "ÀÀÀÀ", 12])
def test_bad_base64_is_invalid(value):
    event, issues = load({"payload": {"length": 3, "data_b64": value}})
    assert event.payload == Payload(length=3)
    assert invalid_fields(issues) == ["payload.data_b64"]


def test_null_base64_loads_as_none_without_issue():
    event, issues = load({"payload": {"data_b64": None}})
    assert event.payload.data is None
    assert issues == []


def test_unknown_enum_values_are_invalid():
    event, issues = load(
        {
            "preprocess_status": "maybe",
            "processing_action": "MARK",
            "flow": {"direction": "forward", "state": "OPEN"},
        }
    )
    assert event.preprocess_status is None
    assert event.processing_action is None
    assert event.flow.direction is Direction.FORWARD
    assert event.flow.state is None
    assert invalid_fields(issues) == ["preprocess_status", "processing_action", "flow.state"]


def test_enum_values_load_as_members():
    event, issues = load(
        {"preprocess_status": "partial", "decoded": {"kind": "mime", "status": "failed"}}
    )
    assert issues == []
    assert event.preprocess_status is PreprocessStatus.PARTIAL
    assert event.decoded == DecodedMime(status=DecodeStatus.FAILED)


def test_union_member_is_chosen_by_tag_case_insensitively():
    event, issues = load(
        {
            "network": {"src_ip": "10.0.0.1"},
            "transport": {"protocol": "udp", "src_port": 53},
            "application": {"protocol": "DNS", "message": {"protocol": "dns", "kind": "query"}},
        }
    )
    assert issues == []
    assert event.transport == UdpInfo(protocol="udp", src_port=53)
    assert event.application.message == DnsMessage(protocol="dns", kind="query")
    assert event.event_type == "dns_query"


@pytest.mark.parametrize(
    ("record", "field", "expected"),
    [
        ({"transport": {"protocol": "SCTP"}}, "transport", "TcpInfo | UdpInfo"),
        ({"transport": {"src_port": 1}}, "transport", "TcpInfo | UdpInfo"),
        ({"transport": [6]}, "transport", "TcpInfo | UdpInfo"),
        (
            {"application": {"message": {"protocol": "FTP"}}},
            "application.message",
            "HttpMessage | DnsMessage | SmtpSession",
        ),
        ({"decoded": {"kind": "html"}}, "decoded", "DecodedHttp | DecodedMime"),
    ],
)
def test_union_without_a_matching_tag_is_invalid(record, field, expected):
    _, issues = load({"network": {"src_ip": "10.0.0.1"}, **record})
    assert [(i.context["field"], i.context["expected"]) for i in issues] == [(field, expected)]


def test_nested_lists_of_ints_and_strings():
    event, issues = load(
        {
            "transport": {
                "protocol": "TCP",
                "options": [{"type": 5, "blocks": [[1, 2], [3, "4"], "x"]}],
            },
            "decoded": {"kind": "http", "uri": {"params": [["a", "1"], ["b", 2]]}},
        }
    )
    assert event.transport.options == [TcpOption(type=5, blocks=[[1, 2], [3]])]
    assert event.decoded.uri.params == [["a", "1"], ["b"]]
    assert invalid_fields(issues) == [
        "transport.options[0].blocks[1][1]",
        "transport.options[0].blocks[2]",
        "decoded.uri.params[1][1]",
    ]


def test_dict_fields_load_values_and_drop_bad_entries():
    event, issues = load(
        {
            "application": {"detection": {"scores": {"HTTP": 1, "DNS": "high"}}},
            "normalized": {"http": {"headers": {"host": ["a"], "x": "b"}}},
        }
    )
    assert event.application.detection.scores == {"HTTP": 1.0}
    assert event.normalized.http.headers == {"host": ["a"]}
    assert invalid_fields(issues) == [
        "application.detection.scores.DNS",
        "normalized.http.headers.x",
    ]


def test_object_fields_pass_json_values_through():
    issues = Issues("load")
    record = from_jsonable(DnsRecord, {"value": {"a": [1, "b", None, 2.5]}}, issues, "r")
    assert record.value == {"a": [1, "b", None, 2.5]}
    assert issues.records == []


def test_object_fields_reject_non_finite_numbers():
    issues = Issues("load")
    record = from_jsonable(DnsRecord, {"value": [1, float("nan")]}, issues, "r")
    assert record.value is None
    assert invalid_fields(issues.records) == ["r.value"]


def test_from_jsonable_on_a_non_object_returns_none():
    issues = Issues("load")
    assert from_jsonable(TcpFlags, [True], issues, "transport.flags") is None
    assert invalid_fields(issues.records) == ["transport.flags"]


@pytest.mark.parametrize("value", [[1, 2], "text", None, 5])
def test_non_object_record_becomes_a_stub(value):
    event, issues = decode_packet(value)
    assert event == PacketEvent()
    assert [(i.stage, i.code, i.context["field"]) for i in issues] == [("load", "invalid_type", "")]


@pytest.mark.parametrize(
    ("header", "context"),
    [
        ({"schema_version": 1}, {"schema_version": 1}),
        ({"schema_version": 9}, {"schema_version": 9}),
        ({"schema_version": "2"}, {"schema_version": "2"}),
        ({"schema_version": True}, {"schema_version": True}),
        ({"record_type": "flow"}, {"record_type": "flow"}),
        ({"record_type": None}, {"record_type": None}),
    ],
)
def test_unsupported_schema_is_reported_but_the_record_still_loads(header, context):
    event, issues = load({**header, **FLAT})
    assert [(i.stage, i.code, i.context) for i in issues] == [
        ("load", "unsupported_schema", context)
    ]
    assert event.packet_id == 3
    assert event.src_port == 51234


def test_absent_schema_version_and_record_type_are_accepted():
    _, issues = load(FLAT)
    assert issues == []


def test_flat_event_builds_network_and_transport():
    event, issues = load(FLAT)
    assert issues == []
    assert event.network == Ipv4Info(
        protocol="IPv4", src_ip="10.0.0.1", dst_ip="10.0.0.2", protocol_name="tcp"
    )
    assert event.transport == TcpInfo(src_port=51234, dst_port=80)
    assert event.event_type == "tcp_segment"


def test_flat_event_uses_transport_protocol_when_protocol_is_not_tcp_or_udp():
    record = {**FLAT, "protocol": "IPv4", "transport_protocol": "Udp"}
    event, issues = load(record)
    assert issues == []
    assert event.transport == UdpInfo(src_port=51234, dst_port=80)


def test_flat_event_without_a_transport_protocol_has_no_transport():
    event, issues = load({**FLAT, "protocol": "ICMP"})
    assert issues == []
    assert event.network.src_ip == "10.0.0.1"
    assert event.transport is None
    assert event.event_type == "network_only"


def test_flat_event_with_one_address_still_builds_network():
    record = {key: value for key, value in FLAT.items() if key != "src_ip"}
    event, _ = load(record)
    assert (event.network.src_ip, event.network.dst_ip) == (None, "10.0.0.2")


def test_flat_fields_with_wrong_types_are_reported_by_their_top_level_key():
    event, issues = load({**FLAT, "src_ip": 10, "src_port": "80", "dst_port": 70000})
    assert invalid_fields(issues) == ["src_ip", "src_port"]
    assert event.network.src_ip is None
    assert event.transport == TcpInfo(src_port=None, dst_port=70000)


def test_nested_blocks_win_over_flat_fields():
    record = {
        **FLAT,
        "network": {"protocol": "IPv4", "src_ip": "192.168.0.1"},
        "transport": {"protocol": "UDP", "src_port": 1},
    }
    event, issues = load(record)
    assert issues == []
    assert event.network == Ipv4Info(protocol="IPv4", src_ip="192.168.0.1")
    assert event.transport == UdpInfo(src_port=1)


def test_derived_and_unknown_top_level_keys_are_ignored():
    record = {
        **FLAT,
        "event_type": 5,
        "timestamp_iso": ["not", "a", "date"],
        "application_protocol": {"x": 1},
        "something_else": "x",
    }
    event, issues = load(record)
    assert issues == []
    assert event.application_protocol == "UNKNOWN"


def test_v1_event_loads_with_unsupported_schema():
    v1 = {
        "schema_version": 1,
        "packet_id": 2,
        "timestamp": 1759000001.107919,
        "timestamp_iso": "2025-09-27T19:06:41.107919+00:00",
        "event_type": "http_request",
        "network_protocol": "IPv4",
        "transport_protocol": "TCP",
        "application_protocol": "HTTP",
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "src_port": 51234,
        "dst_port": 80,
        "network": {"protocol": "IPv4", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "ttl": 64},
        "transport": {
            "protocol": "TCP",
            "src_port": 51234,
            "dst_port": 80,
            "flags": {"psh": True, "ack": True},
            "flags_list": ["PSH", "ACK"],
            "payload_length": 187,
        },
        "application": {
            "protocol": "HTTP",
            "detection": {"method": "port+payload", "confidence": 1.0, "scores": {"HTTP": 1.0}},
            "http": {"method": "GET", "headers": {"host": "example.com"}},
        },
        "payload": {"length": 187, "sha256": "ab" * 32, "preview": "GET / HTTP/1.1"},
        "errors": [],
    }
    event, issues = load(v1)
    assert [(i.code, i.context) for i in issues] == [("unsupported_schema", {"schema_version": 1})]
    assert (event.src_ip, event.dst_ip, event.src_port, event.dst_port) == (
        "10.0.0.1",
        "10.0.0.2",
        51234,
        80,
    )
    assert event.transport.flags == TcpFlags(psh=True, ack=True)
    assert event.application.protocol == "HTTP"
    assert event.application.message is None
    assert event.application.detection.scores == {"HTTP": 1.0}
    assert event.payload == Payload(length=187, sha256="ab" * 32, preview="GET / HTTP/1.1")
    assert event.event_type == "http_unparsed"


def test_lone_surrogates_are_rejected_so_the_event_stays_utf8_writable():
    text = '{"network": {"src_ip": "\\udc00"}, "reason": ["ok", "\\ud800"], '
    text += '"normalized": {"http": {"headers": {"\\ud800": ["x"], "host": ["a"]}}}}'
    event, issues = decode_packet(json.loads(text))
    assert event.network.src_ip is None
    assert event.reason == ["ok"]
    assert event.normalized.http.headers == {"host": ["a"]}
    assert invalid_fields(issues) == ["network.src_ip", "normalized.http.headers", "reason[1]"]
    encode_line(event).encode("utf-8")
