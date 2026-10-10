from __future__ import annotations

import base64
import json
from dataclasses import fields

import pytest
from codec_samples import TS, flow_record, message_event, rich_dns_event, rich_http_event

from ids.codec import encode, encode_line, iso_timestamp, to_jsonable
from ids.issues import Issue
from ids.model import (
    DecodedMime,
    Detection,
    DnsQuestion,
    FlowRecord,
    Ipv4Info,
    MessageEvent,
    MimeHeaders,
    PacketEvent,
    Payload,
    TcpInfo,
)

PACKET_KEYS = [
    "schema_version",
    "record_type",
    "packet_id",
    "timestamp",
    "timestamp_iso",
    "event_type",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "application_protocol",
    "preprocess_status",
    "processing_action",
    "reason",
    "flow",
    "capture",
    "link",
    "network",
    "transport",
    "application",
    "payload",
    "decoded",
    "normalized",
    "issues",
]


def test_packet_record_key_order():
    assert list(encode(rich_http_event())) == PACKET_KEYS


def test_empty_packet_record_has_every_key_with_empty_values():
    assert encode(PacketEvent()) == {
        "schema_version": 2,
        "record_type": "packet",
        "packet_id": None,
        "timestamp": None,
        "timestamp_iso": None,
        "event_type": "unparsed",
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "protocol": None,
        "application_protocol": "UNKNOWN",
        "preprocess_status": None,
        "processing_action": None,
        "reason": [],
        "flow": None,
        "capture": None,
        "link": None,
        "network": None,
        "transport": None,
        "application": None,
        "payload": None,
        "decoded": None,
        "normalized": None,
        "issues": [],
    }


def test_derived_top_level_fields_come_from_the_nested_blocks():
    record = encode(rich_http_event())
    assert record["timestamp"] == TS
    assert record["timestamp_iso"] == "2025-09-27T19:06:40.100000Z"
    assert record["event_type"] == "http_request"
    assert (record["src_ip"], record["dst_ip"], record["src_port"], record["dst_port"]) == (
        "10.0.0.1",
        "10.0.0.2",
        51234,
        80,
    )
    assert record["protocol"] == "TCP"
    assert record["application_protocol"] == "HTTP"


def test_nested_dataclass_writes_every_declared_field_in_order():
    network = encode(PacketEvent(network=Ipv4Info(src_ip="10.0.0.1")))["network"]
    assert list(network) == [f.name for f in fields(Ipv4Info)]
    assert network["src_ip"] == "10.0.0.1"
    assert network["flags"] is None
    assert network["options"] == []


def test_json_aliases_replace_python_field_names():
    assert to_jsonable(DnsQuestion(name="a", type=1, class_=1)) == {
        "name": "a",
        "type": 1,
        "type_name": None,
        "class": 1,
        "class_name": None,
    }
    headers = to_jsonable(MimeHeaders(from_="a@example.com"))
    assert "from_" not in headers
    assert headers["from"] == "a@example.com"


def test_bytes_fields_are_written_as_base64_under_b64_keys():
    data = b"\x00\xffGET"
    encoded = to_jsonable(Payload(length=5, data=data))
    assert "data" not in encoded
    assert encoded["data_b64"] == base64.b64encode(data).decode("ascii")
    assert base64.b64decode(encoded["data_b64"]) == data


def test_missing_bytes_are_written_as_null_b64():
    assert to_jsonable(Payload())["data_b64"] is None


def test_enums_are_written_as_their_values():
    record = encode(rich_http_event())
    assert record["preprocess_status"] == "partial"
    assert record["processing_action"] == "mark"
    assert record["flow"] == {
        "flow_id": "0123456789abcdef",
        "direction": "forward",
        "state": "ESTABLISHED",
        "flow_packet_index": 4,
    }
    assert record["decoded"]["status"] == "decoded"
    assert record["decoded"]["kind"] == "http"


def test_issues_are_written_as_objects():
    assert encode(rich_http_event())["issues"] == [
        {
            "stage": "transport",
            "code": "truncated_packet",
            "message": "short segment",
            "context": {"needed": 20, "have": 12},
        }
    ]


def test_dns_record_alias_object_value_and_nested_issue():
    answers = encode(rich_dns_event())["application"]["message"]["answers"]
    assert answers[0]["class"] == 1
    assert answers[0]["value"] == "93.184.216.34"
    assert answers[1]["value"] == ["v=spf1", "-all"]
    opt = encode(rich_dns_event())["application"]["message"]["additionals"][0]
    assert opt["value"] == {"flags": 0, "note": "x"}
    assert opt["rdata_error"] == {
        "stage": "application",
        "code": "decode_error",
        "message": "bad",
        "context": {"offset": 3},
    }


def test_message_record_starts_with_schema_and_type_then_declared_fields():
    record = encode(message_event())
    expected = ["schema_version", "record_type"]
    expected += ["data_b64" if f.name == "data" else f.name for f in fields(MessageEvent)]
    assert list(record) == expected
    assert record["record_type"] == "message"
    assert base64.b64decode(record["data_b64"]) == message_event().data
    assert record["decoded"]["headers"]["from"] == "a@example.com"


def test_flow_record_starts_with_schema_and_type_then_declared_fields():
    record = encode(flow_record())
    assert list(record) == ["schema_version", "record_type"] + [f.name for f in fields(FlowRecord)]
    assert record["record_type"] == "flow"
    assert record["forward"] == {"packet_count": 3, "byte_count": 250, "payload_byte_count": 100}
    assert record["tcp"]["state"] == "CLOSED"
    assert record["end_reason"] == "closed"


def test_empty_flow_record_keeps_zero_counters():
    record = encode(FlowRecord())
    assert record["packet_count"] == 0
    assert record["forward"] == {"packet_count": 0, "byte_count": 0, "payload_byte_count": 0}
    assert record["tcp"] is None
    assert record["end_reason"] is None


@pytest.mark.parametrize(
    "record",
    [
        PacketEvent(reason=[b"raw"]),
        PacketEvent(issues=[Issue("load", "x", "y", {"value": {1, 2}})]),
        PacketEvent(issues=[Issue("load", "x", "y", {1: "int key"})]),
    ],
)
def test_non_json_values_raise_type_error(record):
    with pytest.raises(TypeError):
        encode(record)


def test_non_json_value_inside_a_nested_block_raises_type_error():
    with pytest.raises(TypeError):
        to_jsonable(Detection(scores={"HTTP": object()}))


def test_encode_rejects_objects_that_are_not_records():
    with pytest.raises(TypeError):
        encode(TcpInfo())


def test_encode_line_is_compact_and_keeps_unicode():
    line = encode_line(PacketEvent(decoded=DecodedMime(headers=MimeHeaders(subject="Chào"))))
    assert line.startswith('{"schema_version":2,"record_type":"packet","packet_id":null,')
    assert "Chào" in line
    assert json.loads(line)["decoded"]["headers"]["subject"] == "Chào"


def test_encode_line_rejects_nan():
    with pytest.raises(ValueError):
        encode_line(PacketEvent(packet_id=1, timestamp=float("nan")))


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, None),
        (0, "1970-01-01T00:00:00.000000Z"),
        (1759000000, "2025-09-27T19:06:40.000000Z"),
        (TS, "2025-09-27T19:06:40.100000Z"),
        (1e20, None),
        (float("nan"), None),
    ],
)
def test_iso_timestamp(value, expected):
    assert iso_timestamp(value) == expected


def test_out_of_range_timestamp_encodes_with_null_iso():
    record = encode(PacketEvent(packet_id=1, timestamp=1e20))
    assert record["timestamp"] == 1e20
    assert record["timestamp_iso"] is None
