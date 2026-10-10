from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from ids.capture import EventsSource, PcapSource
from ids.codec import encode_line
from ids.parsers import PacketParser

FIXTURES = Path(__file__).resolve().parents[1] / "TEST" / "capture-parser" / "fixtures"


def write_lines(tmp_path, *lines):
    path = tmp_path / "events.jsonl"
    encoded = [line if isinstance(line, bytes) else line.encode("utf-8") for line in lines]
    path.write_bytes(b"\n".join(encoded) + b"\n")
    return path


def load(path, **options):
    source = EventsSource(path, **options)
    return source, list(source.items())


def codes(event):
    return [(issue.stage, issue.code) for issue in event.issues]


def test_parsed_events_round_trip(tmp_path):
    parser = PacketParser()
    originals = [parser.parse(raw) for raw in PcapSource(FIXTURES / "04-http-get.pcap").items()]
    source, loaded = load(write_lines(tmp_path, *(encode_line(event) for event in originals)))
    assert loaded == originals
    assert source.describe()["events_loaded"] == 2


def test_blank_lines_count_and_non_json_becomes_a_stub(tmp_path):
    path = write_lines(tmp_path, "", '{"packet_id": 7, "timestamp": 1.5}', "   ", "not json")
    _, events = load(path)
    assert [(event.packet_id, event.timestamp) for event in events] == [(7, 1.5), (4, None)]
    assert events[0].issues == []
    (issue,) = events[1].issues
    assert (issue.stage, issue.code, issue.context) == ("load", "invalid_json", {"line": 4})


def test_flow_and_message_lines_are_skipped_with_a_warning(tmp_path):
    path = write_lines(
        tmp_path,
        '{"record_type": "flow", "flow_id": "x"}',
        '{"record_type": "packet", "packet_id": 2}',
        '{"record_type": "message"}',
    )
    source, events = load(path)
    assert [event.packet_id for event in events] == [2]
    assert source.warnings == [
        "line 1: skipped record_type 'flow'",
        "line 3: skipped record_type 'message'",
    ]
    assert source.describe()["skipped_records"] == 2


def test_unhashable_record_type_is_loaded_as_unsupported_schema(tmp_path):
    _, events = load(write_lines(tmp_path, '{"record_type": ["flow"], "packet_id": 1}'))
    assert [event.packet_id for event in events] == [1]
    assert ("load", "unsupported_schema") in codes(events[0])


def test_other_schema_versions_still_load(tmp_path):
    _, (event,) = load(write_lines(tmp_path, '{"schema_version": 9, "packet_id": 1}'))
    assert event.packet_id == 1
    assert ("load", "unsupported_schema") in codes(event)


def test_load_issues_follow_the_carried_issues(tmp_path):
    line = json.dumps(
        {
            "packet_id": 1,
            "timestamp": "late",
            "issues": [
                {"stage": "network", "code": "truncated_packet", "message": "short", "context": {}}
            ],
        }
    )
    _, (event,) = load(write_lines(tmp_path, line))
    assert event.timestamp is None
    assert codes(event) == [("network", "truncated_packet"), ("load", "invalid_type")]


def test_stage_outputs_are_cleared_on_load(tmp_path):
    line = json.dumps(
        {
            "packet_id": 1,
            "preprocess_status": "invalid",
            "processing_action": "drop",
            "reason": ["invalid_timestamp"],
            "flow": {"flow_id": "abc"},
            "normalized": {"protocol": "TCP"},
            "decoded": {"kind": "http", "status": "decoded"},
            "issues": [
                {"stage": "preprocess", "code": "x", "message": "old verdict", "context": {}},
                {"stage": "network", "code": "truncated_packet", "message": "short", "context": {}},
            ],
        }
    )
    _, (event,) = load(write_lines(tmp_path, line))
    assert event.preprocess_status is None
    assert event.processing_action is None
    assert event.reason == []
    assert event.flow is None
    assert event.normalized is None
    assert event.decoded is None
    assert codes(event) == [("network", "truncated_packet")]


def test_count_limit(tmp_path):
    path = write_lines(tmp_path, '{"packet_id": 1}', '{"packet_id": 2}', '{"packet_id": 3}')
    _, events = load(path, count=2)
    assert [event.packet_id for event in events] == [1, 2]


def test_dash_reads_stdin(monkeypatch):
    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(b'{"packet_id": 1}\n')))
    source, events = load("-")
    assert [event.packet_id for event in events] == [1]
    assert source.origin == "stdin"


def test_invalid_utf8_line_is_a_stub_and_bom_is_accepted(tmp_path):
    path = write_lines(
        tmp_path,
        b'\xef\xbb\xbf{"packet_id": 1}',
        b'{"packet_id": "\xff"}',
        b'{"packet_id": 3}',
    )
    _, events = load(path)
    assert [event.packet_id for event in events] == [1, 2, 3]
    assert [codes(event) for event in events] == [[], [("load", "invalid_json")], []]


def test_nan_and_infinity_are_invalid_json(tmp_path):
    path = write_lines(
        tmp_path,
        '{"packet_id": 5, "timestamp": NaN}',
        '{"packet_id": 6, "timestamp": -Infinity}',
    )
    _, events = load(path)
    assert [(event.packet_id, event.timestamp) for event in events] == [(1, None), (2, None)]
    assert [codes(event) for event in events] == [[("load", "invalid_json")]] * 2
    assert [json.loads(encode_line(event))["packet_id"] for event in events] == [1, 2]


def test_missing_file_raises_oserror(tmp_path):
    with pytest.raises(OSError):
        list(EventsSource(tmp_path / "missing.jsonl").items())


def test_recursion_error_line_is_a_stub(tmp_path, monkeypatch):
    real_loads = json.loads

    def loads(line, **kwargs):
        if line.startswith(b"[[deep"):
            raise RecursionError("maximum recursion depth exceeded")
        return real_loads(line, **kwargs)

    monkeypatch.setattr("ids.capture.events.json.loads", loads)
    path = write_lines(tmp_path, "[[deep]]", '{"packet_id": 2}')
    _, events = load(path)
    assert [event.packet_id for event in events] == [1, 2]
    assert [codes(event) for event in events] == [[("load", "invalid_json")], []]
