from __future__ import annotations

import json
from pathlib import Path

import pytest

from ids.cli import main
from ids.issues import Issue
from ids.model import (
    ApplicationInfo,
    DecodedMime,
    DecodeStatus,
    Ipv4Info,
    MessageEvent,
    PacketEvent,
    PreprocessStatus,
    ProcessingAction,
    TcpInfo,
)
from ids.parsers import PacketParser
from ids.pipeline import Runner
from ids.preprocess import PreprocessConfig, PreprocessorStage
from ids.sink import JsonlSink
from ids.stats import Stats

NOW = 1759000100.0
FLAT = {
    "packet_id": 1,
    "timestamp": 1759000000.0,
    "src_ip": "10.0.0.1",
    "dst_ip": "10.0.0.2",
    "protocol": "TCP",
    "src_port": 40000,
    "dst_port": 80,
}
FORWARD, MARK, DROP = ProcessingAction.FORWARD, ProcessingAction.MARK, ProcessingAction.DROP


def packet(packet_id: int = 1, **overrides: object) -> PacketEvent:
    fields: dict[str, object] = {
        "packet_id": packet_id,
        "timestamp": 1759000000.0,
        "network": Ipv4Info(src_ip="10.0.0.1", dst_ip="10.0.0.2", protocol_name="TCP"),
        "transport": TcpInfo(src_port=40000, dst_port=80),
    }
    fields.update(overrides)
    return PacketEvent(**fields)


def run(record, *, invalid: str = "mark", unsupported: str = "mark"):
    config = PreprocessConfig(
        invalid_policy=invalid, unsupported_policy=unsupported, clock=lambda: NOW
    )
    PreprocessorStage(config).process(record, [].append)
    return record


ICMP = Ipv4Info(src_ip="10.0.0.1", dst_ip="10.0.0.2", protocol_name="ICMP")
KINDS = {
    "valid": lambda: packet(),
    "partial": lambda: packet(transport=TcpInfo(src_port=0, dst_port=80)),
    "invalid": lambda: packet(transport=TcpInfo(src_port=40000, dst_port=70000)),
    "unsupported": lambda: packet(network=ICMP, transport=None),
    "invalid+unsupported": lambda: packet(packet_id=0, network=ICMP, transport=None),
}


@pytest.mark.parametrize(
    ("kind", "invalid", "unsupported", "action"),
    [
        ("valid", "drop", "drop", FORWARD),
        ("partial", "drop", "drop", MARK),
        ("invalid", "mark", "drop", MARK),
        ("invalid", "drop", "mark", DROP),
        ("unsupported", "mark", "mark", MARK),
        ("unsupported", "drop", "mark", MARK),
        ("unsupported", "mark", "drop", DROP),
        ("invalid+unsupported", "mark", "drop", MARK),
        ("invalid+unsupported", "drop", "mark", DROP),
    ],
)
def test_policy_matrix(kind, invalid, unsupported, action):
    record = run(KINDS[kind](), invalid=invalid, unsupported=unsupported)
    assert record.processing_action is action


def test_stage_writes_status_reason_and_normalized_values():
    record = run(packet(network=Ipv4Info(src_ip="010.000.000.001", dst_ip="10.0.0.2")))
    assert record.preprocess_status is PreprocessStatus.PARTIAL
    assert record.processing_action is MARK
    assert record.reason == ["ip_normalized"]
    assert record.normalized.src_ip == "10.0.0.1"
    assert record.network.src_ip == "010.000.000.001"


def test_valid_event_has_an_empty_reason_list():
    record = run(packet())
    assert (record.preprocess_status, record.processing_action, record.reason) == (
        PreprocessStatus.VALID,
        FORWARD,
        [],
    )


def test_normalization_notes_follow_validation_reasons_without_duplicates():
    record = run(
        packet(
            timestamp=1759000000000,
            transport=TcpInfo(src_port=0, dst_port=80),
            issues=[Issue("application", "decode_error", "x")],
        )
    )
    assert record.reason == [
        "reserved_port:src_port",
        "application/decode_error",
        "timestamp_scaled",
    ]


def test_the_configured_clock_bounds_future_timestamps():
    record = packet(timestamp=1759000000.0)
    config = PreprocessConfig(clock=lambda: 1759000000.0 - 86401)
    PreprocessorStage(config).process(record, [].append)
    assert record.reason == ["invalid_timestamp"]


def test_unknown_application_on_tcp_is_forwarded():
    record = run(
        packet(application=ApplicationInfo(protocol="UNKNOWN")), invalid="drop", unsupported="drop"
    )
    assert (record.preprocess_status, record.processing_action) == (PreprocessStatus.VALID, FORWARD)


@pytest.mark.parametrize("field", ["invalid_policy", "unsupported_policy"])
def test_config_rejects_unknown_policies(field):
    with pytest.raises(ValueError, match=field):
        PreprocessConfig(**{field: "skip"})


def message(**overrides: object) -> MessageEvent:
    fields: dict[str, object] = {
        "message_id": "f-1",
        "complete": True,
        "truncated": False,
        "gap": False,
        "decoded": DecodedMime(status=DecodeStatus.DECODED),
    }
    fields.update(overrides)
    return MessageEvent(**fields)


@pytest.mark.parametrize(
    ("overrides", "reasons"),
    [
        ({}, []),
        ({"decoded": None}, []),
        ({"decoded": DecodedMime(status=DecodeStatus.UNCHANGED)}, []),
        ({"complete": False}, ["message_incomplete"]),
        ({"truncated": True}, ["message_truncated"]),
        ({"gap": True}, ["message_gap"]),
        ({"decoded": DecodedMime(status=DecodeStatus.PARTIAL)}, ["decode_partial:mime"]),
        ({"decoded": DecodedMime(status=DecodeStatus.FAILED)}, ["decode_failed:mime"]),
        (
            {"complete": False, "gap": True, "issues": [Issue("decoder", "invalid_base64", "x")]},
            ["message_incomplete", "message_gap", "decoder/invalid_base64"],
        ),
    ],
)
def test_message_status_follows_reassembly_and_mime_outcome(overrides, reasons):
    record = run(message(**overrides), invalid="drop", unsupported="drop")
    assert record.reason == reasons
    if reasons:
        assert (record.preprocess_status, record.processing_action) == (
            PreprocessStatus.PARTIAL,
            MARK,
        )
    else:
        assert (record.preprocess_status, record.processing_action) == (
            PreprocessStatus.VALID,
            FORWARD,
        )


INVALID_LINE = {**FLAT, "packet_id": 2, "dst_port": 70000}
ICMP_LINE = {
    "packet_id": 3,
    "timestamp": 1759000002.0,
    "src_ip": "10.0.0.1",
    "dst_ip": "10.0.0.2",
    "protocol": "ICMP",
}


def packet_records(path: Path) -> list[dict[str, object]]:
    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    return [record for record in records if record["record_type"] == "packet"]


def verdicts(path: Path) -> list[tuple[object, ...]]:
    return [
        (r["packet_id"], r["preprocess_status"], r["processing_action"], r["reason"])
        for r in packet_records(path)
    ]


def write_events(tmp_path: Path, *records: dict[str, object]) -> str:
    path = tmp_path / "events.jsonl"
    path.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")
    return str(path)


def test_runner_does_not_write_an_event_the_drop_policy_dropped(tmp_path):
    output = tmp_path / "out.jsonl"
    stats = Stats()
    stage = PreprocessorStage(PreprocessConfig(invalid_policy="drop", clock=lambda: NOW))
    events = [packet(1), packet(2, transport=TcpInfo(src_port=40000, dst_port=70000))]
    with JsonlSink(str(output)) as sink:
        Runner(PacketParser(), [stage], sink, stats).run(events)
    assert verdicts(output) == [(1, "valid", "forward", [])]
    assert stats.to_dict()["dropped"] == 1


def test_unknown_policy_skip_still_skips_rather_than_drops_a_forwarded_unknown_event(tmp_path):
    output = tmp_path / "out.jsonl"
    stats = Stats()
    config = PreprocessConfig(invalid_policy="drop", unsupported_policy="drop", clock=lambda: NOW)
    unknown = packet(1, application=ApplicationInfo(protocol="UNKNOWN"))
    with JsonlSink(str(output)) as sink:
        Runner(PacketParser(), [PreprocessorStage(config)], sink, stats, unknown_policy="skip").run(
            [unknown]
        )
    summary = stats.to_dict()
    assert (summary["skipped"], summary["dropped"]) == (1, 0)
    assert output.read_text(encoding="utf-8") == ""


def test_cli_marks_invalid_and_unsupported_events_by_default(tmp_path):
    events = write_events(tmp_path, FLAT, INVALID_LINE, ICMP_LINE)
    output = tmp_path / "out.jsonl"
    assert main(["--events", events, "-o", str(output), "-q"]) == 0
    assert verdicts(output) == [
        (1, "valid", "forward", []),
        (2, "invalid", "mark", ["invalid_port:dst_port"]),
        (3, "partial", "mark", ["unsupported_protocol:ICMP"]),
    ]


def test_cli_invalid_policy_drop_writes_only_the_valid_event(tmp_path):
    events = write_events(tmp_path, FLAT, INVALID_LINE)
    output = tmp_path / "out.jsonl"
    assert main(["--events", events, "-o", str(output), "-q", "--invalid-policy", "drop"]) == 0
    assert verdicts(output) == [(1, "valid", "forward", [])]


def test_cli_unsupported_policy_drop_writes_only_the_supported_event(tmp_path):
    events = write_events(tmp_path, FLAT, ICMP_LINE)
    output = tmp_path / "out.jsonl"
    argv = ["--events", events, "-o", str(output), "-q", "--unsupported-policy", "drop"]
    assert main(argv) == 0
    assert verdicts(output) == [(1, "valid", "forward", [])]


@pytest.mark.parametrize("flag", ["--invalid-policy", "--unsupported-policy"])
def test_cli_rejects_an_unknown_policy_value(tmp_path, flag):
    with pytest.raises(SystemExit) as caught:
        main(["--events", write_events(tmp_path, FLAT), flag, "skip"])
    assert caught.value.code == 2
