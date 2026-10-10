from __future__ import annotations

from ids.issues import Issue
from ids.model import (
    ApplicationInfo,
    Detection,
    EndReason,
    FlowRecord,
    HttpMessage,
    Ipv4Info,
    MessageEvent,
    PacketEvent,
    Payload,
    PreprocessStatus,
    ProcessingAction,
    TcpInfo,
)
from ids.stats import Stats


def http_packet(packet_id, **fields):
    return PacketEvent(
        packet_id=packet_id,
        timestamp=float(packet_id),
        network=Ipv4Info(protocol="IPv4"),
        transport=TcpInfo(),
        application=ApplicationInfo(
            protocol="HTTP",
            detection=Detection(protocol="HTTP", method="port+payload"),
            message=HttpMessage(kind="request"),
        ),
        payload=Payload(length=10),
        **fields,
    )


def test_written_packets_fill_the_breakdowns():
    stats = Stats()
    stats.observe(http_packet(1))
    stats.observe(
        PacketEvent(packet_id=2, timestamp=2.0, issues=[Issue("link", "truncated_packet", "short")])
    )
    summary = stats.to_dict()
    assert stats.written == 2
    assert summary["packets_seen"] == 2
    assert summary["records_written"] == {"packet": 2, "message": 0, "flow": 0}
    assert summary["event_types"] == {"http_request": 1, "unparsed": 1}
    assert summary["protocols"] == {"TCP": 1, "none": 1}
    assert summary["application_protocols"] == {"HTTP": 1, "UNKNOWN": 1}
    assert summary["detection_methods"] == {"port+payload": 1}
    assert summary["issue_codes"] == {"link/truncated_packet": 1}
    assert summary["packets_with_issues"] == 1
    assert (summary["first_timestamp"], summary["last_timestamp"]) == (1.0, 2.0)


def test_dropped_and_skipped_packets_are_seen_but_not_written():
    stats = Stats()
    stats.dropped(
        http_packet(
            1,
            preprocess_status=PreprocessStatus.INVALID,
            processing_action=ProcessingAction.DROP,
        )
    )
    stats.skipped(PacketEvent(packet_id=2, timestamp=3.0))
    summary = stats.to_dict()
    assert summary["packets_seen"] == 2
    assert summary["dropped"] == 1
    assert summary["skipped"] == 1
    assert summary["records_written"] == {"packet": 0, "message": 0, "flow": 0}
    assert summary["preprocess_status"] == {"invalid": 1}
    assert summary["processing_action"] == {"drop": 1}
    assert summary["event_types"] == {}
    assert summary["last_timestamp"] == 3.0


def test_messages_and_flows_are_counted_by_outcome():
    stats = Stats()
    stats.observe(MessageEvent(message_id="f-1", complete=True))
    stats.observe(
        MessageEvent(
            message_id="f-2",
            complete=False,
            preprocess_status=PreprocessStatus.PARTIAL,
            issues=[Issue("decoder", "invalid_base64", "bad")],
        )
    )
    stats.observe(FlowRecord(flow_id="a", end_reason=EndReason.CLOSED))
    stats.observe(FlowRecord(flow_id="b", end_reason=EndReason.IDLE_TIMEOUT))
    summary = stats.to_dict()
    assert summary["records_written"] == {"packet": 0, "message": 2, "flow": 2}
    assert summary["messages"] == {"complete": 1, "incomplete": 1}
    assert summary["flow_end_reasons"] == {"closed": 1, "idle_timeout": 1}
    assert summary["issue_codes"] == {"decoder/invalid_base64": 1}
    assert summary["preprocess_status"] == {"partial": 1}
    assert summary["packets_seen"] == 0


def test_timestamps_skip_missing_values():
    stats = Stats()
    stats.observe(PacketEvent(packet_id=1))
    stats.observe(PacketEvent(packet_id=2, timestamp=5.0))
    stats.observe(PacketEvent(packet_id=3))
    summary = stats.to_dict()
    assert (summary["first_timestamp"], summary["last_timestamp"]) == (5.0, 5.0)


def test_stage_errors_and_extra_are_reported_last():
    stats = Stats()
    stats.stage_error("flow", "flush")
    stats.stage_error("flow", "flush")
    stats.extra["active_flows"] = 3
    summary = stats.to_dict()
    assert summary["stage_errors"] == {"flow/flush": 2}
    assert summary["active_flows"] == 3
    assert list(summary)[-2:] == ["stage_errors", "active_flows"]
