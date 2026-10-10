from __future__ import annotations

from flow_events import CLIENT, SERVER, T0, tcp_event, udp_event

from ids.flow import FlowConfig, FlowTrackerStage
from ids.model import (
    EndReason,
    FlowRecord,
    MessageEvent,
    Normalized,
    PacketEvent,
    PreprocessStatus,
)
from ids.stats import Stats


def test_message_events_pass_untouched():
    stage, out = FlowTrackerStage(), []
    message = MessageEvent(message_id="x-1", data=b"hi")
    stage.process(message, out.append)
    assert out == []
    assert stage.active_count == 0


def test_invalid_events_are_not_tracked():
    stage, out = FlowTrackerStage(), []
    event = udp_event(1, T0, CLIENT, SERVER)
    event.preprocess_status = PreprocessStatus.INVALID
    stage.process(event, out.append)
    assert event.flow is None
    assert stage.active_count == 0


def test_partial_events_are_tracked():
    stage, out = FlowTrackerStage(), []
    event = udp_event(1, T0, CLIENT, SERVER)
    event.preprocess_status = PreprocessStatus.PARTIAL
    stage.process(event, out.append)
    assert event.flow is not None
    assert event.flow.flow_packet_index == 1


def test_events_without_a_five_tuple_or_time_are_not_tracked():
    stage, out = FlowTrackerStage(), []
    no_transport = PacketEvent(packet_id=1, timestamp=T0)
    no_time = udp_event(2, T0, CLIENT, SERVER)
    no_time.timestamp = None
    for event in (no_transport, no_time):
        stage.process(event, out.append)
        assert event.flow is None
    assert stage.active_count == 0


def test_normalized_timestamps_drive_the_clock():
    stage, out = FlowTrackerStage(), []
    first = udp_event(1, 1759000000000.0, CLIENT, SERVER)  # raw value in milliseconds
    first.normalized = Normalized(timestamp=T0)
    second = udp_event(2, 1759000001000.0, SERVER, CLIENT)
    second.normalized = Normalized(timestamp=T0 + 1)
    stage.process(first, out.append)
    stage.process(second, out.append)
    assert out == []
    assert second.flow.flow_id == first.flow.flow_id
    stage.flush(out.append)
    assert (out[0].start_time, out[0].duration) == (T0, 1.0)


def test_tick_expires_idle_flows_without_new_packets():
    stage = FlowTrackerStage(FlowConfig(udp_idle_timeout=60.0))
    out = []
    stage.process(udp_event(1, T0, CLIENT, SERVER), out.append)
    stage.tick(T0 + 30, out.append)
    assert out == []
    stage.tick(T0 + 61, out.append)
    assert [(type(r), r.end_reason) for r in out] == [(FlowRecord, EndReason.IDLE_TIMEOUT)]
    assert stage.active_count == 0


def test_flush_reports_active_flows_and_exports_them():
    stats = Stats()
    stage, out = FlowTrackerStage(stats=stats), []
    stage.process(udp_event(1, T0, CLIENT, SERVER), out.append)
    stage.process(tcp_event(2, T0 + 1, CLIENT, SERVER, "S"), out.append)
    stage.flush(out.append)
    assert stats.extra["active_flows"] == 2
    assert [r.end_reason for r in out] == [EndReason.END_OF_INPUT, EndReason.END_OF_INPUT]
    assert stage.active_count == 0
