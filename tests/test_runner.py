from __future__ import annotations

from pathlib import Path

import pytest

from ids.capture import PcapSource
from ids.issues import Issue
from ids.model import (
    ApplicationInfo,
    FlowRecord,
    MessageEvent,
    PacketEvent,
    ProcessingAction,
    RawPacket,
    Tick,
)
from ids.parsers import PacketParser
from ids.pipeline import UNKNOWN_POLICIES, Runner
from ids.stats import Stats

FIXTURES = Path(__file__).resolve().parents[1] / "TEST" / "fixtures"


class ListSink:
    def __init__(self):
        self.records = []

    def write(self, record):
        self.records.append(record)


class FailingSink:
    def write(self, record):
        raise OSError("disk full")


def label(record):
    if isinstance(record, FlowRecord):
        return ("flow", record.flow_id)
    if isinstance(record, MessageEvent):
        return ("message", record.message_id)
    return ("packet", record.packet_id)


def labels(sink):
    return [label(record) for record in sink.records]


class Recorder:
    """Stage that logs every call into a shared journal."""

    def __init__(self, name, journal):
        self.name = name
        self.journal = journal

    def process(self, record, emit):
        self.journal.append((self.name, "process", label(record)[1]))

    def tick(self, now, emit):
        self.journal.append((self.name, "tick", now))

    def flush(self, emit):
        self.journal.append((self.name, "flush", None))


class Exploding(Recorder):
    def process(self, record, emit):
        raise RuntimeError("stage bug")


class Dropper(Recorder):
    def process(self, record, emit):
        super().process(record, emit)
        record.processing_action = ProcessingAction.DROP


class Emitter(Recorder):
    """Emits a flow and a message while processing packet 2; notes any re-entry."""

    def __init__(self, name, journal):
        super().__init__(name, journal)
        self.active = False
        self.reentered = False

    def process(self, record, emit):
        if self.active:
            self.reentered = True
        self.active = True
        super().process(record, emit)
        if isinstance(record, PacketEvent) and record.packet_id == 2:
            emit(FlowRecord(flow_id="f1"))
            emit(MessageEvent(message_id="m1"))
        self.active = False


class Flusher(Recorder):
    def flush(self, emit):
        super().flush(emit)
        emit(FlowRecord(flow_id="end"))


class BrokenClock(Recorder):
    def tick(self, now, emit):
        raise RuntimeError("tick bug")

    def flush(self, emit):
        raise RuntimeError("flush bug")


def packet(packet_id, protocol="HTTP", **fields):
    return PacketEvent(
        packet_id=packet_id,
        timestamp=float(packet_id),
        application=ApplicationInfo(protocol=protocol),
        **fields,
    )


def run(stages, items, sink=None, **options):
    sink = sink if sink is not None else ListSink()
    stats = Stats()
    Runner(PacketParser(), stages, sink, stats, **options).run(items)
    return sink, stats


def test_records_pass_every_stage_in_order_then_reach_the_sink():
    journal = []
    sink, stats = run([Recorder("a", journal), Recorder("b", journal)], [packet(1), packet(2)])
    assert journal == [
        ("a", "process", 1),
        ("b", "process", 1),
        ("a", "process", 2),
        ("b", "process", 2),
        ("a", "flush", None),
        ("b", "flush", None),
    ]
    assert labels(sink) == [("packet", 1), ("packet", 2)]
    assert stats.to_dict()["records_written"]["packet"] == 2


def test_raw_packets_are_parsed_before_the_stages():
    sink, _ = run([], [RawPacket(1, 1.0, b"\x00" * 6, 1, "pcap", "test", 6, 6)])
    (event,) = sink.records
    assert [(issue.stage, issue.code) for issue in event.issues] == [("link", "truncated_packet")]
    assert event.capture.origin == "test"


def test_a_failing_stage_records_an_issue_and_the_next_stage_still_runs():
    journal = []
    sink, _ = run([Exploding("boom", journal), Recorder("after", journal)], [packet(1)])
    assert ("after", "process", 1) in journal
    assert sink.records[0].issues == [
        Issue("boom", "internal_error", "stage bug", {"exception": "RuntimeError"})
    ]


def test_a_drop_stops_the_record_before_the_next_stage():
    journal = []
    sink, stats = run([Dropper("drop", journal), Recorder("after", journal)], [packet(1)])
    assert ("after", "process", 1) not in journal
    assert sink.records == []
    assert (stats.dropped_count, stats.packets_seen) == (1, 1)


def test_a_record_dropped_by_the_last_stage_is_not_written():
    journal = []
    sink, stats = run([Recorder("first", journal), Dropper("last", journal)], [packet(1)])
    assert sink.records == []
    assert stats.dropped_count == 1


def test_a_record_already_marked_drop_never_reaches_a_stage():
    journal = []
    sink, stats = run(
        [Recorder("a", journal)], [packet(1, processing_action=ProcessingAction.DROP)]
    )
    assert journal == [("a", "flush", None)]
    assert sink.records == []
    assert stats.dropped_count == 1


def test_emitted_records_are_written_before_the_triggering_packet():
    journal = []
    emitter = Emitter("emitter", journal)
    sink, stats = run(
        [Recorder("first", journal), emitter, Recorder("last", journal)],
        [packet(1), packet(2)],
    )
    assert labels(sink) == [("packet", 1), ("flow", "f1"), ("message", "m1"), ("packet", 2)]
    assert journal[3:9] == [
        ("first", "process", 2),
        ("emitter", "process", 2),
        ("first", "process", "m1"),
        ("emitter", "process", "m1"),
        ("last", "process", "m1"),
        ("last", "process", 2),
    ]
    assert emitter.reentered is False
    assert stats.to_dict()["records_written"] == {"packet": 2, "message": 1, "flow": 1}


def test_ticks_reach_every_stage_between_records():
    journal = []
    sink, _ = run(
        [Recorder("a", journal), Recorder("b", journal)], [packet(1), Tick(5.0), packet(2)]
    )
    assert journal == [
        ("a", "process", 1),
        ("b", "process", 1),
        ("a", "tick", 5.0),
        ("b", "tick", 5.0),
        ("a", "process", 2),
        ("b", "process", 2),
        ("a", "flush", None),
        ("b", "flush", None),
    ]
    assert labels(sink) == [("packet", 1), ("packet", 2)]


def test_flush_output_is_written_at_end_of_input():
    sink, _ = run([Flusher("flow", [])], [packet(1)])
    assert labels(sink) == [("packet", 1), ("flow", "end")]


def test_tick_and_flush_failures_are_isolated_and_counted():
    journal = []
    sink, stats = run([BrokenClock("clock", journal), Flusher("after", journal)], [Tick(1.0)])
    assert journal == [("after", "tick", 1.0), ("after", "flush", None)]
    assert labels(sink) == [("flow", "end")]
    assert stats.to_dict()["stage_errors"] == {"clock/tick": 1, "clock/flush": 1}


def test_sink_failures_are_not_swallowed():
    with pytest.raises(OSError, match="disk full"):
        run([Recorder("a", [])], [packet(1)], sink=FailingSink())


def test_unknown_policy_skip_suppresses_only_unknown_packets():
    sink, stats = run(
        [Emitter("emitter", [])],
        [packet(1, "UNKNOWN"), packet(2), PacketEvent(packet_id=3)],
        unknown_policy="skip",
    )
    assert labels(sink) == [("flow", "f1"), ("message", "m1"), ("packet", 2)]
    assert (stats.skipped_count, stats.packets_seen) == (2, 3)


def test_unknown_policy_must_be_known():
    assert UNKNOWN_POLICIES == ("emit", "skip")
    with pytest.raises(ValueError):
        Runner(PacketParser(), [], ListSink(), Stats(), unknown_policy="explode")


def test_keyboard_interrupt_flushes_the_stages_then_propagates():
    def items():
        yield packet(1)
        raise KeyboardInterrupt

    sink = ListSink()
    with pytest.raises(KeyboardInterrupt):
        Runner(PacketParser(), [Flusher("flow", [])], sink, Stats()).run(items())
    assert labels(sink) == [("packet", 1), ("flow", "end")]


def test_unknown_policy_skip_on_capture_fixtures():
    sink, stats = run([], PcapSource(FIXTURES / "04-http-get.pcap").items(), unknown_policy="skip")
    assert [event.event_type for event in sink.records] == ["http_request"]
    assert stats.skipped_count == 1
    sink, stats = run(
        [], PcapSource(FIXTURES / "11-unknown-protocol.pcap").items(), unknown_policy="skip"
    )
    assert sink.records == []
    assert (stats.skipped_count, stats.packets_seen) == (6, 6)
