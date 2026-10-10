from __future__ import annotations

import json
import sys

import pytest

from ids.codec import encode_line
from ids.model import EndReason, FlowRecord, MessageEvent, PacketEvent
from ids.sink import JsonlSink

PACKET = PacketEvent(packet_id=1, timestamp=1.0)
FLOW = FlowRecord(flow_id="f1", end_reason=EndReason.CLOSED)
MESSAGE = MessageEvent(message_id="f1-1", flow_id="f1", data=b"hi")


def lines(path):
    return path.read_text(encoding="utf-8").splitlines()


def test_records_are_written_as_codec_lines_in_order(tmp_path):
    path = tmp_path / "out.jsonl"
    with JsonlSink(str(path)) as sink:
        sink.write(PACKET)
        sink.write(FLOW)
        sink.write(MESSAGE)
    assert lines(path) == [encode_line(PACKET), encode_line(FLOW), encode_line(MESSAGE)]
    assert [json.loads(line)["record_type"] for line in lines(path)] == [
        "packet",
        "flow",
        "message",
    ]


def test_flow_records_go_to_the_flows_path(tmp_path):
    out = tmp_path / "out.jsonl"
    flows = tmp_path / "flows.jsonl"
    with JsonlSink(str(out), flows_path=str(flows)) as sink:
        sink.write(PACKET)
        sink.write(FLOW)
        sink.write(MESSAGE)
    assert lines(out) == [encode_line(PACKET), encode_line(MESSAGE)]
    assert lines(flows) == [encode_line(FLOW)]


def test_stdout_is_the_default_and_stays_open(capsys):
    sink = JsonlSink()
    sink.write(PACKET)
    sink.close()
    assert not sys.stdout.closed
    print("after")
    assert capsys.readouterr().out == encode_line(PACKET) + "\nafter\n"


def test_file_output_is_flushed_every_n_records(tmp_path):
    path = tmp_path / "out.jsonl"
    sink = JsonlSink(str(path), flush_every=2)
    sink.write(PACKET)
    assert path.read_text(encoding="utf-8") == ""
    sink.write(PACKET)
    assert len(lines(path)) == 2
    sink.write(PACKET)
    sink.close()
    assert len(lines(path)) == 3


def test_unwritable_path_raises_oserror(tmp_path):
    with pytest.raises(OSError):
        JsonlSink(str(tmp_path / "missing" / "out.jsonl"))


def test_unwritable_flows_path_raises_and_closes_the_main_output(tmp_path):
    out = tmp_path / "out.jsonl"
    with pytest.raises(OSError):
        JsonlSink(str(out), flows_path=str(tmp_path / "missing" / "flows.jsonl"))
    assert out.read_text(encoding="utf-8") == ""
