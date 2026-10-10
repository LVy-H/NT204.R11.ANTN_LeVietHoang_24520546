from __future__ import annotations

import base64
import importlib.util
import json
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import pytest

from ids.cli import main

ROOT = Path(__file__).resolve().parents[1]
FLOW_TRACKER = Path("TEST/flow-tracker")
FLOW_FIXTURES = FLOW_TRACKER / "fixtures"
INPUT_SUFFIXES = {".pcap", ".pcapng", ".jsonl"}
ALL_FIXTURES = sorted(
    path.relative_to(ROOT)
    for path in ROOT.glob("TEST/*/fixtures/*")
    if path.suffix in INPUT_SUFFIXES
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


BASE_TIME = 1759000000


def at(offset_ms: int) -> float:
    """Timestamp the pcap reader yields for a fixture frame at `offset_ms`."""
    return (BASE_TIME + offset_ms // 1000) + (offset_ms % 1000) * 1000 / 1_000_000


@dataclass
class CaseRun:
    exit_code: int
    records: list[dict]
    stats: dict
    stderr: str

    def of(self, record_type: str) -> list[dict]:
        return [record for record in self.records if record["record_type"] == record_type]

    @property
    def packets(self) -> list[dict]:
        return self.of("packet")

    @property
    def messages(self) -> list[dict]:
        return self.of("message")

    @property
    def flows(self) -> list[dict]:
        return self.of("flow")

    def packet(self, packet_id: int) -> dict:
        (found,) = [p for p in self.packets if p["packet_id"] == packet_id]
        return found

    def flow(self, flow_id: str) -> dict:
        (found,) = [f for f in self.flows if f["flow_id"] == flow_id]
        return found

    def position(self, record: dict) -> int:
        return next(i for i, item in enumerate(self.records) if item is record)


def source_flag(fixture: Path) -> str:
    return "--events" if fixture.suffix == ".jsonl" else "--pcap"


def stats_of(stderr: str) -> dict:
    """The `--stats` JSON object, which starts at the first "{\\n" of stderr."""
    return json.loads(stderr[stderr.index("{\n") :])


@pytest.fixture
def run_case(tmp_path, capsys, monkeypatch):
    """Run one fixture through `ids.cli.main` exactly as TEST/run_cases.sh does, in-process.

    All records go to one stream (no --flows-output) so tests can check the order of
    flow, message and packet records.
    """
    monkeypatch.chdir(ROOT)

    def run(fixture: Path) -> CaseRun:
        assert (ROOT / fixture).is_file(), f"missing fixture {fixture}"
        output = tmp_path / f"{fixture.stem}.jsonl"
        capsys.readouterr()
        code = main([source_flag(fixture), str(fixture), "--output", str(output), "--stats", "-q"])
        stderr = capsys.readouterr().err
        records = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
        return CaseRun(code, records, stats_of(stderr), stderr)

    return run


@pytest.fixture(scope="session")
def generator():
    path = ROOT / FLOW_TRACKER / "generate_fixtures.py"
    spec = importlib.util.spec_from_file_location("flow_tracker_fixtures", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses resolve annotations through sys.modules
    spec.loader.exec_module(module)
    return module


def test_fixture_generator_reproduces_every_committed_fixture(generator):
    committed = {path.name: path.read_bytes() for path in (ROOT / FLOW_FIXTURES).glob("*")}
    assert sorted(committed) == sorted(generator.CASES)
    for name in generator.CASES:
        assert generator.build(name) == committed[name], name


@pytest.mark.parametrize("fixture", ALL_FIXTURES, ids=str)
def test_every_fixture_yields_one_outcome_per_input(run_case, fixture):
    run = run_case(fixture)

    assert run.exit_code == 0
    assert all(record["schema_version"] == 2 for record in run.records)
    assert {record["record_type"] for record in run.records} <= {"packet", "message", "flow"}
    assert all(list(packet) == PACKET_KEYS for packet in run.packets)
    assert (
        len(run.packets) + run.stats["dropped"] + run.stats["skipped"] == run.stats["packets_seen"]
    )
    tracked = Counter(p["flow"]["flow_id"] for p in run.packets if p["flow"] is not None)
    assert tracked == {flow["flow_id"]: flow["packet_count"] for flow in run.flows}


def test_t01_url_and_query_are_percent_decoded_once(run_case):
    run = run_case(FLOW_FIXTURES / "T01-http-url-decode.pcap")
    (packet,) = run.packets
    raw_uri = "/search%20page?q=%27%20OR%201%3D1&x=a+b"

    assert run.exit_code == 0
    assert packet["application"]["message"]["uri"] == raw_uri
    assert base64.b64decode(packet["payload"]["data_b64"]).startswith(
        f"GET {raw_uri} HTTP/1.1\r\n".encode()
    )
    assert packet["decoded"]["uri"] == {
        "text": "/search page?q=' OR 1=1&x=a b",
        "path": "/search page",
        "query": "q=' OR 1=1&x=a b",
        "params": [["q", "' OR 1=1"], ["x", "a b"]],
        "status": "decoded",
        "double_encoded": False,
    }
    assert packet["decoded"]["form"] is None
    assert packet["decoded"]["body"] is None
    assert packet["decoded"]["status"] == "decoded"
    assert packet["normalized"]["http"]["path"] == "/search page"
    assert packet["preprocess_status"] == "valid"
    assert packet["reason"] == []


def test_t02_html_entities_are_decoded_and_unknown_ones_kept(run_case):
    run = run_case(FLOW_FIXTURES / "T02-html-entities.pcap")
    (packet,) = run.packets

    assert run.exit_code == 0
    assert packet["application"]["message"]["kind"] == "response"
    assert packet["decoded"]["uri"] is None
    assert packet["decoded"]["body"] == {
        "text": "<script>alert(1)</script> & ' &bogus;",
        "charset": "ascii",
        "status": "decoded",
        "invalid_byte_count": 0,
        "first_invalid_offset": None,
        "truncated": False,
        "entity_count": 6,
    }
    assert packet["decoded"]["status"] == "decoded"
    assert packet["issues"] == []
    assert packet["preprocess_status"] == "valid"


T03_HEADERS = {
    "subject": "Báo cáo tuần",
    "from": "Alice <alice@example.test>",
    "to": "Bob <bob@example.test>",
    "cc": None,
    "date": None,
    "message_id": None,
}
T03_MULTIPART_PARTS = [
    {
        "index": 0,
        "content_type": "text/plain",
        "charset": "utf-8",
        "transfer_encoding": "base64",
        "filename": None,
        "size": 35,
        "sha256": "1e78af1dac7301009561066b6a2ed3c851329bc274c34e672fce9f2b7a5c5e46",
        "text": "Xin chào, đây là phần Base64.",
        "status": "decoded",
        "truncated": False,
    },
    {
        "index": 1,
        "content_type": "text/plain",
        "charset": "utf-8",
        "transfer_encoding": "quoted-printable",
        "filename": None,
        "size": 26,
        "sha256": "dad562aa03eba1334b75bb2ad0377e70dbdd360fef611294966bb6d302a14a9c",
        "text": "Café = 3 euro, softbreak.",
        "status": "decoded",
        "truncated": False,
    },
]
T03_SINGLE_PART = {
    "index": 0,
    "content_type": "text/plain",
    "charset": "utf-8",
    "transfer_encoding": "quoted-printable",
    "filename": None,
    "size": 41,
    "sha256": "e9424246ed8150d13a07d1e86c919aadc274cf54617827d882402fb17acbd309",
    "text": "Giờ họp lúc 9h.\r\n.dot-stuffed line\r\n",
    "status": "decoded",
    "truncated": False,
}


def test_t03_split_smtp_message_is_reassembled_and_mime_decoded(run_case, generator):
    run = run_case(FLOW_FIXTURES / "T03-smtp-mime.pcap")
    assert len(run.messages) == 2
    first = run.messages[0]
    (flow,) = run.flows
    flow_id = flow["flow_id"]

    assert run.exit_code == 0
    assert flow["application_protocol"] == "SMTP"
    assert first["message_id"] == f"{flow_id}-1"
    assert first["flow_id"] == flow_id
    assert first["protocol"] == "SMTP"
    assert first["packet_ids"] == [13, 14]
    assert first["start_time"] == at(120)
    assert first["end_time"] == at(130)
    assert base64.b64decode(first["data_b64"]) == generator.t03_multipart_message()
    assert (first["complete"], first["truncated"], first["gap"]) == (True, False, False)
    assert first["decoded"]["headers"] == T03_HEADERS
    assert first["decoded"]["parts"] == T03_MULTIPART_PARTS
    assert first["decoded"]["status"] == "decoded"
    assert first["preprocess_status"] == "valid"
    assert first["reason"] == []
    # emitted while the segment holding "\r\n.\r\n" is processed, before its packet record
    assert run.position(run.packet(13)) < run.position(first) < run.position(run.packet(14))
    assert run.stats["messages"] == {"complete": 2, "incomplete": 0}


def test_t03_single_segment_message_is_decoded_at_packet_level(run_case):
    run = run_case(FLOW_FIXTURES / "T03-smtp-mime.pcap")
    packet = run.packet(18)
    second = run.messages[1]

    assert packet["application"]["message"]["kind"] == "data"
    assert packet["decoded"]["kind"] == "mime"
    assert packet["decoded"]["headers"]["subject"] == "single segment"
    assert packet["decoded"]["parts"] == [T03_SINGLE_PART]
    assert packet["decoded"]["status"] == "decoded"
    assert packet["preprocess_status"] == "valid"
    assert second["packet_ids"] == [18]
    assert second["decoded"]["parts"] == [T03_SINGLE_PART]
