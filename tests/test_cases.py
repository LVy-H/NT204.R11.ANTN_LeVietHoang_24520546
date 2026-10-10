from __future__ import annotations

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
