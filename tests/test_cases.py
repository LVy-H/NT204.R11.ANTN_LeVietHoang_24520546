from __future__ import annotations

import base64
import importlib.util
import json
import sys
from collections import Counter
from dataclasses import dataclass, fields
from pathlib import Path

import pytest

from ids.cli import main
from ids.model import HttpMessage, Ipv4Info

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


def json_keys(cls: type) -> list[str]:
    return [f.metadata.get("json", f.name) for f in fields(cls)]


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


def test_t04_invalid_utf8_body_is_partial_and_the_next_packet_is_clean(run_case):
    run = run_case(FLOW_FIXTURES / "T04-invalid-charset.pcap")
    broken, valid = run.packets

    assert run.exit_code == 0
    body = broken["decoded"]["body"]
    assert body["text"] == "ok \ufffd\ufffd bad \ufffd"
    assert body["charset"] == "utf-8"
    assert body["status"] == "partial"
    assert body["invalid_byte_count"] == 4
    assert body["first_invalid_offset"] == 3
    assert [(i["stage"], i["code"], i["context"]) for i in broken["issues"]] == [
        (
            "decoder",
            "invalid_charset_bytes",
            {"field": "body", "invalid_byte_count": 4, "first_invalid_offset": 3},
        )
    ]
    assert broken["preprocess_status"] == "partial"
    assert broken["processing_action"] == "mark"
    assert broken["reason"] == ["decoder/invalid_charset_bytes", "decode_partial:body"]

    assert valid["decoded"]["body"]["text"] == "chào"
    assert valid["decoded"]["body"]["status"] == "decoded"
    assert valid["issues"] == []
    assert valid["preprocess_status"] == "valid"
    assert valid["processing_action"] == "forward"


T05_HTTP_NORMALIZED = {
    "timestamp": 1759000000.5,
    "timestamp_iso": "2025-09-27T19:06:40.500000Z",
    "network_protocol": "IPv4",
    "protocol": "TCP",
    "application_protocol": "HTTP",
    "src_ip": "10.0.0.1",
    "dst_ip": "10.0.0.2",
    "src_port": 51234,
    "dst_port": 80,
    "http": {
        "method": "GET",
        "scheme": None,
        "host": "www.example.com",
        "port": 8080,
        "path": "/Docs/B/index.html",
        "headers": {
            "host": ["WWW.Example.COM:8080"],
            "user-agent": ["Mixed/1.0"],
            "accept": ["*/*"],
        },
    },
    "dns": None,
    "smtp": None,
}
T05_DNS_NORMALIZED = {
    "timestamp": 1759000001.0,
    "timestamp_iso": "2025-09-27T19:06:41.000000Z",
    "network_protocol": "IPv4",
    "protocol": "UDP",
    "application_protocol": "DNS",
    "src_ip": "10.0.0.1",
    "dst_ip": "10.0.0.2",
    "src_port": 40000,
    "dst_port": 53,
    "http": None,
    "dns": {"names": ["www.example.com"]},
    "smtp": None,
}


def test_t05_every_spelling_normalizes_to_the_same_values(run_case):
    capture = run_case(FLOW_FIXTURES / "T05-normalize-pcap.pcap")
    loaded = run_case(FLOW_FIXTURES / "T05-normalize-events.jsonl")
    http_packet, dns_packet = capture.packets

    assert (capture.exit_code, loaded.exit_code) == (0, 0)
    assert http_packet["normalized"] == T05_HTTP_NORMALIZED
    assert dns_packet["normalized"] == T05_DNS_NORMALIZED
    assert [loaded.packet(i)["normalized"] for i in (1, 2, 3)] == [T05_HTTP_NORMALIZED] * 3
    assert loaded.packet(4)["normalized"] == T05_DNS_NORMALIZED
    # raw fields keep the original spelling
    assert loaded.packet(2)["src_ip"] == "010.000.000.001"
    assert loaded.packet(2)["application"]["message"]["headers"][0]["name"] == "host"
    assert http_packet["application"]["message"]["uri"] == "/Docs/./a/../B//index.html"
    assert [(p["preprocess_status"], p["reason"]) for p in capture.packets] == [
        ("valid", []),
        ("valid", []),
    ]
    assert [(p["preprocess_status"], p["reason"]) for p in loaded.packets] == [
        ("valid", []),
        ("partial", ["ip_normalized"]),
        ("partial", ["timestamp_scaled"]),
        ("valid", []),
    ]


def test_t06_events_missing_optional_fields_load_with_the_full_key_set(run_case):
    run = run_case(FLOW_FIXTURES / "T06-missing-fields.jsonl")
    flat, nested, http = run.packets

    assert run.exit_code == 0
    assert [p["packet_id"] for p in run.packets] == [1, 2, 3]
    assert all(list(p) == PACKET_KEYS for p in run.packets)
    assert [(p["preprocess_status"], p["reason"]) for p in run.packets] == [("valid", [])] * 3
    assert all(p["issues"] == [] for p in run.packets)
    assert all(p["link"] is None for p in run.packets)
    assert all(p["flow"] is not None for p in run.packets)

    assert flat["application"] is None
    assert flat["application_protocol"] == "UNKNOWN"
    assert list(flat["network"]) == json_keys(Ipv4Info)
    assert flat["network"]["options"] == []
    assert flat["protocol"] == "TCP"

    assert list(nested["network"]) == json_keys(Ipv4Info)
    assert nested["network"]["options"] == []
    assert nested["protocol"] == "UDP"

    message = http["application"]["message"]
    assert list(message) == json_keys(HttpMessage)
    assert message["headers"] == []
    assert message["body"] is None
    assert http["event_type"] == "http_request"


def test_t07_three_way_handshake_establishes_one_flow(run_case):
    run = run_case(FLOW_FIXTURES / "T07-tcp-handshake.pcap")
    (flow,) = run.flows

    assert run.exit_code == 0
    assert [p["flow"]["flow_id"] for p in run.packets] == [flow["flow_id"]] * 3
    assert [p["flow"]["state"] for p in run.packets] == ["HANDSHAKE", "HANDSHAKE", "ESTABLISHED"]
    assert [p["flow"]["direction"] for p in run.packets] == ["forward", "backward", "forward"]
    assert [p["flow"]["flow_packet_index"] for p in run.packets] == [1, 2, 3]
    assert flow["protocol"] == "TCP"
    assert flow["endpoint_a"] == {"ip": "10.0.0.1", "port": 51234}
    assert flow["endpoint_b"] == {"ip": "10.0.0.2", "port": 9000}
    assert flow["tcp"] == {
        "state": "ESTABLISHED",
        "syn_count": 2,
        "ack_count": 2,
        "fin_count": 0,
        "rst_count": 0,
        "handshake_complete": True,
        "midstream": False,
    }
    assert (flow["packet_count"], flow["byte_count"], flow["payload_byte_count"]) == (3, 120, 0)
    assert (flow["start_time"], flow["last_seen"], flow["duration"]) == (at(0), at(20), 0.02)
    assert (flow["first_packet_id"], flow["last_packet_id"]) == (1, 3)
    assert flow["end_reason"] == "end_of_input"


def test_t08_both_directions_share_one_flow_id(run_case):
    run = run_case(FLOW_FIXTURES / "T08-tcp-bidirectional.pcap")
    (flow,) = run.flows

    assert run.exit_code == 0
    assert {p["flow"]["flow_id"] for p in run.packets} == {flow["flow_id"]}
    expected = ["forward" if p["src_ip"] == "10.0.0.1" else "backward" for p in run.packets]
    assert [p["flow"]["direction"] for p in run.packets] == expected
    assert expected == [
        "forward",
        "backward",
        "forward",
        "forward",
        "backward",
        "backward",
        "forward",
    ]
    assert flow["forward"] == {"packet_count": 4, "byte_count": 173, "payload_byte_count": 13}
    assert flow["backward"] == {"packet_count": 3, "byte_count": 157, "payload_byte_count": 37}
    assert (flow["packet_count"], flow["byte_count"], flow["payload_byte_count"]) == (7, 330, 50)
    assert flow["tcp"]["state"] == "ESTABLISHED"


def test_t09_graceful_close_and_reset_end_their_flows(run_case):
    run = run_case(FLOW_FIXTURES / "T09-tcp-close-reset.pcap")
    graceful = run.flow(run.packet(1)["flow"]["flow_id"])
    aborted = run.flow(run.packet(9)["flow"]["flow_id"])

    assert run.exit_code == 0
    assert [run.packet(i)["flow"]["state"] for i in range(1, 9)] == [
        "HANDSHAKE",
        "HANDSHAKE",
        "ESTABLISHED",
        "ESTABLISHED",
        "CLOSING",
        "CLOSING",
        "CLOSING",
        "CLOSED",
    ]
    assert graceful["tcp"] == {
        "state": "CLOSED",
        "syn_count": 2,
        "ack_count": 7,
        "fin_count": 2,
        "rst_count": 0,
        "handshake_complete": True,
        "midstream": False,
    }
    assert graceful["end_reason"] == "closed"
    assert (graceful["packet_count"], graceful["byte_count"]) == (8, 324)

    assert [run.packet(i)["flow"]["state"] for i in range(9, 13)] == [
        "HANDSHAKE",
        "HANDSHAKE",
        "ESTABLISHED",
        "RESET",
    ]
    assert aborted["tcp"]["state"] == "RESET"
    assert aborted["tcp"]["rst_count"] == 1
    assert aborted["end_reason"] == "reset"
    assert (aborted["packet_count"], aborted["first_packet_id"], aborted["last_packet_id"]) == (
        4,
        9,
        12,
    )


def test_t09_syn_reusing_a_closed_five_tuple_starts_a_new_flow(run_case):
    run = run_case(FLOW_FIXTURES / "T09-tcp-close-reset.pcap")
    graceful_id = run.packet(1)["flow"]["flow_id"]
    reused = run.packet(13)

    assert reused["flow"]["flow_id"] != graceful_id
    assert reused["flow"]["flow_packet_index"] == 1
    assert reused["flow"]["state"] == "HANDSHAKE"
    # the lingering closed flow is exported before the SYN that replaces it
    assert run.position(run.flow(graceful_id)) < run.position(reused)
    replacement = run.flow(reused["flow"]["flow_id"])
    assert replacement["tcp"]["state"] == "ESTABLISHED"
    assert (replacement["first_packet_id"], replacement["last_packet_id"]) == (13, 15)
    assert replacement["end_reason"] == "end_of_input"
    assert len(run.flows) == 3


def test_t10_dns_query_and_response_form_one_udp_flow(run_case):
    run = run_case(FLOW_FIXTURES / "T10-udp-dns-flow.pcap")
    (flow,) = run.flows

    assert run.exit_code == 0
    assert [p["event_type"] for p in run.packets] == ["dns_query", "dns_response"]
    assert [p["flow"]["state"] for p in run.packets] == [None, None]
    assert [p["flow"]["direction"] for p in run.packets] == ["forward", "backward"]
    assert flow["protocol"] == "UDP"
    assert flow["application_protocol"] == "DNS"
    assert flow["tcp"] is None
    assert flow["packet_count"] == 2
    assert flow["byte_count"] == sum(p["network"]["total_length"] for p in run.packets) == 141
    assert flow["forward"] == {"packet_count": 1, "byte_count": 57, "payload_byte_count": 29}
    assert flow["backward"] == {"packet_count": 1, "byte_count": 84, "payload_byte_count": 56}
    assert flow["end_reason"] == "end_of_input"


def test_t11_interleaved_flows_are_counted_separately(run_case):
    run = run_case(FLOW_FIXTURES / "T11-interleaved-flows.pcap")
    by_flow: dict[str, list[int]] = {}
    for packet in run.packets:
        by_flow.setdefault(packet["flow"]["flow_id"], []).append(packet["packet_id"])

    assert run.exit_code == 0
    assert sorted(by_flow.values()) == [[1, 4, 7, 9, 12], [2, 5, 8, 11], [3, 6, 10]]
    summary = {
        (
            flow["protocol"],
            flow["endpoint_a"]["ip"],
            flow["endpoint_a"]["port"],
            flow["endpoint_b"]["port"],
        ): (flow["packet_count"], flow["byte_count"], flow["payload_byte_count"])
        for flow in run.flows
    }
    assert summary == {
        ("TCP", "10.0.0.1", 51234, 9000): (5, 218, 18),
        ("TCP", "10.0.0.3", 51300, 9000): (4, 167, 7),
        ("UDP", "10.0.0.1", 40000, 5000): (3, 99, 15),
    }
    for flow in run.flows:
        assert by_flow[flow["flow_id"]][0] == flow["first_packet_id"]
        assert by_flow[flow["flow_id"]][-1] == flow["last_packet_id"]
    indexes = [p["flow"]["flow_packet_index"] for p in run.packets]
    assert indexes == [1, 1, 1, 2, 2, 2, 3, 3, 4, 3, 4, 5]


def test_t12_idle_udp_flow_is_exported_before_the_packet_that_expires_it(run_case):
    run = run_case(FLOW_FIXTURES / "T12-udp-idle-timeout.pcap")
    first, later = run.flows

    assert run.exit_code == 0
    # a gap of exactly 60 s (packet 2 -> 3) keeps the flow alive; 61 s (3 -> 4) expires it
    assert [p["flow"]["flow_id"] for p in run.packets[:3]] == [first["flow_id"]] * 3
    assert first["end_reason"] == "idle_timeout"
    assert (first["packet_count"], first["last_packet_id"], first["last_seen"]) == (
        3,
        3,
        at(61000),
    )
    assert run.position(run.packet(3)) < run.position(first) < run.position(run.packet(4))
    assert run.packet(4)["flow"]["flow_id"] == later["flow_id"] != first["flow_id"]
    assert later["end_reason"] == "end_of_input"
    assert run.stats["active_flows"] == 1
    assert run.stats["flow_end_reasons"] == {"idle_timeout": 1, "end_of_input": 1}


def test_t13_flow_counters_match_the_packet_mix(run_case):
    run = run_case(FLOW_FIXTURES / "T13-tcp-flow-stats.pcap")
    (flow,) = run.flows

    assert run.exit_code == 0
    assert (flow["packet_count"], flow["byte_count"], flow["payload_byte_count"]) == (11, 790, 350)
    assert flow["forward"] == {"packet_count": 7, "byte_count": 430, "payload_byte_count": 150}
    assert flow["backward"] == {"packet_count": 4, "byte_count": 360, "payload_byte_count": 200}
    assert flow["tcp"] == {
        "state": "CLOSED",
        "syn_count": 2,
        "ack_count": 10,
        "fin_count": 2,
        "rst_count": 0,
        "handshake_complete": True,
        "midstream": False,
    }
    assert (flow["start_time"], flow["last_seen"], flow["duration"]) == (at(0), at(2500), 2.5)
    assert (flow["first_packet_id"], flow["last_packet_id"]) == (1, 11)
    assert flow["end_reason"] == "closed"
