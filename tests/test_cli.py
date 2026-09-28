import json
from pathlib import Path

import pytest

from pcparser.cli import main

FIXTURES = Path(__file__).resolve().parents[1] / "TEST" / "fixtures"
HANDSHAKE = str(FIXTURES / "01-tcp-handshake.pcap")
HTTP_GET = str(FIXTURES / "04-http-get.pcap")
UNKNOWN = str(FIXTURES / "11-unknown-protocol.pcap")


def test_cli_writes_jsonl_to_a_file(tmp_path, capsys):
    output = tmp_path / "out.jsonl"
    assert main(["--pcap", HANDSHAKE, "--output", str(output)]) == 0
    lines = output.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 3
    events = [json.loads(line) for line in lines]
    assert [event["packet_id"] for event in events] == [1, 2, 3]
    assert events[0]["event_type"] == "tcp_segment"
    assert capsys.readouterr().out == ""


def test_cli_defaults_to_stdout(capsys):
    assert main(["--pcap", HANDSHAKE]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 3
    assert json.loads(lines[0])["capture"]["source"] == "pcap"


def test_cli_stats_go_to_stderr(tmp_path, capsys):
    output = tmp_path / "out.jsonl"
    assert main(["-r", HANDSHAKE, "-o", str(output), "--stats"]) == 0
    error_output = capsys.readouterr().err
    assert "parsed 3 events from 3 packets" in error_output
    summary = json.loads(error_output[error_output.index("{\n") :])
    assert summary["events_written"] == 3
    assert summary["source"]["format"] == "pcap"
    assert summary["event_types"] == {"tcp_segment": 3}


def test_cli_quiet_suppresses_progress(tmp_path, capsys):
    assert main(["-r", HANDSHAKE, "-o", str(tmp_path / "o.jsonl"), "-q"]) == 0
    assert capsys.readouterr().err == ""


def test_cli_count_limits_packets(tmp_path):
    output = tmp_path / "out.jsonl"
    assert main(["-r", HANDSHAKE, "-c", "2", "-o", str(output)]) == 0
    assert len(output.read_text(encoding="utf-8").splitlines()) == 2


def test_cli_unknown_policy_skip(tmp_path):
    output = tmp_path / "out.jsonl"
    assert main(["-r", HTTP_GET, "-o", str(output), "--unknown-policy", "skip"]) == 0
    events = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    assert [event["event_type"] for event in events] == ["http_request"]


def test_cli_reports_a_missing_capture_file(capsys):
    assert main(["--pcap", "/nonexistent/nope.pcap"]) == 1
    assert "error:" in capsys.readouterr().err


def test_cli_reports_an_unknown_interface(capsys):
    assert main(["--interface", "definitely-not-an-interface"]) == 1
    assert "not found" in capsys.readouterr().err


def test_cli_list_interfaces(capsys):
    assert main(["--list-interfaces"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines
    assert any(line.startswith("lo") for line in lines)


def test_cli_requires_exactly_one_source(capsys):
    with pytest.raises(SystemExit) as caught:
        main([])
    assert caught.value.code == 2
    with pytest.raises(SystemExit) as caught:
        main(["--pcap", HANDSHAKE, "--interface", "lo"])
    assert caught.value.code == 2


def test_cli_rejects_an_unknown_policy():
    with pytest.raises(SystemExit) as caught:
        main(["--pcap", HANDSHAKE, "--unknown-policy", "nope"])
    assert caught.value.code == 2


def test_cli_version(capsys):
    with pytest.raises(SystemExit) as caught:
        main(["--version"])
    assert caught.value.code == 0
    assert capsys.readouterr().out.strip() == "pcparser 0.1.0"


def test_cli_malformed_fixture_exits_cleanly(tmp_path, capsys):
    output = tmp_path / "malformed.jsonl"
    assert main(["-r", str(FIXTURES / "12-malformed.pcap"), "-o", str(output)]) == 0
    assert len(output.read_text(encoding="utf-8").splitlines()) == 14
    assert "warning:" in capsys.readouterr().err


def test_cli_skip_policy_on_the_unknown_fixture(tmp_path):
    output = tmp_path / "unknown.jsonl"
    assert main(["-r", UNKNOWN, "-o", str(output), "--unknown-policy", "skip"]) == 0
    assert output.read_text(encoding="utf-8") == ""
