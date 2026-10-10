from __future__ import annotations

import base64
import itertools
import json
from pathlib import Path

import pytest
from fake_scapy import FakeScapy

from ids import __version__
from ids.capture import PcapSource, live
from ids.cli import main

FIXTURES = Path(__file__).resolve().parents[1] / "TEST" / "fixtures"
HANDSHAKE = str(FIXTURES / "01-tcp-handshake.pcap")
TCP_DATA = str(FIXTURES / "02-tcp-data.pcap")
HTTP_GET = str(FIXTURES / "04-http-get.pcap")
UNKNOWN = str(FIXTURES / "11-unknown-protocol.pcap")
MALFORMED = str(FIXTURES / "12-malformed.pcap")


def records(text):
    return [json.loads(line) for line in text.splitlines()]


def packet_records(text):
    """Later plans add flow and message records to the same stream; keep packets only."""
    return [record for record in records(text) if record["record_type"] == "packet"]


def packets(path):
    return packet_records(Path(path).read_text(encoding="utf-8"))


def summary_of(err):
    return json.loads(err[err.index("{\n") :])


def test_cli_writes_jsonl_to_a_file(tmp_path, capsys):
    output = tmp_path / "out.jsonl"
    assert main(["--pcap", HANDSHAKE, "--output", str(output)]) == 0
    events = packets(output)
    assert [event["packet_id"] for event in events] == [1, 2, 3]
    assert events[0]["event_type"] == "tcp_segment"
    assert events[0]["schema_version"] == 2
    assert capsys.readouterr().out == ""


def test_cli_defaults_to_stdout(capsys):
    assert main(["--pcap", HANDSHAKE]) == 0
    events = packet_records(capsys.readouterr().out)
    assert len(events) == 3
    assert events[0]["capture"]["source"] == "pcap"


def test_cli_stats_go_to_stderr(tmp_path, capsys):
    assert main(["-r", HANDSHAKE, "-o", str(tmp_path / "out.jsonl"), "--stats"]) == 0
    err = capsys.readouterr().err
    assert err.startswith(f"source: pcap {HANDSHAKE}\n")
    assert "from 3 packets (0 dropped, 0 skipped, 0 with issues)" in err
    summary = summary_of(err)
    assert summary["records_written"]["packet"] == 3
    assert summary["packets_seen"] == 3
    assert summary["event_types"] == {"tcp_segment": 3}
    assert summary["source"]["format"] == "pcap"


def test_cli_quiet_with_stats_prints_only_the_summary(tmp_path, capsys):
    assert main(["-r", HANDSHAKE, "-o", str(tmp_path / "o.jsonl"), "-q", "--stats"]) == 0
    assert json.loads(capsys.readouterr().err)["packets_seen"] == 3


def test_cli_quiet_suppresses_status_lines(tmp_path, capsys):
    assert main(["-r", HANDSHAKE, "-o", str(tmp_path / "o.jsonl"), "-q"]) == 0
    assert capsys.readouterr().err == ""


def test_cli_count_limits_packets(tmp_path):
    output = tmp_path / "out.jsonl"
    assert main(["-r", HANDSHAKE, "-c", "2", "-o", str(output)]) == 0
    assert len(packets(output)) == 2


def test_cli_unknown_policy_skip(tmp_path):
    output = tmp_path / "out.jsonl"
    assert main(["-r", HTTP_GET, "-o", str(output), "--unknown-policy", "skip"]) == 0
    assert [event["event_type"] for event in packets(output)] == ["http_request"]


def test_cli_skip_policy_on_the_unknown_fixture(tmp_path):
    output = tmp_path / "unknown.jsonl"
    assert main(["-r", UNKNOWN, "-o", str(output), "--unknown-policy", "skip"]) == 0
    assert packets(output) == []


def test_cli_limits_payload_bytes_and_preview(tmp_path):
    output = tmp_path / "out.jsonl"
    argv = ["-r", TCP_DATA, "-o", str(output), "--max-payload-bytes", "4", "--preview-limit", "2"]
    assert main(argv) == 0
    payload = packets(output)[0]["payload"]
    assert base64.b64decode(payload["data_b64"]) == b"PAYL"
    assert payload["data_truncated"] is True
    assert payload["preview"] == "PA"
    assert payload["length"] == 29


def test_cli_malformed_fixture_exits_cleanly(tmp_path, capsys):
    output = tmp_path / "malformed.jsonl"
    assert main(["-r", MALFORMED, "-o", str(output)]) == 0
    assert len(packets(output)) == 14
    assert "warning:" in capsys.readouterr().err


def test_cli_reports_a_missing_capture_file(capsys):
    assert main(["--pcap", "/nonexistent/nope.pcap"]) == 1
    assert "error:" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("content", "message"),
    [
        (b"", "capture file is empty"),
        (b"NOPE" + b"\x00" * 40, "unrecognised capture file format"),
    ],
)
def test_cli_reports_a_broken_capture_file(tmp_path, capsys, content, message):
    capture = tmp_path / "broken.pcap"
    capture.write_bytes(content)
    output = tmp_path / "out.jsonl"
    assert main(["-r", str(capture), "-o", str(output)]) == 1
    err = capsys.readouterr().err
    assert f"error: {message}\n" in err
    assert "Traceback" not in err
    assert output.read_text(encoding="utf-8") == ""


def test_cli_reports_an_unwritable_output_path(tmp_path, capsys):
    assert main(["-r", HANDSHAKE, "-o", str(tmp_path / "missing" / "out.jsonl")]) == 1
    err = capsys.readouterr().err
    assert "error:" in err
    assert "Traceback" not in err


def test_cli_reports_an_unknown_interface(capsys):
    assert main(["--interface", "definitely-not-an-interface"]) == 1
    assert "not found" in capsys.readouterr().err


def test_cli_capture_idle_timeout_stops_live_capture(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(live, "scapy_module", lambda: FakeScapy())
    output = tmp_path / "live.jsonl"
    assert main(["-i", "eth0", "--capture-idle-timeout", "0.05", "-o", str(output)]) == 0
    assert "without traffic" in capsys.readouterr().err
    assert packets(output) == []


def test_cli_interrupt_flushes_and_exits_130(tmp_path, monkeypatch, capsys):
    original = PcapSource.items

    def interrupted(self):
        yield from itertools.islice(original(self), 1)
        raise KeyboardInterrupt

    monkeypatch.setattr(PcapSource, "items", interrupted)
    output = tmp_path / "out.jsonl"
    assert main(["-r", HANDSHAKE, "-o", str(output)]) == 130
    assert [event["packet_id"] for event in packets(output)] == [1]
    assert "interrupted" in capsys.readouterr().err


def test_cli_list_interfaces(capsys):
    assert main(["--list-interfaces"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines
    assert any(line.startswith("lo") for line in lines)


def test_cli_requires_exactly_one_source():
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


@pytest.mark.parametrize(
    "argv",
    [
        ["--count", "0"],
        ["--count", "-1"],
        ["--count", "many"],
        ["--max-payload-bytes", "-5"],
        ["--preview-limit", "-1"],
        ["--capture-idle-timeout", "-0.5"],
        ["--capture-idle-timeout", "nan"],
        ["--capture-idle-timeout", "inf"],
    ],
)
def test_cli_rejects_bad_numbers(argv, capsys):
    with pytest.raises(SystemExit) as caught:
        main(["--pcap", HANDSHAKE, *argv])
    assert caught.value.code == 2
    assert argv[0] in capsys.readouterr().err


def test_cli_version(capsys):
    with pytest.raises(SystemExit) as caught:
        main(["--version"])
    assert caught.value.code == 0
    assert capsys.readouterr().out.strip() == f"ids {__version__}"
