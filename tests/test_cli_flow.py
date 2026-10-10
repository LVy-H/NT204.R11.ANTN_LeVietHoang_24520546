from __future__ import annotations

import base64
import json

import pytest
from golden import CLIENT_MAC, SERVER_MAC
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from ids.cli import build_parser, main

T0 = 1759000000.0
CLIENT = ("10.0.0.1", 53000)
RESOLVER = ("10.0.0.53", 53)


def frame(timestamp, src, dst, layer4, payload=b""):
    packet = Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IP(src=src[0], dst=dst[0]) / layer4
    if payload:
        packet = packet / payload
    packet.time = timestamp
    return packet


def udp_frame(timestamp, src, dst, payload=b"ping"):
    return frame(timestamp, src, dst, UDP(sport=src[1], dport=dst[1]), payload)


def tcp_frame(timestamp, src, dst, flags, seq, ack, payload=b""):
    layer4 = TCP(sport=src[1], dport=dst[1], flags=flags, seq=seq, ack=ack)
    return frame(timestamp, src, dst, layer4, payload)


def run_cli(tmp_path, frames, *extra):
    pcap = tmp_path / "in.pcap"
    out = tmp_path / "out.jsonl"
    wrpcap(str(pcap), frames)
    assert main(["-r", str(pcap), "-o", str(out), "-q", *extra]) == 0
    return [json.loads(line) for line in out.read_text().splitlines()]


def test_flow_records_share_the_main_stream_by_default(tmp_path):
    records = run_cli(
        tmp_path, [udp_frame(T0, CLIENT, RESOLVER), udp_frame(T0 + 0.5, RESOLVER, CLIENT)]
    )
    assert [r["record_type"] for r in records] == ["packet", "packet", "flow"]
    assert records[2]["packet_count"] == 2
    assert records[2]["end_reason"] == "end_of_input"
    assert records[0]["flow"]["flow_id"] == records[2]["flow_id"]


def test_flows_output_moves_flow_records_to_their_own_file(tmp_path):
    flows = tmp_path / "flows.jsonl"
    records = run_cli(
        tmp_path,
        [udp_frame(T0, CLIENT, RESOLVER), udp_frame(T0 + 0.5, RESOLVER, CLIENT)],
        "--flows-output",
        str(flows),
    )
    assert [r["record_type"] for r in records] == ["packet", "packet"]
    flow_records = [json.loads(line) for line in flows.read_text().splitlines()]
    assert [r["record_type"] for r in flow_records] == ["flow"]
    assert flow_records[0]["flow_id"] == records[0]["flow"]["flow_id"]


def test_udp_idle_timeout_flag_splits_a_quiet_flow(tmp_path):
    frames = [udp_frame(T0, CLIENT, RESOLVER), udp_frame(T0 + 5, CLIENT, RESOLVER)]
    assert [r["record_type"] for r in run_cli(tmp_path, frames)] == ["packet", "packet", "flow"]
    records = run_cli(tmp_path, frames, "--udp-idle-timeout", "2")
    assert [r["record_type"] for r in records] == ["packet", "flow", "packet", "flow"]
    assert records[1]["end_reason"] == "idle_timeout"


def test_tcp_idle_timeout_flag_splits_a_quiet_connection(tmp_path):
    server = ("10.0.0.2", 8080)
    frames = [
        tcp_frame(T0, CLIENT, server, "S", 1, 0),
        tcp_frame(T0 + 10, server, CLIENT, "SA", 9, 2),
    ]
    records = run_cli(tmp_path, frames, "--tcp-idle-timeout", "5")
    flows = [r for r in records if r["record_type"] == "flow"]
    assert [f["end_reason"] for f in flows] == ["idle_timeout", "end_of_input"]


def test_tcp_closed_timeout_flag_ends_the_linger(tmp_path):
    server = ("10.0.0.2", 8080)
    frames = [
        tcp_frame(T0, CLIENT, server, "S", 1, 0),
        tcp_frame(T0 + 0.1, server, CLIENT, "R", 0, 2),
        udp_frame(T0 + 2, CLIENT, RESOLVER),
    ]
    default = run_cli(tmp_path, frames)
    assert [r["record_type"] for r in default] == ["packet", "packet", "packet", "flow", "flow"]
    records = run_cli(tmp_path, frames, "--tcp-closed-timeout", "1")
    assert [r["record_type"] for r in records] == ["packet", "packet", "flow", "packet", "flow"]
    assert records[2]["end_reason"] == "reset"


def test_max_flows_flag_evicts_the_oldest_flow(tmp_path):
    other = ("10.0.0.9", 53001)
    frames = [udp_frame(T0, CLIENT, RESOLVER), udp_frame(T0 + 1, other, RESOLVER)]
    records = run_cli(tmp_path, frames, "--max-flows", "1")
    assert [r["record_type"] for r in records] == ["packet", "flow", "packet", "flow"]
    assert records[1]["end_reason"] == "evicted"


def test_max_message_bytes_flag_caps_a_reassembled_smtp_body(tmp_path):
    client, server = ("10.0.0.1", 40000), ("10.0.0.2", 25)
    body = b"Subject: hi\r\n\r\nhello world\r\n.\r\n"
    frames = [
        tcp_frame(T0, client, server, "PA", 100, 900, b"EHLO client.test\r\n"),
        tcp_frame(T0 + 0.1, server, client, "PA", 900, 118, b"250 ok\r\n"),
        tcp_frame(T0 + 0.2, client, server, "PA", 118, 908, b"DATA\r\n"),
        tcp_frame(T0 + 0.3, server, client, "PA", 908, 124, b"354 go ahead\r\n"),
        tcp_frame(T0 + 0.4, client, server, "PA", 124, 922, body),
    ]
    records = run_cli(tmp_path, frames, "--max-message-bytes", "4")
    assert [r["record_type"] for r in records] == [
        "packet",
        "packet",
        "packet",
        "packet",
        "message",
        "packet",
        "flow",
    ]
    message = records[4]
    assert base64.b64decode(message["data_b64"]) == b"Subj"
    assert (message["complete"], message["truncated"], message["gap"]) == (True, True, False)
    assert message["packet_ids"] == [5]
    assert message["flow_id"] == records[6]["flow_id"]


@pytest.mark.parametrize(
    ("flag", "value"),
    [
        ("--tcp-idle-timeout", "-1"),
        ("--udp-idle-timeout", "-1"),
        ("--tcp-closed-timeout", "-1"),
        ("--max-flows", "0"),
        ("--max-message-bytes", "0"),
    ],
)
def test_flow_limits_reject_out_of_range_values(flag, value, capsys):
    with pytest.raises(SystemExit) as caught:
        build_parser().parse_args(["-r", "in.pcap", flag, value])
    assert caught.value.code == 2
    assert f"argument {flag}:" in capsys.readouterr().err


def test_flows_output_must_differ_from_output(tmp_path, capsys):
    out = tmp_path / "out.jsonl"
    with pytest.raises(SystemExit) as caught:
        main(["-r", "in.pcap", "-o", str(out), "--flows-output", str(tmp_path / "." / "out.jsonl")])
    assert caught.value.code == 2
    assert "--flows-output" in capsys.readouterr().err
    assert not out.exists()
