from __future__ import annotations

import json
import random
from pathlib import Path

from ids.capture import PcapSource
from ids.codec import encode_line
from ids.issues import Issue
from ids.model import UNKNOWN, ApplicationInfo, RawPacket
from ids.parsers import PacketParser, ParserConfig
from ids.payload import sha256_hex

FIXTURES = Path(__file__).resolve().parents[1] / "TEST" / "capture-parser" / "fixtures"


def raw_packets(fixture):
    return list(PcapSource(FIXTURES / fixture).items())


def events(fixture, config=None):
    parser = PacketParser(config)
    return [parser.parse(raw) for raw in raw_packets(fixture)]


def boom(*args, **kwargs):
    raise RuntimeError("parser bug")


def test_tcp_handshake_sequence():
    results = events("01-tcp-handshake.pcap")
    assert [event.transport.flags_string for event in results] == ["S", "SA", "A"]
    assert [event.event_type for event in results] == ["tcp_segment"] * 3
    assert results[0].transport.flags.syn is True
    assert results[1].transport.flags.ack is True
    assert results[0].network.header_checksum_valid is True
    assert all(event.issues == [] for event in results)


def test_tcp_data_payload_is_kept():
    results = events("02-tcp-data.pcap")
    assert [event.transport.payload_length for event in results] == [29, 32]
    assert results[0].payload.preview.startswith("PAYLOAD-01")
    assert results[0].payload.data.startswith(b"PAYLOAD-01")
    assert results[0].payload.length == len(results[0].payload.data) == 29
    assert results[1].payload.binary is True
    assert len(results[1].payload.sha256) == 64


def test_payload_bytes_are_capped_but_hashed_in_full():
    full = events("02-tcp-data.pcap")[0].payload
    capped = events("02-tcp-data.pcap", ParserConfig(max_payload_bytes=10))[0].payload
    assert full.data_truncated is False
    assert capped.data == b"PAYLOAD-01"
    assert capped.data_truncated is True
    assert capped.length == 29
    assert capped.sha256 == full.sha256 == sha256_hex(full.data)


def test_udp_packets():
    results = events("03-udp.pcap")
    assert all(event.protocol == "UDP" for event in results)
    assert [event.transport.payload_length for event in results] == [15, 64, 0]
    assert results[0].application_protocol == UNKNOWN
    assert results[0].application.detection.method == "none"


def test_http_get_application_block():
    event = events("04-http-get.pcap")[1]
    assert event.event_type == "http_request"
    assert event.application_protocol == "HTTP"
    message = event.application.message
    assert message.method == "GET"
    assert message.uri == "/index.html?q=ids&page=1"
    assert message.header("host") == "example.com"
    assert [header.name for header in message.headers] == [
        "Host",
        "User-Agent",
        "Accept",
        "Cookie",
        "Connection",
    ]
    assert event.application.detection.method == "port+payload"
    assert event.src_ip == "10.0.0.1"
    assert event.dst_port == 80


def test_http_post_body_is_located_in_the_payload():
    event = events("05-http-post.pcap")[0]
    message = event.application.message
    assert message.method == "POST"
    assert message.body.length == 42
    assert message.body.declared_length == 42
    start = message.body.offset
    assert event.payload.data[start : start + 42] == b"username=alice&password=s3cr3t&remember=on"
    assert event.issues == []


def test_http_responses_report_status_codes():
    results = events("06-http-response.pcap")
    messages = [event.application.message for event in results]
    assert [message.status_code for message in messages] == [200, 404]
    assert [message.reason for message in messages] == ["OK", "Not Found"]
    assert messages[0].header("server") == "nginx/1.24.0"
    assert results[0].event_type == "http_response"


def test_dns_queries_report_name_and_type():
    results = events("07-dns-query.pcap")
    assert [event.event_type for event in results] == ["dns_query"] * 3
    questions = [event.application.message.questions[0] for event in results]
    assert [(question.name, question.type_name) for question in questions] == [
        ("example.com", "A"),
        ("mail.example.com", "MX"),
        ("1.1.168.192.in-addr.arpa", "PTR"),
    ]


def test_dns_response_has_answers():
    results = events("08-dns-response.pcap")
    first = results[0].application.message
    assert first.kind == "response"
    assert first.rcode_name == "NOERROR"
    assert [answer.type_name for answer in first.answers] == ["CNAME", "A"]
    assert first.answers[1].value == "93.184.216.34"
    assert results[1].application.message.rcode_name == "NXDOMAIN"


def test_smtp_commands():
    results = events("09-smtp-command.pcap")
    sessions = [event.application.message for event in results]
    assert [session.command for session in sessions] == ["EHLO", "MAIL", "RCPT", "DATA"]
    assert sessions[1].mail_from == "alice@example.test"
    assert sessions[2].rcpt_to == ["bob@example.test"]
    assert all(event.event_type == "smtp_command" for event in results)


def test_smtp_status_codes():
    results = events("10-smtp-response.pcap")
    sessions = [event.application.message for event in results]
    assert [session.status_code for session in sessions] == [220, 250, 354, 550]
    assert len(sessions[1].replies) == 1
    assert all(event.event_type == "smtp_response" for event in results)


def test_unknown_protocols_do_not_crash():
    results = events("11-unknown-protocol.pcap")
    assert len(results) == 6
    assert all(event.application_protocol == UNKNOWN for event in results)
    assert {event.event_type for event in results} == {
        "unknown_payload",
        "network_only",
        "unparsed",
    }
    assert results[3].network.protocol == "IPv4"
    assert results[3].transport is None
    assert results[3].application is None
    assert results[3].issues == []


def test_malformed_packets_do_not_crash():
    results = events("12-malformed.pcap")
    assert len(results) == 14
    assert all(event.issues for event in results)
    found = {(issue.stage, issue.code) for event in results for issue in event.issues}
    assert ("link", "truncated_packet") in found
    assert ("network", "malformed_header") in found
    assert ("network", "truncated_packet") in found
    assert ("network", "unsupported_protocol") in found
    assert ("transport", "malformed_header") in found
    assert ("transport", "truncated_packet") in found
    assert ("application", "decode_error") in found
    assert ("application", "truncated_body") in found
    assert ("capture", "truncated_packet") in found
    assert [(issue.stage, issue.code) for issue in results[13].issues] == [
        ("capture", "truncated_packet"),
        ("network", "truncated_packet"),
        ("transport", "truncated_packet"),
    ]


def test_pcapng_fixture_parses_like_pcap():
    results = events("13-mixed.pcapng")
    assert len(results) == 12
    assert all(event.capture.source == "pcap" for event in results)
    assert all(event.capture.linktype_name == "EN10MB" for event in results)
    assert {event.event_type for event in results} == {
        "tcp_segment",
        "http_request",
        "dns_query",
        "smtp_command",
    }


def test_preview_limit_is_respected():
    event = events("02-tcp-data.pcap", ParserConfig(preview_limit=4))[0]
    assert event.payload.preview == "PAYL"
    assert event.payload.preview_truncated is True
    assert event.payload.length == 29


def test_random_bytes_never_escape_the_parser():
    rng = random.Random(20260928)
    parser = PacketParser()
    for index in range(3000):
        data = bytes(rng.getrandbits(8) for _ in range(rng.randrange(0, 96)))
        packet = RawPacket(
            packet_id=index + 1,
            timestamp=1759000000.0 + index,
            data=data,
            linktype=rng.choice([0, 1, 101, 113, 228, 276, 999]),
            source="pcap",
            origin="fuzz",
            original_length=len(data),
            declared_capture_length=len(data),
        )
        event = parser.parse(packet)
        assert event.application_protocol in {"HTTP", "DNS", "SMTP", UNKNOWN}
        assert json.loads(encode_line(event))["packet_id"] == index + 1


def test_link_crash_is_contained_in_one_event(monkeypatch):
    monkeypatch.setattr("ids.parsers.parse_link", boom)
    event = PacketParser().parse(RawPacket(1, 0.0, b"\x00" * 60, 1, "pcap", "fuzz", 60, 60))
    assert event.issues == [
        Issue("link", "internal_error", "parser bug", {"exception": "RuntimeError"})
    ]
    assert event.event_type == "unparsed"
    assert event.network is None
    assert event.payload.length == 60


def test_detector_crash_leaves_the_packet_unknown(monkeypatch):
    monkeypatch.setattr("ids.parsers.detect", boom)
    event = PacketParser().parse(raw_packets("04-http-get.pcap")[1])
    assert event.issues == [
        Issue("detect", "internal_error", "parser bug", {"exception": "RuntimeError"})
    ]
    assert event.application == ApplicationInfo(protocol=UNKNOWN, detection=None, message=None)
    assert event.transport is not None
    assert event.payload.length == 187


def test_missing_application_parser_is_reported_at_application_stage(monkeypatch):
    monkeypatch.setattr("ids.parsers.by_name", lambda name: None)
    event = PacketParser().parse(raw_packets("04-http-get.pcap")[1])
    assert [(issue.stage, issue.code, issue.message) for issue in event.issues] == [
        ("application", "internal_error", "no application parser registered for HTTP")
    ]
    assert event.application.protocol == "HTTP"
    assert event.application.message is None
    assert event.event_type == "http_unparsed"


def test_failure_outside_the_steps_falls_back_to_a_minimal_event(monkeypatch):
    def broken_payload(*args, **kwargs):
        raise RuntimeError("payload bug")

    monkeypatch.setattr("ids.parsers.make_payload", broken_payload)
    event = PacketParser().parse(RawPacket(9, 12.5, b"\x00" * 60, 1, "pcap", "fuzz", 60, 60))
    assert event.packet_id == 9
    assert event.timestamp == 12.5
    assert event.event_type == "unparsed"
    assert event.payload is None
    assert event.capture.captured_length == 60
    assert event.capture.linktype_name == "EN10MB"
    assert event.issues == [
        Issue("pipeline", "internal_error", "payload bug", {"exception": "RuntimeError"})
    ]
