import json
import random
from pathlib import Path

import pytest

from pcparser.capture import PcapFileCapture
from pcparser.capture.base import RawPacket
from pcparser.pipeline import UNKNOWN_POLICIES, Pipeline

FIXTURES = Path(__file__).resolve().parents[1] / "TEST" / "fixtures"


def events(fixture, **options):
    pipeline = Pipeline(**options)
    source = PcapFileCapture(FIXTURES / fixture)
    return [pipeline.process(packet) for packet in source.packets()]


def test_tcp_handshake_sequence():
    results = events("01-tcp-handshake.pcap")
    assert [event["transport"]["flags_string"] for event in results] == ["S", "SA", "A"]
    assert [event["event_type"] for event in results] == ["tcp_segment"] * 3
    assert results[0]["transport"]["flags"]["syn"] is True
    assert results[1]["transport"]["flags"]["ack"] is True
    assert results[0]["network"]["header_checksum_valid"] is True


def test_tcp_data_payload_is_normalised():
    results = events("02-tcp-data.pcap")
    assert [event["transport"]["payload_length"] for event in results] == [29, 32]
    assert results[0]["payload"]["preview"].startswith("PAYLOAD-01")
    assert results[1]["payload"]["binary"] is True
    assert len(results[1]["payload"]["sha256"]) == 64


def test_udp_packets():
    results = events("03-udp.pcap")
    assert all(event["transport_protocol"] == "UDP" for event in results)
    assert [event["transport"]["payload_length"] for event in results] == [15, 64, 0]
    assert results[0]["application_protocol"] == "UNKNOWN"


def test_http_get_application_block():
    event = events("04-http-get.pcap")[1]
    assert event["event_type"] == "http_request"
    assert event["application_protocol"] == "HTTP"
    detail = event["application"]["http"]
    assert detail["method"] == "GET"
    assert detail["host"] == "example.com"
    assert detail["query_params"] == {"q": ["ids"], "page": ["1"]}
    assert event["application"]["detection"]["method"] == "port+payload"


def test_http_post_form_is_parsed():
    event = events("05-http-post.pcap")[0]
    detail = event["application"]["http"]
    assert detail["method"] == "POST"
    assert detail["body"]["length"] == 42
    assert detail["form"] == {"username": ["alice"], "password": ["s3cr3t"], "remember": ["on"]}
    assert event["errors"] == []


def test_http_responses_report_status_codes():
    results = events("06-http-response.pcap")
    assert [event["application"]["http"]["status_code"] for event in results] == [200, 404]
    assert results[0]["application"]["http"]["server"] == "nginx/1.24.0"
    assert results[0]["event_type"] == "http_response"


def test_dns_queries_report_name_and_type():
    results = events("07-dns-query.pcap")
    assert [event["event_type"] for event in results] == ["dns_query"] * 3
    questions = [event["application"]["dns"]["questions"][0] for event in results]
    assert [(question["name"], question["type_name"]) for question in questions] == [
        ("example.com", "A"),
        ("mail.example.com", "MX"),
        ("1.1.168.192.in-addr.arpa", "PTR"),
    ]


def test_dns_response_has_answers():
    results = events("08-dns-response.pcap")
    first = results[0]["application"]["dns"]
    assert first["kind"] == "response"
    assert first["rcode_name"] == "NOERROR"
    assert len(first["answers"]) >= 1
    assert [answer["type_name"] for answer in first["answers"]] == ["CNAME", "A"]
    assert first["answers"][1]["value"] == "93.184.216.34"
    assert results[1]["application"]["dns"]["rcode_name"] == "NXDOMAIN"


def test_smtp_commands():
    results = events("09-smtp-command.pcap")
    assert [event["application"]["smtp"]["command"] for event in results] == [
        "EHLO",
        "MAIL",
        "RCPT",
        "DATA",
    ]
    assert results[1]["application"]["smtp"]["mail_from"] == "alice@example.test"
    assert results[2]["application"]["smtp"]["rcpt_to"] == ["bob@example.test"]
    assert all(event["event_type"] == "smtp_command" for event in results)


def test_smtp_status_codes():
    results = events("10-smtp-response.pcap")
    assert [event["application"]["smtp"]["status_code"] for event in results] == [
        220,
        250,
        354,
        550,
    ]
    assert results[1]["application"]["smtp"]["reply_count"] == 1
    assert all(event["event_type"] == "smtp_response" for event in results)


def test_unknown_protocols_do_not_crash():
    results = events("11-unknown-protocol.pcap")
    assert len(results) == 6
    assert all(event["application_protocol"] == "UNKNOWN" for event in results)
    assert {event["event_type"] for event in results} == {
        "unknown_payload",
        "network_only",
        "unparsed",
    }
    assert results[3]["network_protocol"] == "IPv4"
    assert results[3]["transport"] is None


def test_malformed_packets_do_not_crash():
    results = events("12-malformed.pcap")
    assert len(results) == 14
    assert all(event["errors"] for event in results)
    found = {(error["stage"], error["code"]) for event in results for error in event["errors"]}
    assert ("link", "truncated_packet") in found
    assert ("network", "malformed_header") in found
    assert ("network", "truncated_packet") in found
    assert ("network", "unsupported_protocol") in found
    assert ("transport", "malformed_header") in found
    assert ("transport", "truncated_packet") in found
    assert ("application", "decode_error") in found
    assert ("application", "truncated_body") in found
    assert ("capture", "truncated_packet") in found


def test_pcapng_fixture_parses_like_pcap():
    results = events("13-mixed.pcapng")
    assert len(results) == 12
    assert all(event["capture"]["source"] == "pcap" for event in results)
    assert all(event["capture"]["linktype_name"] == "EN10MB" for event in results)
    assert {event["event_type"] for event in results} == {
        "tcp_segment",
        "http_request",
        "dns_query",
        "smtp_command",
    }


def test_unknown_policy_skip_drops_only_unknown_events():
    kept = events("11-unknown-protocol.pcap", unknown_policy="skip")
    assert kept == [None] * 6
    mixed = events("04-http-get.pcap", unknown_policy="skip")
    assert mixed[0] is None
    assert mixed[1]["event_type"] == "http_request"


def test_invalid_unknown_policy_is_rejected():
    with pytest.raises(ValueError):
        Pipeline(unknown_policy="explode")
    assert UNKNOWN_POLICIES == ("emit", "skip")


def test_default_schema_keys_are_stable():
    event = events("04-http-get.pcap")[1]
    assert set(event) == {
        "schema_version",
        "packet_id",
        "timestamp",
        "timestamp_iso",
        "event_type",
        "network_protocol",
        "transport_protocol",
        "application_protocol",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "capture",
        "link",
        "network",
        "transport",
        "application",
        "payload",
        "errors",
    }
    assert event["src_ip"] == "10.0.0.1"
    assert event["dst_port"] == 80
    assert event["timestamp_iso"].startswith("2025-")
    assert json.loads(json.dumps(event))["packet_id"] == event["packet_id"]


def test_preview_limit_is_respected():
    event = events("02-tcp-data.pcap", preview_limit=4)[0]
    assert event["payload"]["preview"] == "PAYL"
    assert event["payload"]["preview_truncated"] is True
    assert event["payload"]["length"] == 29


def test_random_bytes_never_escape_the_pipeline():
    rng = random.Random(20260928)
    pipeline = Pipeline()
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
        event = pipeline.process(packet)
        assert isinstance(event, dict)
        assert event["application_protocol"] in {"HTTP", "DNS", "SMTP", "UNKNOWN"}
        json.dumps(event)


def test_parser_crash_is_contained_in_one_event(monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("parser bug")

    monkeypatch.setattr("pcparser.pipeline.parse_link", boom)
    event = Pipeline().process(RawPacket(1, 0.0, b"\x00" * 60, 1, "pcap", "fuzz", 60, 60))
    assert event["errors"] == [
        {
            "stage": "link",
            "code": "internal_error",
            "message": "parser bug",
            "context": {"exception": "RuntimeError"},
        }
    ]
    assert event["event_type"] == "unparsed"
    assert event["network"] is None


def test_build_failure_falls_back_to_a_minimal_event(monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("build bug")

    monkeypatch.setattr("pcparser.pipeline.Pipeline._build", boom)
    event = Pipeline().process(RawPacket(9, 12.5, b"\x00" * 60, 1, "pcap", "fuzz", 60, 60))
    assert event["packet_id"] == 9
    assert event["timestamp"] == 12.5
    assert event["event_type"] == "unparsed"
    assert event["errors"][0]["code"] == "internal_error"
    assert event["errors"][0]["context"] == {"exception": "RuntimeError"}
