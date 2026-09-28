import pytest
from golden import (
    DNS_ANSWER,
    DNS_QUERY,
    HTTP_GET,
    HTTP_RESPONSE,
    SMTP_EHLO,
    SMTP_GREETING,
    SMTP_MAIL_FROM,
)

from pcparser.parsers.detector import STANDARD_PORTS, detect

NOISE = bytes(range(256))
TLS_CLIENT_HELLO = b"\x16\x03\x01\x00\x2c\x01\x00\x00\x28\x03\x03" + bytes(range(32))


def test_http_on_the_standard_port():
    result = detect(HTTP_GET, src_port=51234, dst_port=80, tcp=True)
    assert result.protocol == "HTTP"
    assert result.method == "port+payload"
    assert result.port_matched is True
    assert result.confidence == 1.0


def test_http_on_an_alternative_standard_port():
    result = detect(HTTP_GET, src_port=51234, dst_port=8080, tcp=True)
    assert result.protocol == "HTTP"
    assert result.method == "port+payload"


def test_http_on_a_non_standard_port_is_detected_from_the_payload():
    result = detect(HTTP_GET, src_port=51234, dst_port=9999, tcp=True)
    assert result.protocol == "HTTP"
    assert result.method == "payload"
    assert result.port_matched is False
    assert result.port_hint is None
    assert result.confidence >= 0.9
    assert "request line" in result.evidence


def test_http_response_on_a_non_standard_port():
    result = detect(HTTP_RESPONSE, src_port=44321, dst_port=51234, tcp=True)
    assert result.protocol == "HTTP"
    assert result.method == "payload"


def test_bare_method_token_is_a_weaker_http_signal():
    result = detect(b"GET /index.html\r\n", src_port=51234, dst_port=9999, tcp=True)
    assert result.protocol == "HTTP"
    assert 0.5 <= result.confidence < 0.9


def test_dns_query_on_the_standard_port():
    result = detect(DNS_QUERY, src_port=40000, dst_port=53, tcp=False)
    assert result.protocol == "DNS"
    assert result.method == "port+payload"
    assert result.confidence == 1.0


def test_dns_query_on_a_non_standard_port():
    result = detect(DNS_QUERY, src_port=40000, dst_port=15353, tcp=False)
    assert result.protocol == "DNS"
    assert result.method == "payload"
    assert "plausible question name" in result.evidence
    assert "known qtype A" in result.evidence


def test_dns_response_reports_answers_as_evidence():
    result = detect(DNS_ANSWER, src_port=53, dst_port=40000, tcp=False)
    assert result.protocol == "DNS"
    assert "response with answers" in result.evidence


def test_dns_over_tcp_needs_the_length_prefix():
    prefixed = len(DNS_QUERY).to_bytes(2, "big") + DNS_QUERY
    assert detect(prefixed, src_port=40000, dst_port=5353, tcp=True).protocol == "DNS"
    assert detect(DNS_QUERY, src_port=40000, dst_port=5353, tcp=True).method == "port"


def test_smtp_commands_and_replies():
    assert detect(SMTP_EHLO, src_port=40000, dst_port=25, tcp=True).protocol == "SMTP"
    assert detect(SMTP_GREETING, src_port=25, dst_port=40000, tcp=True).protocol == "SMTP"
    mail = detect(SMTP_MAIL_FROM, src_port=40000, dst_port=2526, tcp=True)
    assert mail.protocol == "SMTP"
    assert mail.method == "payload"


def test_numeric_status_line_without_a_known_code():
    result = detect(b"299 numeric\r\n", src_port=40000, dst_port=25, tcp=True)
    assert result.protocol == "SMTP"
    assert result.confidence == 0.7


def test_weak_numeric_status_line_needs_the_port_hint():
    assert detect(b"299 numeric\r\n", src_port=40000, dst_port=4444, tcp=True).protocol == "UNKNOWN"
    strong = detect(b"250 ok\r\n", src_port=40000, dst_port=4444, tcp=True)
    assert strong.protocol == "SMTP"
    assert strong.method == "payload"


def test_random_bytes_on_http_port_are_only_a_port_guess():
    result = detect(NOISE, src_port=51234, dst_port=80, tcp=True)
    assert result.protocol == "HTTP"
    assert result.method == "port"
    assert result.confidence == 0.3
    assert result.scores["HTTP"] == 0.25


def test_random_bytes_on_an_unknown_port_stay_unknown():
    result = detect(NOISE, src_port=51234, dst_port=9999, tcp=True)
    assert result.protocol == "UNKNOWN"
    assert result.port_hint is None


def test_empty_payload_is_never_attributed_to_a_protocol():
    result = detect(b"", src_port=51234, dst_port=80, tcp=True)
    assert result.protocol == "UNKNOWN"
    assert result.confidence == 0.0
    assert result.evidence == "no payload to inspect"


def test_tls_on_443_is_not_mistaken_for_http():
    result = detect(TLS_CLIENT_HELLO, src_port=51234, dst_port=443, tcp=True)
    assert result.protocol == "UNKNOWN"


def test_plain_text_on_an_unknown_port_is_unknown():
    assert (
        detect(b"hello world\r\n", src_port=40000, dst_port=40001, tcp=True).protocol == "UNKNOWN"
    )


@pytest.mark.parametrize("payload", [NOISE, b"\x00" * 64, b"\xff" * 64, DNS_QUERY, HTTP_GET])
def test_scores_and_evidence_are_always_exposed(payload):
    result = detect(payload, src_port=1234, dst_port=5678, tcp=True)
    assert set(result.scores) == {"HTTP", "DNS", "SMTP"}
    assert all(0.0 <= score <= 1.0 for score in result.scores.values())
    assert result.protocol in {"HTTP", "DNS", "SMTP", "UNKNOWN"}


def test_standard_port_table_only_holds_known_protocols():
    assert set(STANDARD_PORTS.values()) == {"HTTP", "DNS", "SMTP"}
