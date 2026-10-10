from __future__ import annotations

import pytest

from ids.model import (
    ApplicationInfo,
    DecodedHttp,
    DecodedUri,
    DnsMessage,
    DnsQuestion,
    DnsRecord,
    HttpHeader,
    HttpMessage,
    Ipv4Info,
    PacketEvent,
    SmtpCommand,
    SmtpSession,
    TcpInfo,
    UdpInfo,
)
from ids.preprocess.normalize import (
    canonical_protocol,
    normalize,
    normalize_domain,
    normalize_ip,
    normalize_path,
    normalize_timestamp,
    remove_dot_segments,
    split_host,
)

BASE = 1759000000.0
BASE_ISO = "2025-09-27T19:06:40.000000Z"


def http_event(
    *headers: tuple[str, str], uri: str | None = "/", decoded: DecodedHttp | None = None
) -> PacketEvent:
    message = HttpMessage(
        kind="request",
        method="GET",
        uri=uri,
        headers=[HttpHeader(name, value) for name, value in headers],
    )
    return PacketEvent(
        packet_id=1,
        timestamp=BASE,
        network=Ipv4Info(protocol="IPv4", src_ip="10.0.0.1", dst_ip="10.0.0.2"),
        transport=TcpInfo(src_port=40000, dst_port=80),
        application=ApplicationInfo(protocol="HTTP", message=message),
        decoded=decoded,
    )


@pytest.mark.parametrize("name", ["Tcp", "tcp", "TCP", " tcp "])
def test_protocol_names_are_canonical_whatever_the_case(name):
    assert canonical_protocol(name) == "TCP"


@pytest.mark.parametrize(
    ("name", "expected"),
    [("ipv4", "IPv4"), ("Http", "HTTP"), ("dns", "DNS"), ("smtp", "SMTP"), ("unknown", "UNKNOWN")],
)
def test_every_canonical_name_is_matched(name, expected):
    assert canonical_protocol(name) == expected


def test_names_outside_the_canonical_set_are_upper_cased_and_empty_names_are_none():
    assert canonical_protocol("icmp") == "ICMP"
    assert canonical_protocol("  ") is None
    assert canonical_protocol(None) is None


def test_transport_protocol_text_case_does_not_change_the_normalized_protocol():
    variants = [TcpInfo(protocol=p, src_port=1, dst_port=2) for p in ("Tcp", "tcp", "TCP")]
    normalized = [normalize(PacketEvent(transport=t))[0].protocol for t in variants]
    assert normalized == ["TCP", "TCP", "TCP"]
    assert normalize(PacketEvent(transport=UdpInfo(protocol="udp")))[0].protocol == "UDP"


def test_leading_zero_quads_are_read_as_decimal_octets():
    assert normalize_ip("010.000.000.001") == ("10.0.0.1", ["ip_normalized"])
    assert normalize_ip("010.000.000.001")[0] == normalize_ip("10.0.0.1")[0]


def test_ip_is_trimmed_without_a_note():
    assert normalize_ip(" 10.0.0.1 ") == ("10.0.0.1", [])


@pytest.mark.parametrize(
    "text", ["256.1.1.1", "1.2.3", "1.2.3.4.5", "0x0a.0.0.1", "0010.0.0.1", "::1", "", "a.b.c.d"]
)
def test_anything_that_is_not_a_dotted_quad_is_invalid(text):
    assert normalize_ip(text) == (None, [])


def test_non_string_ip_is_invalid():
    assert normalize_ip(167772161) == (None, [])


def test_domain_is_lowercased_and_loses_its_trailing_dot():
    assert normalize_domain("Example.COM.") == ("example.com", [])
    assert normalize_domain("example.com") == ("example.com", [])


def test_root_name_is_kept():
    assert normalize_domain(".") == (".", [])


def test_non_ascii_labels_are_idna_encoded():
    assert normalize_domain("Bücher.de") == ("xn--bcher-kva.de", [])


def test_leading_underscore_service_labels_are_valid():
    assert normalize_domain("_sip._tcp.Example.com") == ("_sip._tcp.example.com", [])


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("a..b", "a..b"),
        ("x" * 64 + ".com", "x" * 64 + ".com"),
        ("-bad.com", "-bad.com"),
        ("bad-.com", "bad-.com"),
        ("in_side.com", "in_side.com"),
        ("sp ace.com", "sp ace.com"),
    ],
)
def test_names_outside_ldh_rules_keep_a_best_effort_value_and_are_flagged(text, expected):
    assert normalize_domain(text) == (expected, ["invalid_domain"])


def test_names_longer_than_253_characters_are_flagged():
    name = ".".join(["a" * 63] * 4)
    assert normalize_domain(name) == (name, ["invalid_domain"])


def test_host_header_is_split_into_host_and_port():
    assert split_host("Example.COM:8080") == ("example.com", 8080, [])
    assert split_host("example.com") == ("example.com", None, [])
    assert split_host("example.com:") == ("example.com", None, [])


@pytest.mark.parametrize("text", ["[::1]:80", "[::1]", "::1", "example.com:http", "a.com:65536"])
def test_unsupported_or_broken_host_forms_are_flagged_not_raised(text):
    _, port, notes = split_host(text)
    assert port is None
    assert notes[0] == "invalid_host"


def test_host_with_bad_port_keeps_the_host():
    assert split_host("Example.com:99999") == ("example.com", None, ["invalid_host"])


def test_empty_host_is_absent_not_invalid():
    assert split_host("  ") == (None, None, [])


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/a/b/c/./../../g", "/a/g"),
        ("mid/content=5/../6", "mid/6"),
        ("/../a", "/a"),
        ("/a/..", "/"),
        ("/a/.", "/a/"),
        ("../../a", "a"),
        (".", ""),
        ("..", ""),
        ("a/..", "/"),
        ("/a/b/..", "/a/"),
        ("/.hidden/..x", "/.hidden/..x"),
    ],
)
def test_remove_dot_segments_follows_rfc_3986(path, expected):
    assert remove_dot_segments(path) == expected


class CopyCountingPath(str):
    """Counts the characters copied out by slicing, to pin remove_dot_segments as linear."""

    copied = 0

    def __getitem__(self, key):
        piece = super().__getitem__(key)
        self.copied += len(piece)
        return piece


def test_remove_dot_segments_copies_each_character_once():
    path = CopyCountingPath("/a" * 5000 + "/b/..")

    assert remove_dot_segments(path) == "/a" * 5000 + "/"
    assert path.copied <= len(path)


def test_path_collapses_slashes_before_removing_dot_segments_and_keeps_case():
    assert normalize_path("/a/./b/../c//d") == ("/a/c/d", [])
    assert normalize_path("/A//../B") == ("/B", [])


def test_backslashes_are_flagged_and_kept():
    assert normalize_path("/a\\..\\b") == ("/a\\..\\b", ["backslash_in_path"])


def test_epoch_iso_and_milliseconds_give_the_same_timestamp():
    expected = (BASE, BASE_ISO)
    assert normalize_timestamp(BASE)[:2] == expected
    assert normalize_timestamp(1759000000)[:2] == expected
    assert normalize_timestamp("2025-09-27T19:06:40Z") == (BASE, BASE_ISO, [])
    assert normalize_timestamp("2025-09-27T19:06:40+00:00") == (BASE, BASE_ISO, [])
    assert normalize_timestamp("2025-09-27T19:06:40") == (BASE, BASE_ISO, [])
    assert normalize_timestamp(1759000000000) == (BASE, BASE_ISO, ["timestamp_scaled"])


def test_the_millisecond_threshold_is_1e11():
    assert normalize_timestamp(1e11)[2] == []
    assert normalize_timestamp(1e11 + 1)[2] == ["timestamp_scaled"]


def test_iso_with_offset_is_converted_to_utc():
    assert normalize_timestamp("2025-09-28T02:06:40+07:00")[:2] == (BASE, BASE_ISO)


@pytest.mark.parametrize("value", ["yesterday", "", float("nan"), float("inf"), True, None, [1]])
def test_unusable_timestamps_normalize_to_none(value):
    assert normalize_timestamp(value) == (None, None, [])


def test_header_names_are_trimmed_and_lowercased_with_values_grouped_in_order():
    upper = http_event(("CONTENT-TYPE", "text/plain"), ("Accept", "a"), (" accept ", "b"))
    lower = http_event(("content-type", "text/plain"), ("accept", "a"), ("accept", "b"))
    upper_http = normalize(upper)[0].http
    assert upper_http.headers == {"content-type": ["text/plain"], "accept": ["a", "b"]}
    assert upper_http == normalize(lower)[0].http


def test_http_host_variants_normalize_identically():
    a = normalize(http_event(("Host", "Example.COM.:8080")))[0].http
    b = normalize(http_event(("host", "example.com:8080")))[0].http
    assert (a.host, a.port) == (b.host, b.port) == ("example.com", 8080)


def test_absolute_form_authority_wins_over_the_host_header_and_sets_the_scheme():
    event = http_event(("Host", "other.org"), uri="HTTP://User@Example.COM:81/a/../b?q=1")
    http = normalize(event)[0].http
    assert (http.scheme, http.host, http.port, http.path) == ("http", "example.com", 81, "/b")


def test_path_comes_from_the_decoded_uri_when_present():
    decoded = DecodedHttp(uri=DecodedUri(path="/search page/./x"))
    event = http_event(uri="/search%20page/./x?q=1", decoded=decoded)
    assert normalize(event)[0].http.path == "/search page/x"


def test_path_falls_back_to_the_raw_uri_without_query_or_fragment():
    assert normalize(http_event(uri="/a/./b/../c//d?x=/../y#f"))[0].http.path == "/a/c/d"


def test_origin_form_has_no_scheme_and_method_is_kept_as_sent():
    http = normalize(http_event(uri="/"))[0].http
    assert http.scheme is None
    assert http.method == "GET"


def test_dns_names_come_from_questions_then_answers_without_duplicates():
    message = DnsMessage(
        kind="response",
        questions=[DnsQuestion(name="WWW.Example.com.")],
        answers=[DnsRecord(name="www.example.com"), DnsRecord(name="Edge.CDN.net")],
    )
    event = PacketEvent(application=ApplicationInfo(protocol="DNS", message=message))
    assert normalize(event)[0].dns.names == ["www.example.com", "edge.cdn.net"]


def test_smtp_domains_are_lowercased_and_local_parts_kept():
    session = SmtpSession(
        kind="command",
        commands=[SmtpCommand(verb="EHLO", domain="Mail.Example.COM")],
        mail_from="Alice@Example.COM",
        rcpt_to=["Bob@Example.ORG.", "postmaster"],
    )
    event = PacketEvent(application=ApplicationInfo(protocol="SMTP", message=session))
    smtp = normalize(event)[0].smtp
    assert smtp.helo == "mail.example.com"
    assert smtp.mail_from == "Alice@example.com"
    assert smtp.rcpt_to == ["Bob@example.org", "postmaster"]


def test_smtp_helo_address_literal_is_kept():
    session = SmtpSession(commands=[SmtpCommand(verb="HELO", domain="[192.0.2.1]")])
    event = PacketEvent(application=ApplicationInfo(protocol="SMTP", message=session))
    assert normalize(event)[0].smtp.helo == "[192.0.2.1]"


def test_t05_variants_yield_identical_normalized_core_values():
    def event(protocol: str, src: str, stamp: object) -> PacketEvent:
        return PacketEvent(
            packet_id=1,
            timestamp=stamp,
            network=Ipv4Info(src_ip=src, dst_ip="10.0.0.2"),
            transport=TcpInfo(protocol=protocol, src_port=40000, dst_port=80),
        )

    plain = normalize(event("TCP", "10.0.0.1", BASE))
    padded = normalize(event("Tcp", "010.000.000.001", "2025-09-27T19:06:40Z"))
    scaled = normalize(event("tcp", "10.0.0.1", 1759000000000))
    assert plain[0] == padded[0] == scaled[0]
    assert (plain[1], padded[1], scaled[1]) == ([], ["ip_normalized"], ["timestamp_scaled"])


def test_notes_are_reported_once():
    event = PacketEvent(network=Ipv4Info(src_ip="010.0.0.1", dst_ip="010.0.0.2"))
    assert normalize(event)[1] == ["ip_normalized"]


def test_raw_fields_are_not_mutated():
    event = http_event(("CONTENT-TYPE", "x"), ("Host", "Example.COM"), uri="/A/./b")
    event.network.src_ip = "010.000.000.001"
    normalize(event)
    assert event.network.src_ip == "010.000.000.001"
    assert event.application.message.uri == "/A/./b"
    assert event.application.message.headers[0].name == "CONTENT-TYPE"
    assert event.normalized is None


def test_event_with_nothing_parsed_normalizes_to_empty_values():
    normalized, notes = normalize(PacketEvent())
    assert normalized.application_protocol == "UNKNOWN"
    assert (normalized.src_ip, normalized.protocol, normalized.timestamp) == (None, None, None)
    assert (normalized.http, normalized.dns, normalized.smtp) == (None, None, None)
    assert notes == []


def test_review_dot_segments_hidden_by_percent_encoding_resolve_from_the_decoded_path():
    decoded = DecodedHttp(uri=DecodedUri(path="/static/../admin"))
    event = http_event(uri="/static/%2e%2e/admin", decoded=decoded)
    assert normalize(event)[0].http.path == "/admin"


def test_review_duplicate_host_headers_keep_both_values_and_the_last_one_wins():
    http = normalize(http_event(("Host", "good.example"), ("HOST", "Evil.Example")))[0].http
    assert http.headers["host"] == ["good.example", "Evil.Example"]
    assert http.host == "evil.example"


def test_review_control_characters_in_domains_are_flagged():
    assert normalize_domain("ex\x00ample.com") == ("ex\x00ample.com", ["invalid_domain"])


@pytest.mark.parametrize("text", ["a.com:+80", "a.com:\u0668\u0660", "a.com: 80"])
def test_review_signed_spaced_or_non_ascii_port_digits_are_rejected(text):
    assert split_host(text) == ("a.com", None, ["invalid_host"])


@pytest.mark.parametrize("uri", ["http://[::1/a", "http://[abc]/x", "http://a.com\u2100/x"])
def test_review_malformed_absolute_form_authority_is_flagged_not_raised(uri):
    normalized, notes = normalize(http_event(("Host", "good.example"), uri=uri))
    assert (normalized.http.host, normalized.http.path) == (None, None)
    assert notes == ["invalid_host"]


@pytest.mark.parametrize("text", ["a.com:" + "9" * 5000, "a.com:000080"])
def test_review_port_text_longer_than_five_digits_is_rejected(text):
    assert split_host(text) == ("a.com", None, ["invalid_host"])
