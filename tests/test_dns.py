import struct

import pytest
from golden import DNS_ANSWER, DNS_POINTER_LOOP, DNS_QUERY, dns_name

from ids.issues import Issue, Issues, ParseError
from ids.model import DnsCounts, DnsQuestion
from ids.parsers.dns import parse, read_name, score


def record_bytes(name, rtype, rdata, ttl=60, rclass=1):
    return dns_name(name) + struct.pack("!HHIH", rtype, rclass, ttl, len(rdata)) + rdata


def message(identifier, flags, questions=(), answers=(), authorities=(), additionals=()):
    body = b""
    for name, rtype in questions:
        body += dns_name(name) + struct.pack("!HH", rtype, 1)
    for section in (answers, authorities, additionals):
        for item in section:
            body += record_bytes(*item)
    header = struct.pack(
        "!HHHHHH",
        identifier,
        flags,
        len(questions),
        len(answers),
        len(authorities),
        len(additionals),
    )
    return header + body


def parse_udp(payload, issues=None):
    return parse(payload, tcp=False, issues=issues if issues is not None else Issues("application"))


def test_query_question_and_flags():
    issues = Issues("application")
    info = parse_udp(DNS_QUERY, issues)
    assert info.kind == "query"
    assert info.id == 0x1234
    assert info.flags.rd is True
    assert info.flags.qr is False
    assert info.opcode_name == "QUERY"
    assert info.rcode_name == "NOERROR"
    assert info.counts == DnsCounts(questions=1, answers=0, authorities=0, additionals=0)
    assert info.questions == [
        DnsQuestion(name="example.com", type=1, type_name="A", class_=1, class_name="IN")
    ]
    assert info.answers == []
    assert info.tcp is False
    assert issues.records == []


def test_response_with_one_answer():
    info = parse_udp(DNS_ANSWER)
    assert info.kind == "response"
    assert info.flags.qr is True
    assert info.flags.ra is True
    assert info.counts.answers == 1
    answer = info.answers[0]
    assert answer.name == "example.com"
    assert answer.type_name == "A"
    assert answer.class_name == "IN"
    assert answer.ttl == 300
    assert answer.rdlength == 4
    assert answer.value == "93.184.216.34"
    assert answer.rdata is None


def test_name_compression_pointer_is_followed():
    raw = dns_name("example.com")
    name, offset = read_name(raw, 0)
    assert name == "example.com"
    assert offset == len(raw)
    compressed = raw + b"\xc0\x00"
    assert read_name(compressed, len(raw)) == ("example.com", len(raw) + 2)


def test_root_name_reads_as_a_dot():
    assert read_name(b"\x00", 0) == (".", 1)


@pytest.mark.parametrize(
    "rtype,rdata,expected",
    [
        (
            28,
            bytes.fromhex("26062800022000012481893525c81946"),
            "2606:2800:220:1:2481:8935:25c8:1946",
        ),
        (5, dns_name("target.example.com"), "target.example.com"),
        (12, dns_name("host.example.com"), "host.example.com"),
        (2, dns_name("ns1.example.com"), "ns1.example.com"),
    ],
)
def test_name_and_address_rdata(rtype, rdata, expected):
    info = parse_udp(message(1, 0x8180, [("q.example.com", 1)], [("q.example.com", rtype, rdata)]))
    assert info.answers[0].value == expected


def test_mx_rdata():
    rdata = struct.pack("!H", 10) + dns_name("mail.example.com")
    info = parse_udp(message(1, 0x8180, [("example.com", 15)], [("example.com", 15, rdata)]))
    assert info.answers[0].value == {"preference": 10, "exchange": "mail.example.com"}


def test_srv_rdata():
    rdata = struct.pack("!HHH", 10, 60, 5060) + dns_name("sip.example.com")
    info = parse_udp(
        message(1, 0x8180, [("_sip._tcp.example.com", 33)], [("_sip._tcp.example.com", 33, rdata)])
    )
    assert info.answers[0].value == {
        "priority": 10,
        "weight": 60,
        "port": 5060,
        "target": "sip.example.com",
    }


def test_txt_rdata():
    rdata = bytes([11]) + b"v=spf1 -all" + bytes([3]) + b"two"
    info = parse_udp(message(1, 0x8180, [("t.example.com", 16)], [("t.example.com", 16, rdata)]))
    assert info.answers[0].value == ["v=spf1 -all", "two"]


def test_soa_rdata():
    rdata = (
        dns_name("ns.example.com")
        + dns_name("hostmaster.example.com")
        + struct.pack("!IIIII", 1, 2, 3, 4, 5)
    )
    info = parse_udp(message(1, 0x8180, [("example.com", 6)], [("example.com", 6, rdata)]))
    assert info.answers[0].value == {
        "mname": "ns.example.com",
        "rname": "hostmaster.example.com",
        "serial": 1,
        "refresh": 2,
        "retry": 3,
        "expire": 4,
        "minimum": 5,
    }


def test_unknown_rdata_is_hex_encoded():
    info = parse_udp(
        message(1, 0x8180, [("x.example.com", 99)], [("x.example.com", 99, b"\xde\xad\xbe\xef")])
    )
    assert info.answers[0].rdata == "deadbeef"
    assert info.answers[0].value is None
    assert info.answers[0].type_name == "SPF"


def test_bad_rdata_is_kept_on_the_record_and_parsing_continues():
    issues = Issues("application")
    raw = message(
        1,
        0x8180,
        [("a.example.com", 1)],
        [("a.example.com", 1, b"\x01\x02\x03"), ("a.example.com", 1, b"\x0a\x00\x00\x01")],
    )
    info = parse_udp(raw, issues)
    bad, good = info.answers
    assert bad.value is None
    assert bad.rdata == "010203"
    assert bad.rdata_error == Issue(
        "application", "decode_error", "A record has rdlength 3, expected 4", {}
    )
    assert good.value == "10.0.0.1"
    assert good.rdata_error is None
    assert issues.records == []


def test_opt_record_reports_the_udp_payload_size():
    opt = b"\x00" + struct.pack("!HHIH", 41, 4096, 0, 0)
    raw = message(1, 0x0100, [("example.com", 1)])
    raw = raw[:10] + (1).to_bytes(2, "big") + raw[12:] + opt
    record = parse_udp(raw).additionals[0]
    assert record.name == "."
    assert record.type_name == "OPT"
    assert record.udp_payload_size == 4096
    assert record.rdata == ""


def test_unknown_opcode_and_rcode_are_named():
    info = parse_udp(message(1, 0x1800 | 0x000B, [("example.com", 1)]))
    assert info.opcode == 3
    assert info.opcode_name == "OPCODE3"
    assert info.rcode_name == "RCODE11"


def test_rcode_is_named():
    info = parse_udp(message(1, 0x8183, [("missing.example.com", 1)]))
    assert info.rcode == 3
    assert info.rcode_name == "NXDOMAIN"


def test_over_tcp_uses_the_length_prefix():
    message_bytes = message(0x2222, 0x0100, [("example.com", 1)])
    prefixed = len(message_bytes).to_bytes(2, "big") + message_bytes + b"next"
    info = parse(prefixed, tcp=True, issues=Issues("application"))
    assert info.tcp is True
    assert info.id == 0x2222
    assert info.questions[0].name == "example.com"


def test_tcp_length_prefix_longer_than_capture():
    with pytest.raises(ParseError) as caught:
        parse(b"\x00\xff" + message(1, 0x0100, [("example.com", 1)]), tcp=True, issues=Issues("a"))
    assert caught.value.code == "truncated_packet"
    assert caught.value.context == {"declared": 255, "captured": 29}


def test_tcp_length_prefix_below_the_header_size():
    with pytest.raises(ParseError) as caught:
        parse(b"\x00\x05" + b"\x00" * 12, tcp=True, issues=Issues("a"))
    assert caught.value.code == "decode_error"


def test_compression_pointer_loop_is_detected():
    with pytest.raises(ParseError) as caught:
        parse_udp(DNS_POINTER_LOOP)
    assert caught.value.code == "decode_error"
    assert "pointer loop" in caught.value.message


@pytest.mark.parametrize(
    "payload,code",
    [
        (b"", "truncated_packet"),
        (b"\x12\x34\x01", "truncated_packet"),
        (b"\x00" * 12, "decode_error"),
    ],
)
def test_malformed_messages(payload, code):
    with pytest.raises(ParseError) as caught:
        parse_udp(payload)
    assert caught.value.code == code


def test_truncated_question_is_reported():
    with pytest.raises(ParseError) as caught:
        parse_udp(DNS_QUERY[:-1])
    assert caught.value.code == "truncated_packet"


def test_record_rdata_beyond_the_message_is_reported():
    raw = message(1, 0x8180, [("a.example.com", 1)], [("a.example.com", 1, b"\x01\x02\x03\x04")])
    with pytest.raises(ParseError) as caught:
        parse_udp(raw[:-3])
    assert caught.value.code == "truncated_packet"
    assert caught.value.context == {"declared": 4, "available": 1}


def test_score_rewards_a_plausible_query():
    confidence, evidence = score(DNS_QUERY, False)
    assert confidence == pytest.approx(0.9)
    assert evidence == "DNS header, plausible question name, known qtype A"


def test_score_caps_a_response_with_answers_at_one():
    confidence, evidence = score(DNS_ANSWER, False)
    assert confidence == 1.0
    assert evidence.endswith("response with answers")


def test_score_flags_an_unknown_opcode():
    assert score(message(1, 0x1800, [("example.com", 1)]), False) == (
        0.2,
        "DNS header with an unknown opcode",
    )


@pytest.mark.parametrize(
    "payload,tcp",
    [
        (b"\x00" * 11, False),
        (b"\x00" * 12, False),
        (DNS_QUERY, True),
        (DNS_POINTER_LOOP, False),
    ],
)
def test_score_is_zero_when_the_message_does_not_parse(payload, tcp):
    assert score(payload, tcp) == (0.0, None)


def test_score_over_tcp_needs_the_length_prefix():
    prefixed = len(DNS_QUERY).to_bytes(2, "big") + DNS_QUERY
    assert score(prefixed, True)[0] == pytest.approx(0.9)
