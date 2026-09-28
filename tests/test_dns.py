import struct

import pytest
from golden import DNS_ANSWER, DNS_POINTER_LOOP, DNS_QUERY, dns_name

from pcparser.errors import DecodeError, TruncatedPacketError
from pcparser.parsers.dns import parse, read_name


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


def test_query_question_and_flags():
    info = parse(DNS_QUERY)
    assert info["kind"] == "query"
    assert info["id"] == 0x1234
    assert info["flags"]["rd"] is True
    assert info["flags"]["qr"] is False
    assert info["opcode_name"] == "QUERY"
    assert info["rcode_name"] == "NOERROR"
    assert info["counts"] == {"questions": 1, "answers": 0, "authorities": 0, "additionals": 0}
    assert info["questions"] == [
        {"name": "example.com", "type": 1, "type_name": "A", "class": 1, "class_name": "IN"}
    ]
    assert info["answers"] == []


def test_response_with_one_answer():
    info = parse(DNS_ANSWER)
    assert info["kind"] == "response"
    assert info["flags"]["qr"] is True
    assert info["flags"]["ra"] is True
    assert info["counts"]["answers"] == 1
    assert info["answers"][0]["name"] == "example.com"
    assert info["answers"][0]["type_name"] == "A"
    assert info["answers"][0]["ttl"] == 300
    assert info["answers"][0]["value"] == "93.184.216.34"


def test_name_compression_pointer_is_followed():
    raw = dns_name("example.com")
    name, offset = read_name(raw, 0)
    assert name == "example.com"
    assert offset == len(raw)
    compressed = raw + b"\xc0\x00"
    assert read_name(compressed, len(raw)) == ("example.com", len(raw) + 2)


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
    info = parse(message(1, 0x8180, [("q.example.com", 1)], [("q.example.com", rtype, rdata)]))
    assert info["answers"][0]["value"] == expected


def test_mx_rdata():
    rdata = struct.pack("!H", 10) + dns_name("mail.example.com")
    info = parse(message(1, 0x8180, [("example.com", 15)], [("example.com", 15, rdata)]))
    assert info["answers"][0]["value"] == {"preference": 10, "exchange": "mail.example.com"}


def test_srv_rdata():
    rdata = struct.pack("!HHH", 10, 60, 5060) + dns_name("sip.example.com")
    info = parse(
        message(1, 0x8180, [("_sip._tcp.example.com", 33)], [("_sip._tcp.example.com", 33, rdata)])
    )
    assert info["answers"][0]["value"] == {
        "priority": 10,
        "weight": 60,
        "port": 5060,
        "target": "sip.example.com",
    }


def test_txt_rdata():
    rdata = bytes([11]) + b"v=spf1 -all"
    info = parse(message(1, 0x8180, [("t.example.com", 16)], [("t.example.com", 16, rdata)]))
    assert info["answers"][0]["value"] == ["v=spf1 -all"]


def test_soa_rdata():
    rdata = (
        dns_name("ns.example.com")
        + dns_name("hostmaster.example.com")
        + struct.pack("!IIIII", 1, 2, 3, 4, 5)
    )
    info = parse(message(1, 0x8180, [("example.com", 6)], [("example.com", 6, rdata)]))
    assert info["answers"][0]["value"] == {
        "mname": "ns.example.com",
        "rname": "hostmaster.example.com",
        "serial": 1,
        "refresh": 2,
        "retry": 3,
        "expire": 4,
        "minimum": 5,
    }


def test_unknown_rdata_is_hex_encoded():
    info = parse(
        message(1, 0x8180, [("x.example.com", 99)], [("x.example.com", 99, b"\xde\xad\xbe\xef")])
    )
    assert info["answers"][0]["rdata"] == "deadbeef"
    assert "value" not in info["answers"][0]


def test_rcode_is_named():
    info = parse(message(1, 0x8183, [("missing.example.com", 1)]))
    assert info["rcode"] == 3
    assert info["rcode_name"] == "NXDOMAIN"


def test_over_tcp_uses_the_length_prefix():
    message_bytes = message(0x2222, 0x0100, [("example.com", 1)])
    info = parse(len(message_bytes).to_bytes(2, "big") + message_bytes, tcp=True)
    assert info["tcp"] is True
    assert info["id"] == 0x2222
    assert info["questions"][0]["name"] == "example.com"


def test_tcp_length_prefix_longer_than_capture():
    with pytest.raises(TruncatedPacketError):
        parse(b"\x00\xff" + message(1, 0x0100, [("example.com", 1)]), tcp=True)


def test_compression_pointer_loop_is_detected():
    with pytest.raises(DecodeError) as caught:
        parse(DNS_POINTER_LOOP)
    assert "pointer loop" in caught.value.message


@pytest.mark.parametrize(
    "payload,error",
    [
        (b"", TruncatedPacketError),
        (b"\x12\x34\x01", TruncatedPacketError),
        (b"\x00" * 12, DecodeError),
    ],
)
def test_malformed_messages(payload, error):
    with pytest.raises(error):
        parse(payload)


def test_truncated_question_is_reported():
    with pytest.raises(TruncatedPacketError):
        parse(DNS_QUERY[:-1])


def test_record_rdata_beyond_the_message_is_reported():
    raw = message(1, 0x8180, [("a.example.com", 1)], [("a.example.com", 1, b"\x01\x02\x03\x04")])
    with pytest.raises(TruncatedPacketError):
        parse(raw[:-3])
