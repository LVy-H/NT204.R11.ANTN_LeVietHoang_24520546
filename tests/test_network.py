import pytest

from pcparser.errors import MalformedHeaderError, TruncatedPacketError, UnsupportedProtocolError
from pcparser.parsers.network import parse_ipv4

from golden import DST, ICMP, IPV4_MF, IPV4_OPTIONS, IPV6, SRC, TCP_DATA, TCP_SYN_OPTIONS, UDP


def ipv4_bytes(frame):
    return frame[14:]


def test_header_fields():
    info = parse_ipv4(ipv4_bytes(TCP_SYN_OPTIONS)).info
    assert info["protocol"] == "IPv4"
    assert info["version"] == 4
    assert info["header_length"] == 20
    assert info["src_ip"] == SRC
    assert info["dst_ip"] == DST
    assert info["ttl"] == 64
    assert info["identification"] == 4242
    assert info["dscp"] == 0
    assert info["ecn"] == 0
    assert info["protocol_number"] == 6
    assert info["protocol_name"] == "TCP"
    assert info["total_length"] == 64
    assert info["declared_payload_length"] == 44
    assert info["captured_payload_length"] == 44
    assert info["captured_truncated"] is False
    assert info["options"] == []


def test_good_checksum_is_accepted():
    assert parse_ipv4(ipv4_bytes(TCP_SYN_OPTIONS)).info["header_checksum_valid"] is True
    assert parse_ipv4(ipv4_bytes(UDP)).info["header_checksum_valid"] is True


def test_corrupted_checksum_is_detected():
    raw = bytearray(ipv4_bytes(TCP_DATA))
    raw[10] ^= 0xFF
    assert parse_ipv4(bytes(raw)).info["header_checksum_valid"] is False


def test_options_are_decoded_and_header_length_grows():
    result = parse_ipv4(ipv4_bytes(IPV4_OPTIONS))
    assert result.info["header_length"] == 28
    assert [option["name"] for option in result.info["options"]] == ["NOP", "RR"]
    assert result.info["options"][1]["data"] == "0409090909"
    assert result.info["header_checksum_valid"] is True
    assert len(result.payload) == 20


def test_more_fragments_sets_fragmented_flag():
    info = parse_ipv4(ipv4_bytes(IPV4_MF)).info
    assert info["flags"] == {"reserved": False, "df": False, "mf": True}
    assert info["fragment_offset"] == 0
    assert info["fragmented"] is True


def test_ethernet_padding_is_trimmed_to_total_length():
    padded = ipv4_bytes(TCP_DATA) + b"\x00" * 10
    result = parse_ipv4(padded)
    assert result.info["total_length"] == 58
    assert len(result.payload) == 38
    assert result.info["captured_truncated"] is False


def test_short_capture_is_flagged_not_raised():
    result = parse_ipv4(ipv4_bytes(TCP_DATA)[:40])
    assert result.info["captured_truncated"] is True
    assert result.info["declared_payload_length"] == 38
    assert result.info["captured_payload_length"] == 20


def test_ipv6_is_unsupported():
    with pytest.raises(UnsupportedProtocolError) as caught:
        parse_ipv4(ipv4_bytes(IPV6))
    assert caught.value.context == {"version": 6}
    assert caught.value.stage == "network"


def test_icmp_is_parsed_as_a_network_payload():
    info = parse_ipv4(ipv4_bytes(ICMP)).info
    assert info["protocol_number"] == 1
    assert info["protocol_name"] == "ICMP"


def test_empty_and_short_input():
    with pytest.raises(TruncatedPacketError):
        parse_ipv4(b"")
    with pytest.raises(TruncatedPacketError) as caught:
        parse_ipv4(ipv4_bytes(TCP_SYN_OPTIONS)[:12])
    assert caught.value.context == {"declared": 20, "captured": 12}


def test_invalid_ihl_is_malformed():
    raw = bytearray(ipv4_bytes(TCP_SYN_OPTIONS))
    raw[0] = 0x40
    with pytest.raises(MalformedHeaderError):
        parse_ipv4(bytes(raw))


def test_total_length_below_header_length_is_malformed():
    raw = bytearray(ipv4_bytes(TCP_SYN_OPTIONS))
    raw[2:4] = (10).to_bytes(2, "big")
    with pytest.raises(MalformedHeaderError):
        parse_ipv4(bytes(raw))


def test_truncated_options_are_reported():
    raw = bytearray(ipv4_bytes(IPV4_OPTIONS))
    raw[0] = 0x48
    with pytest.raises(TruncatedPacketError):
        parse_ipv4(bytes(raw)[:24])
