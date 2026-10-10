import pytest
from golden import DST, ICMP, IPV4_MF, IPV4_OPTIONS, IPV6, SRC, TCP_DATA, TCP_SYN_OPTIONS, UDP

from ids.issues import Issue, Issues, ParseError
from ids.model import IpOption, Ipv4Flags
from ids.parsers.checksum import internet_checksum
from ids.parsers.network import NetworkResult, parse_ipv4, parse_options


def ipv4_bytes(frame):
    return frame[14:]


def parse(data, issues=None):
    return parse_ipv4(data, issues if issues is not None else Issues("network"))


def with_options(options: bytes) -> bytes:
    """IPv4 header (no payload) carrying `options`, with a valid header checksum."""
    ihl = 5 + len(options) // 4
    header = bytearray(ipv4_bytes(TCP_SYN_OPTIONS)[:20] + options)
    header[0] = 0x40 | ihl
    header[2:4] = (ihl * 4).to_bytes(2, "big")
    header[10:12] = b"\x00\x00"
    header[10:12] = internet_checksum(bytes(header)).to_bytes(2, "big")
    return bytes(header)


def test_header_fields():
    issues = Issues("network")
    result = parse(ipv4_bytes(TCP_SYN_OPTIONS), issues)
    assert isinstance(result, NetworkResult)
    info = result.info
    assert info.protocol == "IPv4"
    assert info.version == 4
    assert info.header_length == 20
    assert info.src_ip == SRC
    assert info.dst_ip == DST
    assert info.ttl == 64
    assert info.identification == 4242
    assert info.dscp == 0
    assert info.ecn == 0
    assert info.protocol_number == 6
    assert info.protocol_name == "TCP"
    assert info.total_length == 64
    assert info.declared_payload_length == 44
    assert info.captured_payload_length == 44
    assert info.captured_truncated is False
    assert info.options == []
    assert issues.records == []


def test_good_checksum_is_accepted():
    assert parse(ipv4_bytes(TCP_SYN_OPTIONS)).info.header_checksum_valid is True
    assert parse(ipv4_bytes(UDP)).info.header_checksum_valid is True


def test_corrupted_checksum_is_detected():
    raw = bytearray(ipv4_bytes(TCP_DATA))
    raw[10] ^= 0xFF
    assert parse(bytes(raw)).info.header_checksum_valid is False


def test_options_are_decoded_and_header_length_grows():
    result = parse(ipv4_bytes(IPV4_OPTIONS))
    assert result.info.header_length == 28
    assert [option.name for option in result.info.options] == ["NOP", "RR"]
    assert result.info.options[1] == IpOption(type=7, name="RR", length=7, data="0409090909")
    assert result.info.header_checksum_valid is True
    assert len(result.payload) == 20


def test_eol_with_zero_padding_adds_no_padding_entry():
    options = parse(with_options(bytes.fromhex("01000000"))).info.options
    assert options == [IpOption(type=1, name="NOP"), IpOption(type=0, name="EOL")]


def test_non_zero_bytes_after_eol_become_a_padding_entry():
    options = parse_options(bytes.fromhex("0100ab00"))
    assert options == [
        IpOption(type=1, name="NOP"),
        IpOption(type=0, name="EOL"),
        IpOption(type=0, name="PADDING", length=2),
    ]


def test_option_length_past_the_header_is_malformed():
    assert parse_options(bytes.fromhex("070a0400")) == [
        IpOption(type=7, name="RR", malformed=True, declared_length=10, available=4)
    ]


def test_option_without_a_length_byte_is_truncated():
    assert parse_options(bytes.fromhex("01010182")) == [
        IpOption(type=1, name="NOP"),
        IpOption(type=1, name="NOP"),
        IpOption(type=1, name="NOP"),
        IpOption(type=130, name="TRUNCATED"),
    ]


def test_unknown_option_type_is_named():
    assert parse_options(bytes.fromhex("63030a00")) == [
        IpOption(type=99, name="UNKNOWN(99)", length=3, data="0a"),
        IpOption(type=0, name="EOL"),
    ]


def test_more_fragments_sets_fragmented_flag():
    info = parse(ipv4_bytes(IPV4_MF)).info
    assert info.flags == Ipv4Flags(reserved=False, df=False, mf=True)
    assert info.fragment_offset == 0
    assert info.fragmented is True


def test_ethernet_padding_is_trimmed_without_an_issue():
    issues = Issues("network")
    result = parse(ipv4_bytes(TCP_DATA) + b"\x00" * 10, issues)
    assert result.info.total_length == 58
    assert len(result.payload) == 38
    assert result.info.captured_truncated is False
    assert issues.records == []


def test_short_capture_is_flagged_and_reported():
    issues = Issues("network")
    result = parse(ipv4_bytes(TCP_DATA)[:40], issues)
    assert result.info.captured_truncated is True
    assert result.info.declared_payload_length == 38
    assert result.info.captured_payload_length == 20
    assert result.payload == ipv4_bytes(TCP_DATA)[20:40]
    assert issues.records == [
        Issue(
            "network",
            "truncated_packet",
            "captured bytes are shorter than the IPv4 total length",
            {"declared": 58, "captured": 40},
        )
    ]


def test_ipv6_is_unsupported():
    with pytest.raises(ParseError) as caught:
        parse(ipv4_bytes(IPV6))
    assert caught.value.code == "unsupported_protocol"
    assert caught.value.context == {"version": 6}


def test_other_ip_versions_are_unsupported():
    with pytest.raises(ParseError) as caught:
        parse(b"\x50" + b"\x00" * 19)
    assert caught.value.code == "unsupported_protocol"
    assert caught.value.context == {"version": 5}


def test_icmp_is_parsed_as_a_network_payload():
    info = parse(ipv4_bytes(ICMP)).info
    assert info.protocol_number == 1
    assert info.protocol_name == "ICMP"


def test_unknown_protocol_number_is_named():
    raw = bytearray(ipv4_bytes(ICMP))
    raw[9] = 200
    assert parse(bytes(raw)).info.protocol_name == "UNKNOWN(200)"


def test_empty_and_short_input():
    with pytest.raises(ParseError) as caught:
        parse(b"")
    assert caught.value.code == "truncated_packet"
    assert caught.value.context == {"captured": 0}
    with pytest.raises(ParseError) as caught:
        parse(ipv4_bytes(TCP_SYN_OPTIONS)[:12])
    assert caught.value.code == "truncated_packet"
    assert caught.value.context == {"declared": 20, "captured": 12}


def test_invalid_ihl_is_malformed():
    raw = bytearray(ipv4_bytes(TCP_SYN_OPTIONS))
    raw[0] = 0x40
    with pytest.raises(ParseError) as caught:
        parse(bytes(raw))
    assert caught.value.code == "malformed_header"
    assert caught.value.context == {"ihl": 0}


def test_total_length_below_header_length_is_malformed():
    raw = bytearray(ipv4_bytes(TCP_SYN_OPTIONS))
    raw[2:4] = (10).to_bytes(2, "big")
    with pytest.raises(ParseError) as caught:
        parse(bytes(raw))
    assert caught.value.code == "malformed_header"
    assert caught.value.context == {"total_length": 10, "header_length": 20}


def test_truncated_options_are_reported():
    raw = bytearray(ipv4_bytes(IPV4_OPTIONS))
    raw[0] = 0x48
    with pytest.raises(ParseError) as caught:
        parse(bytes(raw)[:24])
    assert caught.value.code == "truncated_packet"
    assert caught.value.context == {"declared": 32, "captured": 24}
