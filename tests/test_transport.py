import pytest
from golden import DST, SRC, TCP_DATA, TCP_FIN, TCP_SYN_OPTIONS, UDP

from ids.issues import Issues, ParseError
from ids.model import TcpFlags, TcpInfo, TcpOption, UdpInfo
from ids.parsers.link import parse_link
from ids.parsers.network import IPPROTO_TCP, IPPROTO_UDP, parse_ipv4
from ids.parsers.transport import TransportResult, parse_transport, tcp_options


def transport(frame, **overrides):
    net = parse_ipv4(parse_link(frame, 1).payload, Issues("network"))
    kwargs = {
        "src_ip": net.info.src_ip,
        "dst_ip": net.info.dst_ip,
        "declared_length": net.info.declared_payload_length,
    }
    kwargs.update(overrides)
    return parse_transport(net.info.protocol_number, net.payload, **kwargs)


def test_syn_with_options():
    result = transport(TCP_SYN_OPTIONS)
    assert isinstance(result, TransportResult)
    info = result.info
    assert isinstance(info, TcpInfo)
    assert info.protocol == "TCP"
    assert info.src_port == 51234
    assert info.dst_port == 80
    assert info.seq == 1000
    assert info.ack == 0
    assert info.flags == TcpFlags(
        fin=False,
        syn=True,
        rst=False,
        psh=False,
        ack=False,
        urg=False,
        ece=False,
        cwr=False,
        ns=False,
    )
    assert info.flags_string == "S"
    assert info.flags_list == ["SYN"]
    assert info.header_length == 44
    assert info.window == 8192
    assert info.checksum_valid is True
    assert info.payload_length == 0
    assert result.payload == b""

    names = [option.name for option in info.options]
    assert names == ["MSS", "SACK-Permitted", "WScale", "NOP", "NOP", "Timestamps", "EOL"]
    assert info.options[0].mss == 1460
    assert info.options[2].shift == 7
    assert info.options[5].tsval == 111
    assert info.options[5].tsecr == 0


def test_psh_ack_carries_the_payload():
    result = transport(TCP_DATA)
    assert result.info.flags_string == "PA"
    assert result.info.flags_list == ["PSH", "ACK"]
    assert result.info.header_length == 20
    assert result.info.payload_length == 18
    assert result.payload == b"GET / HTTP/1.1\r\n\r\n"
    assert result.info.checksum_valid is True


def test_fin_psh_ack_flag_string():
    assert transport(TCP_FIN).info.flags_string == "FPA"


def test_tcp_checksum_is_not_verified_without_a_declared_length():
    assert transport(TCP_DATA, declared_length=None).info.checksum_valid is None


def test_sack_blocks_and_unknown_options():
    raw = bytes.fromhex("050a000000010000000a") + bytes.fromhex("fe0399") + bytes.fromhex("00")
    assert tcp_options(raw) == [
        TcpOption(type=5, name="SACK", length=10, blocks=[[1, 10]]),
        TcpOption(type=254, name="UNKNOWN(254)", length=3, data="99"),
        TcpOption(type=0, name="EOL"),
    ]


def test_tcp_option_overrunning_the_header_is_malformed():
    assert tcp_options(bytes.fromhex("0101080a00000000")) == [
        TcpOption(type=1, name="NOP"),
        TcpOption(type=1, name="NOP"),
        TcpOption(type=8, name="Timestamps", malformed=True, declared_length=10, available=6),
    ]


def test_tcp_option_without_a_length_byte_is_malformed():
    assert tcp_options(bytes.fromhex("010102")) == [
        TcpOption(type=1, name="NOP"),
        TcpOption(type=1, name="NOP"),
        TcpOption(type=2, name="MSS", malformed=True),
    ]


def test_udp_fields():
    result = transport(UDP)
    info = result.info
    assert isinstance(info, UdpInfo)
    assert info.protocol == "UDP"
    assert info.src_port == 40000
    assert info.dst_port == 53
    assert info.length == 17
    assert info.declared_payload_length == 9
    assert info.payload_length == 9
    assert info.checksum_valid is True
    assert info.captured_truncated is False
    assert result.payload == b"payload01"


def test_udp_zero_checksum_means_not_computed():
    raw = bytearray(UDP[14:][20:])
    raw[6:8] = b"\x00\x00"
    info = parse_transport(
        IPPROTO_UDP, bytes(raw), src_ip=SRC, dst_ip=DST, declared_length=len(raw)
    ).info
    assert info.checksum == "0x0000"
    assert info.checksum_valid is None


def test_checksum_is_not_verified_when_the_capture_is_short():
    net = parse_ipv4(parse_link(UDP, 1).payload, Issues("network"))
    info = parse_transport(
        IPPROTO_UDP, net.payload[:12], src_ip=SRC, dst_ip=DST, declared_length=17
    ).info
    assert info.checksum_valid is None


def test_corrupted_tcp_checksum_is_detected():
    segment = bytearray(TCP_DATA[14:][20:])
    segment[16] ^= 0xFF
    info = parse_transport(
        IPPROTO_TCP, bytes(segment), src_ip=SRC, dst_ip=DST, declared_length=len(segment)
    ).info
    assert info.checksum_valid is False


def test_tcp_data_offset_below_five_is_malformed():
    raw = bytearray(TCP_DATA[14:][20:])
    raw[12:14] = (0x4018).to_bytes(2, "big")
    with pytest.raises(ParseError) as caught:
        parse_transport(IPPROTO_TCP, bytes(raw), src_ip=SRC, dst_ip=DST)
    assert caught.value.code == "malformed_header"
    assert caught.value.context == {"data_offset": 4}


def test_tcp_header_shorter_than_twenty_bytes():
    with pytest.raises(ParseError) as caught:
        parse_transport(IPPROTO_TCP, b"\x00" * 10, src_ip=SRC, dst_ip=DST)
    assert caught.value.code == "truncated_packet"
    assert caught.value.context == {"declared": 20, "captured": 10}


def test_tcp_options_cut_by_the_capture_are_truncated():
    raw = bytearray(TCP_DATA[14:][20:40])
    raw[12] = 0x60
    with pytest.raises(ParseError) as caught:
        parse_transport(IPPROTO_TCP, bytes(raw), src_ip=SRC, dst_ip=DST)
    assert caught.value.code == "truncated_packet"
    assert caught.value.context == {"declared": 24, "captured": 20}


def test_udp_length_below_eight_is_malformed():
    header = bytes.fromhex("9c40") + bytes.fromhex("9c40") + bytes.fromhex("0004") + b"\x00\x00"
    with pytest.raises(ParseError) as caught:
        parse_transport(IPPROTO_UDP, header, src_ip=SRC, dst_ip=DST)
    assert caught.value.code == "malformed_header"
    assert caught.value.context == {"length": 4}


def test_udp_declared_length_longer_than_capture_is_flagged():
    header = bytes.fromhex("9c40") + bytes.fromhex("9c40") + bytes.fromhex("0064") + b"\x00\x00"
    result = parse_transport(IPPROTO_UDP, header + b"only12bytes!", src_ip=SRC, dst_ip=DST)
    assert result.info.captured_truncated is True
    assert result.info.declared_payload_length == 92
    assert result.info.payload_length == 12
    assert result.payload == b"only12bytes!"


def test_non_first_fragment_has_no_transport_header():
    with pytest.raises(ParseError) as caught:
        parse_transport(IPPROTO_TCP, b"\x00" * 20, src_ip=SRC, dst_ip=DST, fragment_offset=8)
    assert caught.value.code == "unsupported_protocol"
    assert caught.value.context == {"fragment_offset": 8}


def test_other_ip_protocols_are_unsupported():
    with pytest.raises(ParseError) as caught:
        parse_transport(1, b"\x08\x00" + b"\x00" * 6, src_ip=SRC, dst_ip=DST)
    assert caught.value.code == "unsupported_protocol"
    assert caught.value.context == {"protocol_number": 1}
