import pytest

from pcparser.errors import MalformedHeaderError, TruncatedPacketError, UnsupportedProtocolError
from pcparser.parsers.link import parse_link
from pcparser.parsers.network import parse_ipv4
from pcparser.parsers.transport import parse_transport

from golden import TCP_DATA, TCP_FIN, TCP_SYN_OPTIONS, UDP


def transport(frame, **overrides):
    link = parse_link(frame, 1)
    net = parse_ipv4(link.payload)
    kwargs = {
        "src_ip": net.info["src_ip"],
        "dst_ip": net.info["dst_ip"],
        "declared_length": net.info["declared_payload_length"],
    }
    kwargs.update(overrides)
    return parse_transport(net.info["protocol_number"], net.payload, **kwargs)


def test_syn_with_options():
    result = transport(TCP_SYN_OPTIONS)
    info = result.info
    assert info["protocol"] == "TCP"
    assert info["src_port"] == 51234
    assert info["dst_port"] == 80
    assert info["seq"] == 1000
    assert info["ack"] == 0
    assert info["flags"] == {
        "fin": False, "syn": True, "rst": False, "psh": False,
        "ack": False, "urg": False, "ece": False, "cwr": False, "ns": False,
    }
    assert info["flags_string"] == "S"
    assert info["flags_list"] == ["SYN"]
    assert info["header_length"] == 44
    assert info["window"] == 8192
    assert info["checksum_valid"] is True
    assert info["payload_length"] == 0
    assert result.payload == b""

    names = [option["name"] for option in info["options"]]
    assert names == ["MSS", "SACK-Permitted", "WScale", "NOP", "NOP", "Timestamps", "EOL"]
    assert info["options"][0]["mss"] == 1460
    assert info["options"][2]["shift"] == 7
    assert info["options"][5]["tsval"] == 111


def test_psh_ack_carries_the_payload():
    result = transport(TCP_DATA)
    assert result.info["flags_string"] == "PA"
    assert result.info["header_length"] == 20
    assert result.info["payload_length"] == 18
    assert result.payload == b"GET / HTTP/1.1\r\n\r\n"
    assert result.info["checksum_valid"] is True


def test_fin_psh_ack_flag_string():
    assert transport(TCP_FIN).info["flags_string"] == "FPA"


def test_udp_fields():
    result = transport(UDP)
    info = result.info
    assert info["protocol"] == "UDP"
    assert info["src_port"] == 40000
    assert info["dst_port"] == 53
    assert info["length"] == 17
    assert info["declared_payload_length"] == 9
    assert info["payload_length"] == 9
    assert info["checksum_valid"] is True
    assert result.payload == b"payload01"


def test_udp_zero_checksum_means_not_computed():
    raw = bytearray(UDP[14:][20:])
    raw[6:8] = b"\x00\x00"
    info = parse_transport(17, bytes(raw), src_ip="10.0.0.1", dst_ip="10.0.0.2", declared_length=len(raw)).info
    assert info["checksum"] == "0x0000"
    assert info["checksum_valid"] is None


def test_checksum_is_not_verified_when_the_capture_is_short():
    link = parse_link(UDP, 1)
    net = parse_ipv4(link.payload)
    info = parse_transport(17, net.payload[:12], src_ip="10.0.0.1", dst_ip="10.0.0.2", declared_length=17).info
    assert info["checksum_valid"] is None


def test_corrupted_tcp_checksum_is_detected():
    segment = bytearray(TCP_DATA[14:][20:])
    segment[16] ^= 0xFF
    info = parse_transport(
        6, bytes(segment), src_ip="10.0.0.1", dst_ip="10.0.0.2", declared_length=len(segment)
    ).info
    assert info["checksum_valid"] is False


def test_tcp_data_offset_below_five_is_malformed():
    raw = bytearray(TCP_DATA[14:][20:])
    raw[12:14] = (0x4018).to_bytes(2, "big")
    with pytest.raises(MalformedHeaderError):
        parse_transport(6, bytes(raw), src_ip="10.0.0.1", dst_ip="10.0.0.2")


def test_tcp_header_shorter_than_twenty_bytes():
    with pytest.raises(TruncatedPacketError):
        parse_transport(6, b"\x00" * 10, src_ip="10.0.0.1", dst_ip="10.0.0.2")


def test_udp_length_below_eight_is_malformed():
    header = bytes.fromhex("9c40") + bytes.fromhex("9c40") + bytes.fromhex("0004") + bytes.fromhex("0000")
    with pytest.raises(MalformedHeaderError):
        parse_transport(17, header, src_ip="10.0.0.1", dst_ip="10.0.0.2")


def test_udp_declared_length_longer_than_capture_is_flagged():
    header = bytes.fromhex("9c40") + bytes.fromhex("9c40") + bytes.fromhex("0064") + bytes.fromhex("0000")
    info = parse_transport(17, header + b"only12bytes!", src_ip="10.0.0.1", dst_ip="10.0.0.2").info
    assert info["captured_truncated"] is True
    assert info["declared_payload_length"] == 92
    assert info["payload_length"] == 12


def test_non_first_fragment_has_no_transport_header():
    with pytest.raises(UnsupportedProtocolError):
        parse_transport(6, b"\x00" * 20, src_ip="10.0.0.1", dst_ip="10.0.0.2", fragment_offset=8)


def test_other_ip_protocols_are_unsupported():
    with pytest.raises(UnsupportedProtocolError) as caught:
        parse_transport(1, b"\x08\x00" + b"\x00" * 6, src_ip="10.0.0.1", dst_ip="10.0.0.2")
    assert caught.value.context["protocol_number"] == 1
