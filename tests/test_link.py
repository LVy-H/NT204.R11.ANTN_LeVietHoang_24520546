import pytest
from golden import ICMP, IPV6, SERVER_MAC, TCP_SYN_OPTIONS, UDP, VLAN

from pcparser.capture.base import DLT_EN10MB, DLT_LINUX_SLL, DLT_LINUX_SLL2, DLT_NULL, DLT_RAW
from pcparser.errors import TruncatedPacketError, UnsupportedProtocolError
from pcparser.parsers.link import parse_link


def test_ethernet_fields_and_payload():
    result = parse_link(TCP_SYN_OPTIONS, DLT_EN10MB)
    assert result.info["protocol"] == "Ethernet"
    assert result.info["src_mac"] == "02:00:00:00:00:01"
    assert result.info["dst_mac"] == SERVER_MAC
    assert result.info["ethertype"] == 0x0800
    assert result.info["ethertype_name"] == "IPv4"
    assert result.network_protocol == "IPv4"
    assert result.payload[0] == 0x45


def test_vlan_tag_is_reported():
    result = parse_link(VLAN, DLT_EN10MB)
    assert result.info["vlan"] == [{"tpid": "0x8100", "pcp": 5, "dei": False, "vid": 42}]
    assert result.network_protocol == "IPv4"
    assert result.payload[0] == 0x45


def test_icmp_frame_resolves_to_ipv4():
    result = parse_link(ICMP, DLT_EN10MB)
    assert result.network_protocol == "IPv4"
    assert len(result.payload) == 28
    assert result.payload[9] == 1


def test_unknown_ethertype_is_not_an_error():
    frame = bytes.fromhex("020000000002020000000001") + bytes.fromhex("1234") + b"noise"
    result = parse_link(frame, DLT_EN10MB)
    assert result.network_protocol is None
    assert result.info["ethertype_name"] == "0x1234"


def test_arp_ethertype_is_reported():
    frame = bytes.fromhex("020000000002020000000001") + bytes.fromhex("0806") + b"\x00" * 28
    result = parse_link(frame, DLT_EN10MB)
    assert result.network_protocol == "ARP"


def test_truncated_ethernet_reports_declared_and_captured():
    with pytest.raises(TruncatedPacketError) as caught:
        parse_link(b"\x02\x00\x00\x00\x00\x02", DLT_EN10MB)
    assert caught.value.context == {"declared": 14, "captured": 6}
    assert caught.value.stage == "link"


def test_unsupported_linktype_is_rejected():
    with pytest.raises(UnsupportedProtocolError):
        parse_link(b"\x00" * 64, 999)


def test_linux_cooked_v1():
    header = bytes.fromhex("000100010006") + bytes.fromhex("020000000001") + bytes.fromhex("0000")
    header += bytes.fromhex("0800")
    result = parse_link(header + UDP[14:], DLT_LINUX_SLL)
    assert result.info["protocol"] == "LINUX_SLL"
    assert result.info["packet_type"] == 1
    assert result.info["address"] == "02:00:00:00:00:01"
    assert result.network_protocol == "IPv4"


def test_linux_cooked_v2():
    header = bytes.fromhex("0800") + bytes.fromhex("0000") + bytes.fromhex("00000005")
    header += bytes.fromhex("0001") + bytes.fromhex("00") + bytes.fromhex("06")
    header += bytes.fromhex("020000000001") + bytes.fromhex("0000")
    result = parse_link(header + UDP[14:], DLT_LINUX_SLL2)
    assert result.info["protocol"] == "LINUX_SLL2"
    assert result.info["interface_index"] == 5
    assert result.network_protocol == "IPv4"


@pytest.mark.parametrize("family,expected", [(2, "IPv4"), (10, "IPv6")])
def test_null_header_family(family, expected):
    result = parse_link(family.to_bytes(4, "little") + UDP[14:], DLT_NULL)
    assert result.info["protocol"] == "NULL"
    assert result.network_protocol == expected


def test_raw_link_sniffs_ip_version():
    assert parse_link(UDP[14:], DLT_RAW).network_protocol == "IPv4"
    assert parse_link(ICMP[14:], DLT_RAW).network_protocol == "IPv4"
    assert parse_link(IPV6[14:], DLT_RAW).network_protocol == "IPv6"


def test_raw_link_rejects_garbage():
    from pcparser.errors import MalformedHeaderError

    with pytest.raises(MalformedHeaderError):
        parse_link(b"\x00\x01\x02\x03", DLT_RAW)
