import pytest
from golden import ICMP, IPV6, SERVER_MAC, TCP_SYN_OPTIONS, UDP, VLAN

from ids.capture.base import (
    DLT_EN10MB,
    DLT_LINUX_SLL,
    DLT_LINUX_SLL2,
    DLT_LOOP,
    DLT_NULL,
    DLT_RAW,
)
from ids.issues import ParseError
from ids.model import LlcHeader, SnapHeader, VlanTag
from ids.parsers.link import MAX_VLAN_TAGS, LinkResult, parse_link

MACS = bytes.fromhex("020000000002020000000001")
IPV4_PACKET = UDP[14:]


def stacked(tags: list[tuple[int, int]], ethertype: int, payload: bytes) -> bytes:
    header = b"".join(tpid.to_bytes(2, "big") + tci.to_bytes(2, "big") for tpid, tci in tags)
    return MACS + header + ethertype.to_bytes(2, "big") + payload


def test_ethernet_fields_and_payload():
    result = parse_link(TCP_SYN_OPTIONS, DLT_EN10MB)
    assert isinstance(result, LinkResult)
    assert result.info.protocol == "Ethernet"
    assert result.info.src_mac == "02:00:00:00:00:01"
    assert result.info.dst_mac == SERVER_MAC
    assert result.info.ethertype == 0x0800
    assert result.info.ethertype_name == "IPv4"
    assert result.info.vlan == []
    assert result.network_protocol == "IPv4"
    assert result.payload[0] == 0x45


def test_vlan_tag_is_reported():
    result = parse_link(VLAN, DLT_EN10MB)
    assert result.info.vlan == [VlanTag(tpid="0x8100", pcp=5, dei=False, vid=42)]
    assert result.network_protocol == "IPv4"
    assert result.payload[0] == 0x45


def test_three_stacked_vlan_tags_are_accepted():
    frame = stacked([(0x88A8, 1), (0x8100, 2), (0x9100, 0x1003)], 0x0800, IPV4_PACKET)
    result = parse_link(frame, DLT_EN10MB)
    assert [tag.tpid for tag in result.info.vlan] == ["0x88a8", "0x8100", "0x9100"]
    assert [tag.vid for tag in result.info.vlan] == [1, 2, 3]
    assert result.info.vlan[2].dei is True
    assert result.network_protocol == "IPv4"
    assert result.payload == IPV4_PACKET


def test_more_than_max_vlan_tags_is_malformed():
    tags = [(0x8100, vid) for vid in range(MAX_VLAN_TAGS + 1)]
    with pytest.raises(ParseError) as caught:
        parse_link(stacked(tags, 0x0800, IPV4_PACKET), DLT_EN10MB)
    assert caught.value.code == "malformed_header"
    assert caught.value.context == {"limit": 3}


def test_truncated_vlan_tag_reports_declared_and_captured():
    with pytest.raises(ParseError) as caught:
        parse_link(MACS + b"\x81\x00\x00", DLT_EN10MB)
    assert caught.value.code == "truncated_packet"
    assert caught.value.context == {"declared": 18, "captured": 15}


def test_icmp_frame_resolves_to_ipv4():
    result = parse_link(ICMP, DLT_EN10MB)
    assert result.network_protocol == "IPv4"
    assert len(result.payload) == 28
    assert result.payload[9] == 1


def test_unknown_ethertype_is_not_an_error():
    result = parse_link(MACS + bytes.fromhex("1234") + b"noise", DLT_EN10MB)
    assert result.network_protocol is None
    assert result.info.ethertype == 0x1234
    assert result.info.ethertype_name == "0x1234"


def test_arp_ethertype_is_reported():
    result = parse_link(MACS + bytes.fromhex("0806") + b"\x00" * 28, DLT_EN10MB)
    assert result.network_protocol == "ARP"


def test_8023_snap_frame_carries_ipv4():
    llc_snap = bytes.fromhex("aaaa03") + bytes.fromhex("000000") + bytes.fromhex("0800")
    frame = MACS + (len(llc_snap) + len(IPV4_PACKET)).to_bytes(2, "big") + llc_snap + IPV4_PACKET
    result = parse_link(frame, DLT_EN10MB)
    assert result.info.length_field == len(llc_snap) + len(IPV4_PACKET)
    assert result.info.llc == LlcHeader(dsap="0xaa", ssap="0xaa", control=3)
    assert result.info.snap == SnapHeader(oui="000000", protocol=0x0800)
    assert result.info.ethertype == 0x0800
    assert result.network_protocol == "IPv4"
    assert result.payload == IPV4_PACKET


def test_8023_llc_without_snap_has_no_network_protocol():
    frame = MACS + (38).to_bytes(2, "big") + bytes.fromhex("424203") + b"\x00" * 35
    result = parse_link(frame, DLT_EN10MB)
    assert result.info.llc == LlcHeader(dsap="0x42", ssap="0x42", control=3)
    assert result.info.snap is None
    assert result.info.ethertype == 0
    assert result.info.ethertype_name == "0x0000"
    assert result.network_protocol is None


def test_snap_with_vendor_oui_is_not_resolved():
    llc_snap = bytes.fromhex("aaaa03") + bytes.fromhex("00000c") + bytes.fromhex("2000")
    frame = MACS + (40).to_bytes(2, "big") + llc_snap + b"\x00" * 32
    result = parse_link(frame, DLT_EN10MB)
    assert result.info.snap == SnapHeader(oui="00000c", protocol=0x2000)
    assert result.info.ethertype == 0
    assert result.network_protocol is None


def test_truncated_snap_header_is_reported():
    with pytest.raises(ParseError) as caught:
        parse_link(MACS + (8).to_bytes(2, "big") + bytes.fromhex("aaaa0300"), DLT_EN10MB)
    assert caught.value.code == "truncated_packet"
    assert caught.value.context == {"declared": 22, "captured": 18}


def test_truncated_ethernet_reports_declared_and_captured():
    with pytest.raises(ParseError) as caught:
        parse_link(b"\x02\x00\x00\x00\x00\x02", DLT_EN10MB)
    assert caught.value.code == "truncated_packet"
    assert caught.value.context == {"declared": 14, "captured": 6}


def test_unsupported_linktype_is_rejected():
    with pytest.raises(ParseError) as caught:
        parse_link(b"\x00" * 64, 999)
    assert caught.value.code == "unsupported_protocol"
    assert caught.value.context == {"linktype": 999}


def test_linux_cooked_v1():
    header = bytes.fromhex("000100010006") + bytes.fromhex("020000000001") + bytes.fromhex("0000")
    header += bytes.fromhex("0800")
    result = parse_link(header + IPV4_PACKET, DLT_LINUX_SLL)
    assert result.info.protocol == "LINUX_SLL"
    assert result.info.packet_type == 1
    assert result.info.address_type == 1
    assert result.info.address == "02:00:00:00:00:01"
    assert result.network_protocol == "IPv4"
    assert result.payload == IPV4_PACKET


def test_linux_cooked_v2():
    header = bytes.fromhex("0800") + bytes.fromhex("0000") + bytes.fromhex("00000005")
    header += bytes.fromhex("0001") + bytes.fromhex("00") + bytes.fromhex("06")
    header += bytes.fromhex("020000000001") + bytes.fromhex("0000")
    result = parse_link(header + IPV4_PACKET, DLT_LINUX_SLL2)
    assert result.info.protocol == "LINUX_SLL2"
    assert result.info.interface_index == 5
    assert result.info.address == "02:00:00:00:00:01"
    assert result.network_protocol == "IPv4"
    assert result.payload == IPV4_PACKET


@pytest.mark.parametrize("family,expected", [(2, "IPv4"), (10, "IPv6")])
def test_null_header_family(family, expected):
    result = parse_link(family.to_bytes(4, "little") + IPV4_PACKET, DLT_NULL)
    assert result.info.protocol == "NULL"
    assert result.info.address_family == family
    assert result.network_protocol == expected


def test_loop_header_is_big_endian():
    result = parse_link((2).to_bytes(4, "big") + IPV4_PACKET, DLT_LOOP)
    assert result.info.protocol == "LOOP"
    assert result.network_protocol == "IPv4"


def test_null_header_unknown_family_is_named_not_resolved():
    result = parse_link((99).to_bytes(4, "little") + IPV4_PACKET, DLT_NULL)
    assert result.info.ethertype is None
    assert result.info.ethertype_name == "AF_99"
    assert result.network_protocol is None


def test_raw_link_sniffs_ip_version():
    assert parse_link(IPV4_PACKET, DLT_RAW).network_protocol == "IPv4"
    assert parse_link(ICMP[14:], DLT_RAW).network_protocol == "IPv4"
    assert parse_link(IPV6[14:], DLT_RAW).network_protocol == "IPv6"


def test_raw_link_rejects_garbage():
    with pytest.raises(ParseError) as caught:
        parse_link(b"\x00\x01\x02\x03", DLT_RAW)
    assert caught.value.code == "malformed_header"
    assert caught.value.context == {"version": 0}


def test_empty_raw_link_is_truncated():
    with pytest.raises(ParseError) as caught:
        parse_link(b"", DLT_RAW)
    assert caught.value.code == "truncated_packet"
