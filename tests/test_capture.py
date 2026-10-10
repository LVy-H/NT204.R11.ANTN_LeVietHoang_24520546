from __future__ import annotations

import struct

import pytest

from ids.capture.base import linktype_name
from ids.capture.pcap import PcapSource
from ids.issues import ParseError
from ids.model import RawPacket

TS = 1759000000
FRAME_A = bytes.fromhex("0200000000020200000000010800") + bytes.fromhex(
    "4500001c00010000400600000a0000010a000002"
)
FRAME_B = bytes.fromhex("0200000000020200000000010800") + bytes.fromhex(
    "4500001c00010000400600000a0000010a000003"
)


def classic(records, *, endian="<", divisor=1_000_000, linktype=1, snaplen=262144):
    magic = {
        ("<", 1_000_000): b"\xd4\xc3\xb2\xa1",
        (">", 1_000_000): b"\xa1\xb2\xc3\xd4",
        ("<", 1_000_000_000): b"\x4d\x3c\xb2\xa1",
        (">", 1_000_000_000): b"\xa1\xb2\x3c\x4d",
    }[(endian, divisor)]
    out = magic + struct.pack(endian + "HHiIII", 2, 4, 0, 0, snaplen, linktype)
    for seconds, fraction, data, captured in records:
        out += struct.pack(endian + "IIII", seconds, fraction, captured, len(data)) + data
    return out


def block(block_type, body, endian="<"):
    total = 12 + len(body)
    return struct.pack(endian + "II", block_type, total) + body + struct.pack(endian + "I", total)


def section_header(endian="<"):
    bom = b"\x1a\x2b\x3c\x4d" if endian == ">" else b"\x4d\x3c\x2b\x1a"
    return block(0x0A0D0D0A, bom + struct.pack(endian + "HHq", 1, 0, -1), endian)


def interface_description(linktype=1, snaplen=262144, tsresol=None, endian="<"):
    body = struct.pack(endian + "HHI", linktype, 0, snaplen)
    if tsresol is not None:
        body += struct.pack(endian + "HH", 9, 1) + bytes([tsresol]) + b"\x00" * 3
    return block(1, body, endian)


def enhanced_packet(data, timestamp, iface=0, endian="<"):
    body = struct.pack(
        endian + "IIIII", iface, timestamp >> 32, timestamp & 0xFFFFFFFF, len(data), len(data)
    )
    body += data + b"\x00" * (-len(data) % 4)
    return block(6, body, endian)


def write(tmp_path, raw, name="capture.pcap"):
    path = tmp_path / name
    path.write_bytes(raw)
    return path


def test_classic_little_endian(tmp_path):
    raw = classic([(TS, 250000, FRAME_A, len(FRAME_A)), (TS + 1, 500000, FRAME_B, len(FRAME_B))])
    source = PcapSource(write(tmp_path, raw))
    packets = list(source.items())
    assert source.format == "pcap"
    assert source.linktype == 1
    assert source.snaplen == 262144
    assert source.warnings == []
    assert [packet.packet_id for packet in packets] == [1, 2]
    assert packets[0].timestamp == pytest.approx(TS + 0.25)
    assert packets[1].timestamp == pytest.approx(TS + 1.5)
    assert packets[0].data == FRAME_A
    assert packets[0].original_length == len(FRAME_A)
    assert packets[0].truncated is False
    assert packets[0].source == "pcap"
    assert packets[0].origin == str(tmp_path / "capture.pcap")


def test_classic_big_endian(tmp_path):
    raw = classic([(TS, 250000, FRAME_A, len(FRAME_A))], endian=">")
    packets = list(PcapSource(write(tmp_path, raw)).items())
    assert packets[0].timestamp == pytest.approx(TS + 0.25)
    assert packets[0].data == FRAME_A


def test_classic_nanosecond_magic(tmp_path):
    raw = classic([(TS, 123456789, FRAME_A, len(FRAME_A))], divisor=1_000_000_000)
    packets = list(PcapSource(write(tmp_path, raw)).items())
    assert packets[0].timestamp == pytest.approx(TS + 0.123456789)


def test_truncated_record_stops_reading_and_warns(tmp_path):
    raw = classic([(TS, 0, FRAME_A, len(FRAME_A)), (TS + 1, 0, FRAME_B, 400)])
    source = PcapSource(write(tmp_path, raw))
    packets = list(source.items())
    assert len(packets) == 2
    assert packets[1].declared_capture_length == 400
    assert packets[1].truncated is True
    assert len(packets[1].data) == len(FRAME_B)
    assert any("declares 400 captured bytes" in warning for warning in source.warnings)


def test_classic_count_limit(tmp_path):
    raw = classic([(TS, 0, FRAME_A, len(FRAME_A))] * 5)
    assert len(list(PcapSource(write(tmp_path, raw), count=2).items())) == 2


def test_unknown_magic_is_a_malformed_header(tmp_path):
    with pytest.raises(ParseError) as caught:
        list(PcapSource(write(tmp_path, b"NOPE" + b"\x00" * 40)).items())
    assert caught.value.code == "malformed_header"
    assert caught.value.message == "unrecognised capture file format"
    assert caught.value.context == {"magic": "4e4f5045"}


def test_empty_file_is_a_malformed_header(tmp_path):
    with pytest.raises(ParseError) as caught:
        list(PcapSource(write(tmp_path, b"")).items())
    assert caught.value.code == "malformed_header"
    assert caught.value.message == "capture file is empty"


def test_truncated_global_header_is_a_malformed_header(tmp_path):
    with pytest.raises(ParseError) as caught:
        list(PcapSource(write(tmp_path, b"\xd4\xc3\xb2\xa1" + b"\x00" * 10)).items())
    assert caught.value.code == "malformed_header"
    assert caught.value.message == "truncated pcap global header"


def test_missing_file_raises_oserror(tmp_path):
    with pytest.raises(OSError):
        list(PcapSource(tmp_path / "missing.pcap").items())


def test_pcapng_little_endian(tmp_path):
    raw = (
        section_header()
        + interface_description()
        + enhanced_packet(FRAME_A, TS * 1_000_000 + 250000)
    )
    source = PcapSource(write(tmp_path, raw, "capture.pcapng"))
    packets = list(source.items())
    assert source.format == "pcapng"
    assert source.linktype == 1
    assert packets[0].timestamp == pytest.approx(TS + 0.25)
    assert packets[0].data == FRAME_A


def test_pcapng_big_endian(tmp_path):
    raw = (
        section_header(">")
        + interface_description(endian=">")
        + enhanced_packet(FRAME_A, TS * 1_000_000 + 250000, endian=">")
    )
    packets = list(PcapSource(write(tmp_path, raw, "capture.pcapng")).items())
    assert packets[0].timestamp == pytest.approx(TS + 0.25)
    assert packets[0].data == FRAME_A


def test_pcapng_custom_timestamp_resolution(tmp_path):
    raw = (
        section_header()
        + interface_description(tsresol=9)
        + enhanced_packet(FRAME_A, TS * 1_000_000_000 + 500000000)
    )
    packets = list(PcapSource(write(tmp_path, raw, "capture.pcapng")).items())
    assert packets[0].timestamp == pytest.approx(TS + 0.5)


def test_pcapng_binary_timestamp_resolution(tmp_path):
    raw = (
        section_header()
        + interface_description(tsresol=0x80 | 10)
        + enhanced_packet(FRAME_A, TS * 1024)
    )
    packets = list(PcapSource(write(tmp_path, raw, "capture.pcapng")).items())
    assert packets[0].timestamp == pytest.approx(TS)


def test_pcapng_simple_packet_block_has_no_timestamp(tmp_path):
    body = struct.pack("<I", len(FRAME_A)) + FRAME_A + b"\x00" * (-len(FRAME_A) % 4)
    raw = section_header() + interface_description() + block(3, body)
    packets = list(PcapSource(write(tmp_path, raw, "capture.pcapng")).items())
    assert packets[0].timestamp == 0.0
    assert packets[0].data == FRAME_A


def test_pcapng_packet_without_interface_is_skipped(tmp_path):
    raw = section_header() + enhanced_packet(FRAME_A, TS * 1_000_000)
    source = PcapSource(write(tmp_path, raw, "capture.pcapng"))
    assert list(source.items()) == []
    assert any("undefined interface" in warning for warning in source.warnings)


def test_pcapng_bad_block_length_warns(tmp_path):
    raw = section_header() + struct.pack("<II", 1, 3)
    source = PcapSource(write(tmp_path, raw, "capture.pcapng"))
    assert list(source.items()) == []
    assert any("invalid pcapng block length" in warning for warning in source.warnings)


def test_pcapng_short_interface_block_keeps_interface_numbering(tmp_path):
    raw = (
        section_header()
        + block(1, b"\x01\x00\x00\x00")
        + interface_description()
        + enhanced_packet(FRAME_A, TS * 1_000_000, iface=1)
        + enhanced_packet(FRAME_B, TS * 1_000_000, iface=0)
    )
    source = PcapSource(write(tmp_path, raw, "capture.pcapng"))
    packets = list(source.items())
    assert source.warnings == [
        "truncated pcapng interface description block",
        "pcapng packet references unusable interface 0",
    ]
    assert [packet.data for packet in packets] == [FRAME_A]


def test_describe_and_linktype_name():
    assert linktype_name(1) == "EN10MB"
    assert linktype_name(None) is None
    assert linktype_name(4242) == "UNKNOWN(4242)"
    described = PcapSource("missing.pcap", count=3).describe()
    assert described["source"] == "pcap"
    assert described["origin"].endswith("missing.pcap")
    assert described["count_limit"] == 3
    assert described["format"] is None


def test_rawpacket_helpers():
    packet = RawPacket(
        packet_id=7,
        timestamp=1.5,
        data=b"abc",
        linktype=1,
        source="pcap",
        origin="x.pcap",
        original_length=9,
        declared_capture_length=9,
    )
    assert packet.captured_length == 3
    assert packet.truncated is True
