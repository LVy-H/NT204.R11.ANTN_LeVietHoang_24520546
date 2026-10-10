from __future__ import annotations

from golden import CLIENT_MAC, SERVER_MAC
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

from ids.decoder.stage import DecoderStage
from ids.flow import FlowConfig, FlowTrackerStage
from ids.model import (
    Direction,
    Endpoint,
    EndReason,
    FlowRecord,
    Ipv4Info,
    PacketEvent,
    RawPacket,
    TcpState,
    UdpInfo,
)
from ids.parsers import PacketParser
from ids.pipeline import Runner
from ids.preprocess.stage import PreprocessorStage
from ids.stats import Stats

T0 = 1759000000.0
CLIENT = ("10.0.0.1", 40000)
SERVER = ("10.0.0.2", 80)


class ListSink:
    def __init__(self) -> None:
        self.records = []

    def write(self, record) -> None:
        self.records.append(record)


def tcp(src, dst, flags, seq, ack, payload=b""):
    packet = Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IP(src=src[0], dst=dst[0])
    packet = packet / TCP(sport=src[1], dport=dst[1], flags=flags, seq=seq, ack=ack)
    return bytes(packet / payload) if payload else bytes(packet)


def udp(src, dst, payload):
    packet = Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IP(src=src[0], dst=dst[0])
    return bytes(packet / UDP(sport=src[1], dport=dst[1]) / payload)


def raw_packets(frames):
    """frames: (timestamp, ethernet bytes); packet ids are 1-based positions."""
    for packet_id, (timestamp, data) in enumerate(frames, start=1):
        yield RawPacket(
            packet_id=packet_id,
            timestamp=timestamp,
            data=data,
            linktype=1,
            source="pcap",
            origin="test.pcap",
            original_length=len(data),
            declared_capture_length=len(data),
        )


def run(items, config: FlowConfig | None = None):
    sink, stats = ListSink(), Stats()
    stages = [DecoderStage(), PreprocessorStage(), FlowTrackerStage(config, stats)]
    Runner(PacketParser(), stages, sink, stats).run(items)
    return sink.records, stats


def handshake(client=CLIENT, start=T0):
    return [
        (start, tcp(client, SERVER, "S", 1000, 0)),
        (start + 0.1, tcp(SERVER, client, "SA", 5000, 1001)),
        (start + 0.2, tcp(client, SERVER, "A", 1001, 5001)),
    ]


def packets_of(records):
    return [r for r in records if isinstance(r, PacketEvent)]


def flows_of(records):
    return [r for r in records if isinstance(r, FlowRecord)]


def test_t07_handshake_gives_one_established_flow():
    records, stats = run(raw_packets(handshake()))
    packets = packets_of(records)
    assert [type(r) for r in records] == [PacketEvent, PacketEvent, PacketEvent, FlowRecord]
    assert len({p.flow.flow_id for p in packets}) == 1
    assert packets[2].flow.state is TcpState.ESTABLISHED
    (flow,) = flows_of(records)
    assert flow.tcp.state is TcpState.ESTABLISHED
    assert flow.tcp.handshake_complete is True
    assert flow.endpoint_a == Endpoint("10.0.0.1", 40000)
    assert flow.end_reason is EndReason.END_OF_INPUT
    assert stats.extra["active_flows"] == 1


def test_t08_directions_follow_the_sender():
    request = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    frames = [
        *handshake(),
        (T0 + 0.3, tcp(CLIENT, SERVER, "PA", 1001, 5001, request)),
        (T0 + 0.4, tcp(SERVER, CLIENT, "PA", 5001, 1001 + len(request), response)),
        (T0 + 0.5, tcp(CLIENT, SERVER, "A", 1001 + len(request), 5001 + len(response))),
    ]
    records, _ = run(raw_packets(frames))
    packets = packets_of(records)
    assert len({p.flow.flow_id for p in packets}) == 1
    assert [p.flow.direction for p in packets] == [
        Direction.FORWARD,
        Direction.BACKWARD,
        Direction.FORWARD,
        Direction.FORWARD,
        Direction.BACKWARD,
        Direction.FORWARD,
    ]
    (flow,) = flows_of(records)
    assert flow.application_protocol == "HTTP"
    assert (flow.forward.packet_count, flow.backward.packet_count) == (4, 2)
    assert (flow.forward.payload_byte_count, flow.backward.payload_byte_count) == (
        len(request),
        len(response),
    )


def test_t09_fin_close_and_rst_abort():
    reset_client = ("10.0.0.1", 40001)
    frames = [
        *handshake(),
        (T0 + 0.3, tcp(CLIENT, SERVER, "FA", 1001, 5001)),
        (T0 + 0.4, tcp(SERVER, CLIENT, "FA", 5001, 1002)),
        (T0 + 0.5, tcp(CLIENT, SERVER, "A", 1002, 5002)),
        *handshake(reset_client, T0 + 1),
        (T0 + 1.3, tcp(reset_client, SERVER, "R", 1001, 0)),
    ]
    records, _ = run(raw_packets(frames))
    packets = packets_of(records)
    assert packets[5].flow.state is TcpState.CLOSED
    assert packets[9].flow.state is TcpState.RESET
    by_port = {flow.endpoint_a.port: flow for flow in flows_of(records)}
    assert (by_port[40000].tcp.state, by_port[40000].end_reason) == (
        TcpState.CLOSED,
        EndReason.CLOSED,
    )
    assert (by_port[40001].tcp.state, by_port[40001].end_reason) == (
        TcpState.RESET,
        EndReason.RESET,
    )


def test_expired_flow_record_is_written_before_the_packet_that_expired_it():
    frames = [
        (T0, udp(("10.0.0.1", 9000), ("10.0.0.2", 9001), b"ping")),
        (T0 + 61, udp(("10.0.0.3", 9000), ("10.0.0.2", 9001), b"ping")),
    ]
    records, _ = run(raw_packets(frames))
    assert [type(r) for r in records] == [PacketEvent, FlowRecord, PacketEvent, FlowRecord]
    assert records[1].flow_id == records[0].flow.flow_id
    assert records[1].end_reason is EndReason.IDLE_TIMEOUT
    assert records[3].flow_id == records[2].flow.flow_id


def test_invalid_event_is_written_without_a_flow():
    event = PacketEvent(
        packet_id=1,
        timestamp=T0,
        network=Ipv4Info(protocol="IPv4", src_ip="10.0.0.1", dst_ip="10.0.0.2"),
        transport=UdpInfo(src_port=70000, dst_port=53),
    )
    records, stats = run([event])
    assert records == [event]
    assert event.flow is None
    assert stats.extra["active_flows"] == 0
