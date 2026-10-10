from __future__ import annotations

from flow_events import CLIENT, SERVER, T0, app, tcp_event, udp_event

from ids.flow.key import flow_id, make_key
from ids.flow.records import FlowState, packet_bytes, packet_time, payload_bytes
from ids.model import (
    Direction,
    DirectionStats,
    Endpoint,
    EndReason,
    Ipv4Info,
    Normalized,
    PacketEvent,
    Payload,
    TcpState,
    UdpInfo,
)


def track(events):
    """Feed every event into one FlowState, the way the flow table does."""
    first = events[0]
    key, src, dst = make_key(first)
    flow = FlowState(key, src, dst, first, first.timestamp)
    refs = []
    for event in events:
        event_key, src, _ = make_key(event)
        assert event_key == key
        forward = src == flow.record.endpoint_a
        refs.append(flow.add(event, forward, event.timestamp, event.timestamp))
    return flow, refs


def tcp_session():
    """Handshake, 100 B up, 300 B down, graceful close: 6 packets A→B, 4 packets B→A."""
    up, down = b"u" * 100, b"d" * 300
    return [
        tcp_event(1, T0, CLIENT, SERVER, "S", seq=1000, ack=0),
        tcp_event(2, T0 + 0.25, SERVER, CLIENT, "SA", seq=5000, ack=1001),
        tcp_event(3, T0 + 0.5, CLIENT, SERVER, "A", seq=1001, ack=5001),
        tcp_event(4, T0 + 0.75, CLIENT, SERVER, "PA", seq=1001, ack=5001, payload=up),
        tcp_event(5, T0 + 1.0, SERVER, CLIENT, "A", seq=5001, ack=1101),
        tcp_event(6, T0 + 1.25, SERVER, CLIENT, "PA", seq=5001, ack=1101, payload=down),
        tcp_event(7, T0 + 1.5, CLIENT, SERVER, "A", seq=1101, ack=5301),
        tcp_event(8, T0 + 1.75, CLIENT, SERVER, "FA", seq=1101, ack=5301),
        tcp_event(9, T0 + 2.0, SERVER, CLIENT, "FA", seq=5301, ack=1102),
        tcp_event(10, T0 + 2.25, CLIENT, SERVER, "A", seq=1102, ack=5302),
    ]


def test_tcp_session_record_has_exact_counters():
    flow, refs = track(tcp_session())
    record = flow.finish(EndReason.CLOSED)
    assert record.protocol == "TCP"
    assert record.endpoint_a == Endpoint("10.0.0.1", 40000)
    assert record.endpoint_b == Endpoint("10.0.0.2", 80)
    assert (record.start_time, record.last_seen, record.duration) == (T0, T0 + 2.25, 2.25)
    assert (record.packet_count, record.byte_count, record.payload_byte_count) == (10, 800, 400)
    assert record.forward == DirectionStats(packet_count=6, byte_count=340, payload_byte_count=100)
    assert record.backward == DirectionStats(packet_count=4, byte_count=460, payload_byte_count=300)
    tcp = record.tcp
    assert (tcp.syn_count, tcp.ack_count, tcp.fin_count, tcp.rst_count) == (2, 9, 2, 0)
    assert tcp.state is TcpState.CLOSED
    assert tcp.handshake_complete is True and tcp.midstream is False
    assert (record.first_packet_id, record.last_packet_id) == (1, 10)
    assert record.end_reason is EndReason.CLOSED
    assert record.flow_id == flow_id(flow.key, T0)
    assert [ref.flow_packet_index for ref in refs] == list(range(1, 11))
    assert {ref.flow_id for ref in refs} == {record.flow_id}


def test_packet_refs_carry_direction_and_state_after_the_packet():
    _, refs = track(tcp_session()[:4])
    assert [ref.direction for ref in refs] == [
        Direction.FORWARD,
        Direction.BACKWARD,
        Direction.FORWARD,
        Direction.FORWARD,
    ]
    assert [ref.state for ref in refs] == [
        TcpState.HANDSHAKE,
        TcpState.HANDSHAKE,
        TcpState.ESTABLISHED,
        TcpState.ESTABLISHED,
    ]


def test_udp_dns_exchange_is_one_flow_with_one_packet_each_way():
    dns = app("DNS", "port+payload", 1.0)
    client, resolver = ("10.0.0.1", 53000), ("10.0.0.53", 53)
    flow, refs = track(
        [
            udp_event(1, T0, client, resolver, payload=b"q" * 30, application=dns),
            udp_event(2, T0 + 0.02, resolver, client, payload=b"r" * 46, application=dns),
        ]
    )
    record = flow.finish(EndReason.END_OF_INPUT)
    assert record.protocol == "UDP"
    assert record.tcp is None
    assert record.application_protocol == "DNS"
    assert (record.packet_count, record.byte_count) == (2, 58 + 74)
    assert (record.forward.packet_count, record.backward.packet_count) == (1, 1)
    assert record.duration == 0.02
    assert [(ref.direction, ref.state, ref.flow_packet_index) for ref in refs] == [
        (Direction.FORWARD, None, 1),
        (Direction.BACKWARD, None, 2),
    ]


def test_syn_ack_seen_first_makes_its_destination_endpoint_a():
    flow, refs = track(
        [
            tcp_event(1, T0, SERVER, CLIENT, "SA", seq=5000, ack=1001),
            tcp_event(2, T0 + 0.1, CLIENT, SERVER, "A", seq=1001, ack=5001),
        ]
    )
    assert flow.record.endpoint_a == Endpoint("10.0.0.1", 40000)
    assert [ref.direction for ref in refs] == [Direction.BACKWARD, Direction.FORWARD]
    assert refs[-1].state is TcpState.ESTABLISHED


def test_midstream_flow_makes_the_first_sender_endpoint_a():
    flow, refs = track([tcp_event(1, T0, SERVER, CLIENT, "PA", seq=7, ack=9, payload=b"x")])
    assert flow.record.endpoint_a == Endpoint("10.0.0.2", 80)
    assert flow.record.tcp.midstream is True
    assert refs[0].state is TcpState.NEW


def test_out_of_order_timestamps_never_give_a_negative_duration():
    flow, _ = track(
        [
            udp_event(1, T0 + 2, CLIENT, SERVER),
            udp_event(2, T0 + 1, SERVER, CLIENT),
        ]
    )
    record = flow.finish(EndReason.END_OF_INPUT)
    assert (record.start_time, record.last_seen, record.duration) == (T0 + 1, T0 + 2, 1.0)
    assert record.flow_id == flow_id(flow.key, T0 + 2)  # fixed by the first packet


def test_payload_evidence_outranks_port_only_detection():
    flow, _ = track(
        [
            udp_event(1, T0, CLIENT, SERVER, application=app("HTTP", "payload", 0.6)),
            udp_event(2, T0 + 1, CLIENT, SERVER, application=app("SMTP", "port", 0.9)),
        ]
    )
    assert flow.record.application_protocol == "HTTP"


def test_higher_confidence_with_payload_evidence_replaces_the_flow_protocol():
    flow, _ = track(
        [
            tcp_event(1, T0, CLIENT, SERVER, application=app("SMTP", "port", 0.3)),
            tcp_event(2, T0 + 1, CLIENT, SERVER, application=app("HTTP", "payload", 0.7)),
            tcp_event(3, T0 + 2, CLIENT, SERVER, application=app("DNS", "port+payload", 0.9)),
            tcp_event(4, T0 + 3, CLIENT, SERVER, application=app("HTTP", "payload", 0.9)),
        ]
    )
    assert flow.record.application_protocol == "DNS"  # ties keep the earliest


def test_flow_without_any_detection_is_unknown():
    flow, _ = track(
        [
            tcp_event(1, T0, CLIENT, SERVER, "S"),
            tcp_event(2, T0 + 1, SERVER, CLIENT, application=app("UNKNOWN", "none", 0.0)),
        ]
    )
    assert flow.record.application_protocol == "UNKNOWN"


def test_normalized_application_protocol_is_preferred():
    event = udp_event(1, T0, CLIENT, SERVER, application=app("http", "payload", 0.9))
    event.normalized = Normalized(application_protocol="HTTP")
    flow, _ = track([event])
    assert flow.record.application_protocol == "HTTP"


def test_byte_counts_fall_back_to_the_captured_payload_length():
    event = PacketEvent(
        network=Ipv4Info(total_length=None),
        transport=UdpInfo(payload_length=None),
        payload=Payload(length=12),
    )
    assert (packet_bytes(event), payload_bytes(event)) == (12, 12)
    assert (packet_bytes(PacketEvent()), payload_bytes(PacketEvent())) == (0, 0)


def test_negative_or_non_int_lengths_count_as_absent():
    negative = PacketEvent(
        network=Ipv4Info(total_length=-500),
        transport=UdpInfo(payload_length=-40),
        payload=Payload(length=12),
    )
    assert (packet_bytes(negative), payload_bytes(negative)) == (12, 12)
    odd = PacketEvent(
        network=Ipv4Info(total_length=True),
        transport=UdpInfo(payload_length=1.5),
        payload=Payload(length=-3),
    )
    assert (packet_bytes(odd), payload_bytes(odd)) == (0, 0)


def test_packet_time_prefers_the_normalized_timestamp():
    event = udp_event(1, 1759000000123.0, CLIENT, SERVER)  # milliseconds in a loaded event
    event.normalized = Normalized(timestamp=1759000000.123)
    assert packet_time(event) == 1759000000.123
    event.normalized = Normalized()
    assert packet_time(event) == 1759000000123.0


def test_packet_time_rejects_missing_or_non_finite_values():
    assert packet_time(PacketEvent(timestamp=None)) is None
    assert packet_time(PacketEvent(timestamp=float("nan"))) is None
    assert packet_time(PacketEvent(timestamp=float("inf"))) is None
