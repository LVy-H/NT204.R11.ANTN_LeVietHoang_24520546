from __future__ import annotations

from flow_events import CLIENT, SERVER, T0, make_table, tcp_event, udp_event

from ids.flow.key import make_key
from ids.flow.table import FlowTable
from ids.model import EndReason, TcpState

DNS_CLIENT = ("10.0.0.1", 53000)
RESOLVER = ("10.0.0.53", 53)
OTHER = ("10.0.0.7", 9999)


def feed(table: FlowTable, event, out: list):
    key, src, dst = make_key(event)
    return table.apply(event, key, src, dst, event.timestamp, out.append)


def closed_connection(first_id: int, start: float, client=CLIENT):
    """Handshake and graceful close, 0.1 s apart; the flow is CLOSED after the last one."""
    t = start
    return [
        tcp_event(first_id, t, client, SERVER, "S", seq=1000, ack=0),
        tcp_event(first_id + 1, t + 0.1, SERVER, client, "SA", seq=5000, ack=1001),
        tcp_event(first_id + 2, t + 0.2, client, SERVER, "A", seq=1001, ack=5001),
        tcp_event(first_id + 3, t + 0.3, client, SERVER, "FA", seq=1001, ack=5001),
        tcp_event(first_id + 4, t + 0.4, SERVER, client, "FA", seq=5001, ack=1002),
        tcp_event(first_id + 5, t + 0.5, client, SERVER, "A", seq=1002, ack=5002),
    ]


def test_udp_flow_expires_before_a_later_packet_of_another_flow_is_applied():
    table = make_table()
    emitted = []

    def emit(record):
        emitted.append((record, table.active_count))

    first = udp_event(1, T0, DNS_CLIENT, RESOLVER)
    second = udp_event(2, T0 + 1, RESOLVER, DNS_CLIENT)
    for event in (first, second):
        key, src, dst = make_key(event)
        table.apply(event, key, src, dst, event.timestamp, emit)
    late = udp_event(3, T0 + 62, OTHER, RESOLVER)
    key, src, dst = make_key(late)
    ref = table.apply(late, key, src, dst, late.timestamp, emit)
    assert len(emitted) == 1
    record, active_when_emitted = emitted[0]
    assert active_when_emitted == 0  # the late packet's flow did not exist yet
    assert record.end_reason is EndReason.IDLE_TIMEOUT
    assert record.packet_count == 2
    assert ref.flow_packet_index == 1
    assert table.active_count == 1
    assert make_key(first)[0] not in table.udp


def test_gap_equal_to_the_udp_timeout_stays_in_the_same_flow():
    table, out = make_table(), []
    first = feed(table, udp_event(1, T0, DNS_CLIENT, RESOLVER), out)
    second = feed(table, udp_event(2, T0 + 60, DNS_CLIENT, RESOLVER), out)
    assert out == []
    assert second.flow_id == first.flow_id
    assert second.flow_packet_index == 2


def test_same_key_after_expiry_starts_a_new_flow():
    table, out = make_table(), []
    first = feed(table, udp_event(1, T0, DNS_CLIENT, RESOLVER), out)
    second = feed(table, udp_event(2, T0 + 61, DNS_CLIENT, RESOLVER), out)
    assert [record.flow_id for record in out] == [first.flow_id]
    assert second.flow_id != first.flow_id
    assert second.flow_packet_index == 1


def test_expired_flows_leave_in_order_of_their_deadline_across_lanes():
    table, out = make_table(), []
    udp = feed(table, udp_event(1, T0, DNS_CLIENT, RESOLVER), out)  # deadline T0 + 60
    tcp_open = feed(table, tcp_event(2, T0 + 1, OTHER, SERVER, "S"), out)  # T0 + 301
    for event in closed_connection(3, T0 + 9.5):  # closed at T0 + 10, deadline T0 + 15
        closed = feed(table, event, out)
    assert closed.state is TcpState.CLOSED
    table.advance(T0 + 70, out.append)
    assert [(r.flow_id, r.end_reason) for r in out] == [
        (closed.flow_id, EndReason.CLOSED),
        (udp.flow_id, EndReason.IDLE_TIMEOUT),
    ]
    table.advance(T0 + 400, out.append)
    assert (out[-1].flow_id, out[-1].end_reason) == (tcp_open.flow_id, EndReason.IDLE_TIMEOUT)
    assert table.active_count == 0


def test_eviction_exports_the_least_recently_active_flow_across_lanes():
    table, out = make_table(max_flows=2), []
    feed(table, tcp_event(1, T0, CLIENT, SERVER, "S"), out)
    udp = feed(table, udp_event(2, T0 + 1, DNS_CLIENT, RESOLVER), out)
    feed(table, tcp_event(3, T0 + 2, CLIENT, SERVER, "S"), out)  # TCP flow active again
    feed(table, udp_event(4, T0 + 3, OTHER, RESOLVER), out)
    assert [(r.flow_id, r.end_reason) for r in out] == [(udp.flow_id, EndReason.EVICTED)]
    assert table.active_count == 2


def test_closed_flow_lingers_for_trailing_packets_then_a_new_syn_starts_a_new_flow():
    table, out = make_table(), []
    for event in closed_connection(1, T0):
        old = feed(table, event, out)
    trailing = feed(table, tcp_event(7, T0 + 1, SERVER, CLIENT, "A", seq=5002, ack=1002), out)
    assert (trailing.flow_id, trailing.flow_packet_index) == (old.flow_id, 7)
    assert trailing.state is TcpState.CLOSED
    assert out == []
    new = feed(table, tcp_event(8, T0 + 2, CLIENT, SERVER, "S", seq=9000, ack=0), out)
    assert [(r.flow_id, r.end_reason, r.packet_count) for r in out] == [
        (old.flow_id, EndReason.CLOSED, 7)
    ]
    assert new.flow_id != old.flow_id
    assert (new.flow_packet_index, new.state) == (1, TcpState.HANDSHAKE)
    assert table.active_count == 1


def test_closed_flow_is_exported_after_the_linger_since_its_last_packet():
    table, out = make_table(), []
    for event in closed_connection(1, T0):
        feed(table, event, out)
    feed(table, tcp_event(7, T0 + 4, SERVER, CLIENT, "A", seq=5002, ack=1002), out)
    feed(table, udp_event(8, T0 + 6, DNS_CLIENT, RESOLVER), out)
    assert out == []  # 2 s since the trailing ACK
    feed(table, udp_event(9, T0 + 9.5, DNS_CLIENT, RESOLVER), out)
    assert [(r.protocol, r.end_reason) for r in out] == [("TCP", EndReason.CLOSED)]


def test_reset_flow_is_exported_with_reason_reset():
    table, out = make_table(), []
    feed(table, tcp_event(1, T0, CLIENT, SERVER, "S", seq=1000, ack=0), out)
    feed(table, tcp_event(2, T0 + 0.1, SERVER, CLIENT, "RA", seq=0, ack=1001), out)
    table.advance(T0 + 10, out.append)
    assert [(r.end_reason, r.tcp.state) for r in out] == [(EndReason.RESET, TcpState.RESET)]


def test_syn_on_an_open_flow_does_not_start_a_new_flow():
    table, out = make_table(), []
    for event in closed_connection(1, T0)[:3]:
        first = feed(table, event, out)
    again = feed(table, tcp_event(4, T0 + 1, CLIENT, SERVER, "S", seq=7000, ack=0), out)
    assert out == []
    assert again.flow_id == first.flow_id
    assert again.state is TcpState.ESTABLISHED


def test_clock_never_moves_backwards_with_out_of_order_timestamps():
    table, out = make_table(), []
    feed(table, udp_event(1, T0 + 100, DNS_CLIENT, RESOLVER), out)
    feed(table, udp_event(2, T0 + 90, OTHER, RESOLVER), out)
    assert table.clock == T0 + 100
    feed(table, udp_event(3, T0 + 155, CLIENT, RESOLVER), out)
    assert out == []  # the late packet counts as activity at T0 + 100, not T0 + 90
    table.advance(T0 + 120, out.append)
    assert table.clock == T0 + 155
    table.advance(T0 + 161, out.append)
    assert [r.first_packet_id for r in out] == [1, 2]
    assert out[1].last_seen == T0 + 90
    assert table.active_count == 1


def test_flush_exports_everything_oldest_activity_first():
    table, out = make_table(), []
    feed(table, udp_event(1, T0, DNS_CLIENT, RESOLVER), out)
    for event in closed_connection(2, T0 + 1):
        feed(table, event, out)
    feed(table, tcp_event(8, T0 + 2, OTHER, SERVER, "S"), out)
    table.flush(out.append)
    assert [(r.protocol, r.end_reason) for r in out] == [
        ("UDP", EndReason.END_OF_INPUT),
        ("TCP", EndReason.CLOSED),
        ("TCP", EndReason.END_OF_INPUT),
    ]
    assert table.active_count == 0


def test_three_interleaved_flows_are_kept_apart():
    table, out = make_table(), []
    second_client = ("10.0.0.3", 40002)
    events = [
        tcp_event(1, T0, CLIENT, SERVER, "S", seq=100, ack=0),
        tcp_event(2, T0 + 0.1, second_client, SERVER, "S", seq=200, ack=0),
        udp_event(3, T0 + 0.2, DNS_CLIENT, RESOLVER, payload=b"q" * 20),
        tcp_event(4, T0 + 0.3, SERVER, CLIENT, "SA", seq=900, ack=101),
        tcp_event(5, T0 + 0.4, SERVER, second_client, "SA", seq=800, ack=201),
        udp_event(6, T0 + 0.5, RESOLVER, DNS_CLIENT, payload=b"r" * 40),
        tcp_event(7, T0 + 0.6, CLIENT, SERVER, "A", seq=101, ack=901),
        tcp_event(8, T0 + 0.7, second_client, SERVER, "A", seq=201, ack=801),
        tcp_event(9, T0 + 0.8, CLIENT, SERVER, "PA", seq=101, ack=901, payload=b"x" * 10),
    ]
    refs = [feed(table, event, out) for event in events]
    table.flush(out.append)
    by_id = {record.flow_id: record for record in out}
    assert len(by_id) == 3
    assert [refs[i].flow_id for i in (0, 3, 6, 8)] == [refs[0].flow_id] * 4
    assert [refs[i].flow_id for i in (1, 4, 7)] == [refs[1].flow_id] * 3
    assert refs[2].flow_id == refs[5].flow_id
    assert by_id[refs[0].flow_id].packet_count == 4
    assert by_id[refs[0].flow_id].payload_byte_count == 10
    assert by_id[refs[1].flow_id].packet_count == 3
    assert by_id[refs[2].flow_id].packet_count == 2
    assert by_id[refs[2].flow_id].byte_count == 48 + 68
