from __future__ import annotations

import pytest
from flow_events import CLIENT, SERVER, T0, tcp_event, udp_event

from ids.flow.key import flow_id, make_key
from ids.model import Endpoint, Ipv4Info, Normalized, PacketEvent, TcpInfo


def key_of(event: PacketEvent):
    found = make_key(event)
    assert found is not None
    return found[0]


def test_both_directions_share_one_key():
    forward = make_key(tcp_event(1, T0, CLIENT, SERVER))
    backward = make_key(tcp_event(2, T0, SERVER, CLIENT))
    assert forward is not None and backward is not None
    assert forward[0] == backward[0]
    assert hash(forward[0]) == hash(backward[0])


def test_endpoints_are_returned_in_packet_direction():
    _, src, dst = make_key(tcp_event(1, T0, SERVER, CLIENT))
    assert src == Endpoint("10.0.0.2", 80)
    assert dst == Endpoint("10.0.0.1", 40000)


def test_different_source_ports_give_different_keys():
    first = key_of(tcp_event(1, T0, ("10.0.0.1", 40000), SERVER))
    second = key_of(tcp_event(2, T0, ("10.0.0.1", 40001), SERVER))
    assert first != second


def test_tcp_and_udp_on_the_same_tuple_are_different_keys():
    assert key_of(tcp_event(1, T0, CLIENT, SERVER)) != key_of(udp_event(2, T0, CLIENT, SERVER))


def test_normalized_addresses_win_over_raw_ones():
    event = tcp_event(1, T0, ("010.000.000.001", 40000), SERVER)
    assert make_key(event) is None  # raw form is not canonical
    event.normalized = Normalized(src_ip="10.0.0.1", src_port=40000)
    key, src, _ = make_key(event)
    assert src == Endpoint("10.0.0.1", 40000)
    assert key == key_of(tcp_event(2, T0, CLIENT, SERVER))


@pytest.mark.parametrize(
    "event",
    [
        PacketEvent(packet_id=1, timestamp=T0, network=Ipv4Info(src_ip="10.0.0.1")),
        PacketEvent(
            packet_id=1,
            timestamp=T0,
            transport=TcpInfo(src_port=1, dst_port=2),
        ),
        tcp_event(1, T0, ("999.0.0.1", 1), SERVER),
        tcp_event(1, T0, ("10.0.0.1", 70000), SERVER),
        PacketEvent(
            packet_id=1,
            timestamp=T0,
            network=Ipv4Info(src_ip="10.0.0.1", dst_ip="10.0.0.2"),
            transport=TcpInfo(src_port=None, dst_port=80),
        ),
        PacketEvent(
            packet_id=1,
            timestamp=T0,
            network=Ipv4Info(src_ip="10.0.0.1", dst_ip="10.0.0.2"),
            transport=TcpInfo(src_port=True, dst_port=80),
        ),
    ],
    ids=["no-transport", "no-network", "bad-ip", "port-out-of-range", "port-missing", "bool"],
)
def test_events_without_a_usable_five_tuple_have_no_key(event):
    assert make_key(event) is None


def test_port_zero_is_still_a_usable_key():
    assert make_key(udp_event(1, T0, ("10.0.0.1", 0), SERVER)) is not None


def test_flow_id_has_the_documented_format():
    key = key_of(tcp_event(1, T0, CLIENT, SERVER))
    # sha1("TCP|10.0.0.1:40000|10.0.0.2:80|1759000000000000")[:16]
    assert flow_id(key, T0) == "39d401a88e1bbbfa"


def test_flow_id_orders_endpoints_numerically_not_as_text():
    key = key_of(udp_event(1, T0, ("10.0.0.10", 53), ("10.0.0.9", 5353)))
    # sha1("UDP|10.0.0.9:5353|10.0.0.10:53|1759000000500000")[:16]
    assert flow_id(key, T0 + 0.5) == "eb09350a5d961f6c"


def test_flow_id_is_the_same_from_either_direction_and_on_every_call():
    forward = key_of(tcp_event(1, T0, CLIENT, SERVER))
    backward = key_of(tcp_event(2, T0, SERVER, CLIENT))
    assert flow_id(forward, T0) == flow_id(backward, T0) == flow_id(forward, T0)


def test_a_new_start_time_gives_a_new_flow_id():
    key = key_of(tcp_event(1, T0, CLIENT, SERVER))
    assert flow_id(key, T0) != flow_id(key, T0 + 0.000001)
