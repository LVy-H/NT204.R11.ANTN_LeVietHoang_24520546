from __future__ import annotations

import pytest
from flow_events import flags

from ids.flow.tcp import SEQ_MOD, TcpConnection, is_new_syn, is_syn_ack, seq_ge
from ids.model import TcpState

A = True  # sent by endpoint A (forward)
B = False  # sent by endpoint B (backward)
HANDSHAKE = [(A, "S", 1000, 0, 0), (B, "SA", 5000, 1001, 0), (A, "A", 1001, 5001, 0)]


def run(packets):
    """packets: (forward, flags, seq, ack, payload_length); the first one opens the flow."""
    connection = TcpConnection(flags(packets[0][1]))
    states = [
        connection.update(forward, flags(spec), seq, ack, length)
        for forward, spec, seq, ack, length in packets
    ]
    return connection, states


def test_three_way_handshake_reaches_established():
    connection, states = run(HANDSHAKE)
    assert states == [TcpState.HANDSHAKE, TcpState.HANDSHAKE, TcpState.ESTABLISHED]
    assert connection.stats.handshake_complete is True
    assert connection.stats.midstream is False


def test_ack_from_a_before_the_syn_ack_does_not_establish():
    _, states = run([(A, "S", 1000, 0, 0), (A, "A", 1001, 0, 0)])
    assert states[-1] is TcpState.HANDSHAKE


def test_ack_from_b_after_its_syn_ack_does_not_establish():
    _, states = run([*HANDSHAKE[:2], (B, "A", 5001, 1001, 0)])
    assert states[-1] is TcpState.HANDSHAKE


def test_syn_ack_seen_first_completes_on_the_ack_from_its_destination():
    # The flow table makes the SYN-ACK's destination endpoint A, so the SYN-ACK is backward.
    connection, states = run([(B, "SA", 5000, 1001, 0), (A, "A", 1001, 5001, 0)])
    assert states == [TcpState.HANDSHAKE, TcpState.ESTABLISHED]
    assert connection.stats.handshake_complete is True
    assert connection.stats.midstream is False


def test_midstream_flow_starts_new_and_establishes_on_acks_both_ways():
    connection, states = run([(A, "PA", 1, 1, 10), (A, "A", 11, 1, 0), (B, "A", 1, 11, 0)])
    assert states == [TcpState.NEW, TcpState.NEW, TcpState.ESTABLISHED]
    assert connection.stats.midstream is True
    assert connection.stats.handshake_complete is False


def test_new_flow_needs_the_ack_flag_from_both_sides():
    _, states = run([(A, "A", 1, 1, 0), (B, "P", 1, 0, 5)])
    assert states[-1] is TcpState.NEW


def test_first_packet_without_flags_is_midstream_new():
    connection = TcpConnection(None)
    assert connection.update(A, None, None, None, 0) is TcpState.NEW
    assert connection.stats.midstream is True
    assert (connection.stats.syn_count, connection.stats.ack_count) == (0, 0)


def test_graceful_close_with_separate_acks():
    _, states = run(
        [
            *HANDSHAKE,
            (A, "FA", 1001, 5001, 0),
            (B, "A", 5001, 1002, 0),
            (B, "FA", 5001, 1002, 0),
            (A, "A", 1002, 5002, 0),
        ]
    )
    assert states[3:] == [TcpState.CLOSING, TcpState.CLOSING, TcpState.CLOSING, TcpState.CLOSED]


def test_fin_ack_from_the_peer_acknowledges_and_closes_its_side():
    _, states = run([*HANDSHAKE, (A, "FA", 1001, 5001, 0), (B, "FA", 5001, 1002, 0)])
    assert states[-1] is TcpState.CLOSING
    _, states = run(
        [*HANDSHAKE, (A, "FA", 1001, 5001, 0), (B, "FA", 5001, 1002, 0), (A, "A", 1002, 5002, 0)]
    )
    assert states[-1] is TcpState.CLOSED


def test_simultaneous_fins_close_after_both_acks():
    _, states = run(
        [
            *HANDSHAKE,
            (A, "FA", 1001, 5001, 0),
            (B, "FA", 5001, 1001, 0),
            (A, "A", 1002, 5002, 0),
            (B, "A", 5002, 1002, 0),
        ]
    )
    assert states[3:] == [TcpState.CLOSING, TcpState.CLOSING, TcpState.CLOSING, TcpState.CLOSED]


def test_ack_equal_to_the_fin_sequence_does_not_acknowledge_it():
    _, states = run(
        [*HANDSHAKE, (A, "FA", 1001, 5001, 0), (B, "FA", 5001, 1001, 0), (A, "A", 1002, 5002, 0)]
    )
    assert states[-1] is TcpState.CLOSING


def test_fin_carrying_payload_is_acknowledged_after_the_payload():
    _, states = run(
        [
            *HANDSHAKE,
            (A, "FPA", 1001, 5001, 100),
            (B, "FA", 5001, 1101, 0),  # acknowledges the data, not the FIN
            (A, "A", 1102, 5002, 0),
        ]
    )
    assert states[-1] is TcpState.CLOSING
    _, states = run(
        [*HANDSHAKE, (A, "FPA", 1001, 5001, 100), (B, "FA", 5001, 1102, 0), (A, "A", 1102, 5002, 0)]
    )
    assert states[-1] is TcpState.CLOSED


@pytest.mark.parametrize(
    ("fin_seq", "length", "ack", "closed"),
    [
        (SEQ_MOD - 1, 0, 0, True),
        (SEQ_MOD - 1, 0, SEQ_MOD - 1, False),
        (SEQ_MOD - 3, 5, 3, True),
        (SEQ_MOD - 3, 5, 2, False),
    ],
)
def test_fin_acknowledgement_wraps_around_the_sequence_space(fin_seq, length, ack, closed):
    _, states = run(
        [
            (A, "PA", 1, 1, 0),
            (B, "A", 1, 1, 0),
            (B, "FA", 7000, 1, 0),
            (A, "A", 1, 7001, 0),
            (A, "FPA", fin_seq, 7001, length),
            (B, "A", 7001, ack, 0),
        ]
    )
    assert (states[-1] is TcpState.CLOSED) is closed


def test_seq_ge_handles_wrap_around():
    assert seq_ge(5, 5)
    assert seq_ge(0, SEQ_MOD - 1)
    assert not seq_ge(SEQ_MOD - 1, 0)
    assert seq_ge(100, 99)
    assert not seq_ge(99, 100)


def test_close_without_sequence_numbers_uses_any_peer_ack():
    _, states = run(
        [
            (A, "A", None, None, 0),
            (B, "A", None, None, 0),
            (A, "FA", None, None, 0),
            (B, "FA", None, None, 0),
            (A, "A", None, None, 0),
        ]
    )
    assert states == [
        TcpState.NEW,
        TcpState.ESTABLISHED,
        TcpState.CLOSING,
        TcpState.CLOSING,
        TcpState.CLOSED,
    ]


@pytest.mark.parametrize(
    "before",
    [
        [(A, "PA", 1, 1, 5)],
        [(A, "S", 1000, 0, 0)],
        HANDSHAKE,
        [*HANDSHAKE, (A, "FA", 1001, 5001, 0)],
        [*HANDSHAKE, (A, "FA", 1001, 5001, 0), (B, "FA", 5001, 1002, 0), (A, "A", 1002, 5002, 0)],
    ],
    ids=["new", "handshake", "established", "closing", "closed"],
)
def test_rst_from_any_state_resets(before):
    connection, states = run([*before, (B, "R", 5002, 0, 0)])
    assert states[-1] is TcpState.RESET
    assert connection.stats.rst_count == 1


def test_rst_ack_during_the_handshake_resets():
    _, states = run([(A, "S", 1000, 0, 0), (B, "RA", 0, 1001, 0)])
    assert states == [TcpState.HANDSHAKE, TcpState.RESET]


def test_syn_on_an_established_flow_does_not_move_it_back():
    connection, states = run([*HANDSHAKE, (A, "S", 9000, 0, 0)])
    assert states[-1] is TcpState.ESTABLISHED
    assert connection.stats.syn_count == 3


def test_packets_after_close_or_reset_keep_the_final_state():
    closed = [*HANDSHAKE, (A, "FA", 1001, 5001, 0), (B, "FA", 5001, 1002, 0)]
    closed.append((A, "A", 1002, 5002, 0))
    connection, states = run([*closed, (A, "PA", 1002, 5002, 10), (B, "S", 1, 0, 0)])
    assert states[-2:] == [TcpState.CLOSED, TcpState.CLOSED]
    connection, states = run([*HANDSHAKE, (A, "R", 1001, 0, 0), (B, "FA", 5001, 1001, 0)])
    assert states[-1] is TcpState.RESET
    assert connection.stats.fin_count == 1


def test_flag_counters_count_packets_with_each_flag():
    connection, _ = run(
        [
            *HANDSHAKE,
            (A, "PA", 1001, 5001, 20),
            (A, "FA", 1021, 5001, 0),
            (B, "FA", 5001, 1022, 0),
            (A, "A", 1022, 5002, 0),
        ]
    )
    stats = connection.stats
    assert (stats.syn_count, stats.ack_count, stats.fin_count, stats.rst_count) == (2, 6, 2, 0)
    assert stats.state is TcpState.CLOSED


def test_syn_classification_helpers():
    assert is_new_syn(flags("S")) and not is_new_syn(flags("SA")) and not is_new_syn(None)
    assert is_syn_ack(flags("SA")) and not is_syn_ack(flags("S")) and not is_syn_ack(None)
