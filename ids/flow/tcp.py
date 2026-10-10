from __future__ import annotations

from ..model import TcpFlags, TcpFlowStats, TcpState

SEQ_MOD = 1 << 32
_HALF = 1 << 31
TERMINAL_STATES = frozenset({TcpState.CLOSED, TcpState.RESET})


def seq_ge(a: int, b: int) -> bool:
    """True when sequence number `a` is at or after `b` in 32-bit wrap-around space."""
    return (a - b) % SEQ_MOD < _HALF


def is_syn_ack(flags: TcpFlags | None) -> bool:
    return flags is not None and bool(flags.syn) and bool(flags.ack)


def is_new_syn(flags: TcpFlags | None) -> bool:
    """SYN without ACK: the first packet of a new connection attempt."""
    return flags is not None and bool(flags.syn) and not flags.ack


class TcpConnection:
    """TCP state of one flow. Side 0 is endpoint A (forward), side 1 endpoint B.

    The first packet decides the starting state: a SYN gives HANDSHAKE, anything else NEW with
    `midstream`. `update` must then be called for every packet, the first one included.
    """

    __slots__ = ("_ack_seen", "_fin_acked", "_fin_seen", "_fin_seq", "_syn_ack_from_b", "stats")

    def __init__(self, first_flags: TcpFlags | None) -> None:
        syn = first_flags is not None and bool(first_flags.syn)
        self.stats = TcpFlowStats(
            state=TcpState.HANDSHAKE if syn else TcpState.NEW, midstream=not syn
        )
        self._syn_ack_from_b = False
        self._ack_seen = [False, False]
        self._fin_seen = [False, False]
        self._fin_seq: list[int | None] = [None, None]
        self._fin_acked = [False, False]

    @property
    def state(self) -> TcpState:
        return self.stats.state

    def update(
        self,
        forward: bool,
        flags: TcpFlags | None,
        seq: int | None,
        ack: int | None,
        payload_length: int,
    ) -> TcpState:
        """Count the packet's flags, apply one transition, return the state after it."""
        stats = self.stats
        syn = fin = rst = has_ack = False
        if flags is not None:
            syn, fin = bool(flags.syn), bool(flags.fin)
            rst, has_ack = bool(flags.rst), bool(flags.ack)
        if syn:
            stats.syn_count += 1
        if has_ack:
            stats.ack_count += 1
        if fin:
            stats.fin_count += 1
        if rst:
            stats.rst_count += 1
            stats.state = TcpState.RESET
            return TcpState.RESET

        state = self.state
        if state in TERMINAL_STATES:
            return state
        side = 0 if forward else 1
        peer = 1 - side

        if state is TcpState.HANDSHAKE:
            if syn and has_ack and not forward:
                self._syn_ack_from_b = True
            elif forward and has_ack and not syn and self._syn_ack_from_b:
                state = TcpState.ESTABLISHED
                stats.handshake_complete = True
        elif state is TcpState.NEW and has_ack:
            self._ack_seen[side] = True
            if self._ack_seen[peer]:
                state = TcpState.ESTABLISHED

        if fin and not self._fin_seen[side]:
            self._fin_seen[side] = True
            # The FIN occupies the sequence number right after the segment's payload.
            self._fin_seq[side] = None if seq is None else (seq + payload_length) % SEQ_MOD
            state = TcpState.CLOSING

        if state is TcpState.CLOSING and has_ack and self._fin_seen[peer]:
            fin_seq = self._fin_seq[peer]
            # Without sequence numbers (sparse loaded events) any ACK from the peer counts.
            if fin_seq is None or ack is None or seq_ge(ack, (fin_seq + 1) % SEQ_MOD):
                self._fin_acked[peer] = True
            if self._fin_acked[0] and self._fin_acked[1]:
                state = TcpState.CLOSED

        stats.state = state
        return state
