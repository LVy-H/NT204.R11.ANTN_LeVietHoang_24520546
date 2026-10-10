from __future__ import annotations

from collections import OrderedDict
from typing import TYPE_CHECKING

from ..model import Endpoint, EndReason, FlowRef, PacketEvent, TcpState
from .key import FlowKey
from .records import FlowState
from .smtp import SmtpReassembler
from .tcp import TERMINAL_STATES, is_new_syn

if TYPE_CHECKING:
    from ..pipeline import Emit

Lane = OrderedDict[FlowKey, FlowState]

_CLOSED_REASONS = {TcpState.CLOSED: EndReason.CLOSED, TcpState.RESET: EndReason.RESET}


def _closed_reason(flow: FlowState) -> EndReason:
    """End reason of a flow in the closed lane: its terminal TCP state."""
    return _CLOSED_REASONS[flow.tcp.state]


class FlowTable:
    """Active flows in three lanes ordered by last activity: TCP open, TCP closed, UDP.

    The clock is the largest packet or tick time seen and never moves backwards. A flow
    expires when `clock - touched > lane timeout`, where `touched` is the clock value at its
    latest packet.
    """

    def __init__(
        self,
        *,
        tcp_idle_timeout: float,
        udp_idle_timeout: float,
        tcp_closed_timeout: float,
        max_flows: int,
        max_message_bytes: int,
    ) -> None:
        self.tcp_open: Lane = OrderedDict()
        self.tcp_closed: Lane = OrderedDict()
        self.udp: Lane = OrderedDict()
        self.clock: float | None = None
        self.max_flows = max_flows
        self.max_message_bytes = max_message_bytes
        self._lanes = (self.tcp_open, self.tcp_closed, self.udp)
        self._timeouts = (
            (self.tcp_open, tcp_idle_timeout),
            (self.tcp_closed, tcp_closed_timeout),
            (self.udp, udp_idle_timeout),
        )

    @property
    def active_count(self) -> int:
        return len(self.tcp_open) + len(self.tcp_closed) + len(self.udp)

    def advance(self, now: float, emit: Emit) -> float:
        """Move the clock forward to `now` (never back), export expired flows, return clock."""
        if self.clock is None or now > self.clock:
            self.clock = now
        self._expire(self.clock, emit)
        return self.clock

    def apply(
        self,
        event: PacketEvent,
        key: FlowKey,
        src: Endpoint,
        dst: Endpoint,
        timestamp: float,
        emit: Emit,
    ) -> FlowRef:
        """Expire first, then account `event` to its flow (created if needed)."""
        now = self.advance(timestamp, emit)
        if key.proto == "TCP":
            flow, lane = self._tcp_flow(event, key, src, dst, timestamp, emit)
        else:
            lane = self.udp
            flow = lane.get(key)
            if flow is None:
                flow = self._create(lane, key, src, dst, event, timestamp, emit)
            else:
                lane.move_to_end(key)
        forward = src == flow.record.endpoint_a
        ref = flow.add(event, forward, timestamp, now)
        if flow.tcp is not None:
            if flow.smtp is None and flow.record.application_protocol == "SMTP":
                flow.smtp = SmtpReassembler(flow.record.flow_id, self.max_message_bytes)
            if flow.smtp is not None:
                message = flow.smtp.feed(event, forward, timestamp)
                if message is not None:
                    emit(message)
        if lane is self.tcp_open and ref.state in TERMINAL_STATES:
            del self.tcp_open[key]
            self.tcp_closed[key] = flow
        return ref

    def flush(self, emit: Emit) -> None:
        """Export every flow, oldest activity first.

        Closed-lane flows keep their closed/reset reason; the others end with end_of_input.
        """
        while (lane := self._oldest_lane()) is not None:
            _, flow = lane.popitem(last=False)
            self._export(flow, self._reason(lane, flow, EndReason.END_OF_INPUT), emit)

    def _tcp_flow(
        self,
        event: PacketEvent,
        key: FlowKey,
        src: Endpoint,
        dst: Endpoint,
        timestamp: float,
        emit: Emit,
    ) -> tuple[FlowState, Lane]:
        flow = self.tcp_open.get(key)
        if flow is not None:
            self.tcp_open.move_to_end(key)
            return flow, self.tcp_open
        flow = self.tcp_closed.get(key)
        if flow is not None:
            if not is_new_syn(event.transport.flags):
                self.tcp_closed.move_to_end(key)
                return flow, self.tcp_closed
            # Port reuse during the linger: the old connection ends, a new flow starts.
            del self.tcp_closed[key]
            self._export(flow, _closed_reason(flow), emit)
        return self._create(self.tcp_open, key, src, dst, event, timestamp, emit), self.tcp_open

    def _create(
        self,
        lane: Lane,
        key: FlowKey,
        src: Endpoint,
        dst: Endpoint,
        event: PacketEvent,
        timestamp: float,
        emit: Emit,
    ) -> FlowState:
        if self.active_count >= self.max_flows:
            oldest = self._oldest_lane()
            _, evicted = oldest.popitem(last=False)
            self._export(evicted, EndReason.EVICTED, emit)
        flow = FlowState(key, src, dst, event, timestamp)
        lane[key] = flow
        return flow

    def _expire(self, clock: float, emit: Emit) -> None:
        """Export expired lane fronts in order of their expiry deadline."""
        while True:
            best: Lane | None = None
            best_deadline = 0.0
            for lane, timeout in self._timeouts:
                if not lane:
                    continue
                touched = next(iter(lane.values())).touched
                deadline = touched + timeout
                if clock - touched > timeout and (best is None or deadline < best_deadline):
                    best, best_deadline = lane, deadline
            if best is None:
                return
            _, flow = best.popitem(last=False)
            self._export(flow, self._reason(best, flow, EndReason.IDLE_TIMEOUT), emit)

    def _oldest_lane(self) -> Lane | None:
        best: Lane | None = None
        best_touched = 0.0
        for lane in self._lanes:
            if lane:
                touched = next(iter(lane.values())).touched
                if best is None or touched < best_touched:
                    best, best_touched = lane, touched
        return best

    def _reason(self, lane: Lane, flow: FlowState, default: EndReason) -> EndReason:
        return _closed_reason(flow) if lane is self.tcp_closed else default

    def _export(self, flow: FlowState, reason: EndReason, emit: Emit) -> None:
        if flow.smtp is not None:
            message = flow.smtp.finish()
            if message is not None:
                emit(message)  # an unfinished DATA body goes out before its flow record
        emit(flow.finish(reason))
