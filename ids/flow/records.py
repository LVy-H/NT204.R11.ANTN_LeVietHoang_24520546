from __future__ import annotations

import math
from typing import TYPE_CHECKING

from ..model import Direction, Endpoint, EndReason, FlowRecord, FlowRef, PacketEvent, TcpInfo
from ..model.event import UNKNOWN
from .key import FlowKey, flow_id, start_us
from .tcp import TcpConnection, is_syn_ack

if TYPE_CHECKING:
    from .smtp import SmtpReassembler

PAYLOAD_METHODS = frozenset({"payload", "port+payload"})


def packet_time(event: PacketEvent) -> float | None:
    """Normalized timestamp when the preprocessor set one, else the raw one; None if unusable."""
    normalized = event.normalized
    value = normalized.timestamp if normalized is not None else None
    if value is None:
        value = event.timestamp
    if value is None or isinstance(value, bool) or not math.isfinite(value):
        return None
    return float(value)


def packet_bytes(event: PacketEvent) -> int:
    """IPv4 total length, else captured payload length, else 0."""
    if event.network is not None and event.network.total_length is not None:
        return event.network.total_length
    if event.payload is not None and event.payload.length is not None:
        return event.payload.length
    return 0


def payload_bytes(event: PacketEvent) -> int:
    """Transport payload length, else captured payload length, else 0."""
    if event.transport is not None and event.transport.payload_length is not None:
        return event.transport.payload_length
    if event.payload is not None and event.payload.length is not None:
        return event.payload.length
    return 0


class FlowState:
    """Mutable per-flow state. `record` is filled in place and handed out by `finish`."""

    __slots__ = ("_app_rank", "id_origin", "key", "record", "smtp", "tcp", "touched")

    def __init__(
        self,
        key: FlowKey,
        src: Endpoint,
        dst: Endpoint,
        event: PacketEvent,
        timestamp: float,
        generation: int = 0,
    ) -> None:
        self.key = key
        # (creation time in µs, generation): what the flow_id hashes
        self.id_origin = (start_us(timestamp), generation)
        self.tcp: TcpConnection | None = None
        endpoint_a, endpoint_b = src, dst
        if isinstance(event.transport, TcpInfo):
            flags = event.transport.flags
            if is_syn_ack(flags):
                endpoint_a, endpoint_b = dst, src
            self.tcp = TcpConnection(flags)
        self.record = FlowRecord(
            flow_id=flow_id(key, timestamp, generation),
            protocol=key.proto,
            application_protocol=UNKNOWN,
            endpoint_a=endpoint_a,
            endpoint_b=endpoint_b,
            start_time=timestamp,
            last_seen=timestamp,
            tcp=self.tcp.stats if self.tcp is not None else None,
            first_packet_id=event.packet_id,
        )
        self.touched = timestamp  # tracker clock at the latest packet; drives expiry
        self._app_rank: tuple[int, float] | None = None
        self.smtp: SmtpReassembler | None = None  # set by the table once the flow is SMTP

    def add(self, event: PacketEvent, forward: bool, timestamp: float, now: float) -> FlowRef:
        """Account one packet sent in `forward` (A→B) or backward direction; `now` = clock."""
        record = self.record
        self.touched = now
        if timestamp < record.start_time:
            record.start_time = timestamp
        if timestamp > record.last_seen:
            record.last_seen = timestamp
        size = packet_bytes(event)
        payload = payload_bytes(event)
        record.packet_count += 1
        record.byte_count += size
        record.payload_byte_count += payload
        direction = record.forward if forward else record.backward
        direction.packet_count += 1
        direction.byte_count += size
        direction.payload_byte_count += payload
        record.last_packet_id = event.packet_id
        self._observe_application(event)
        state = None
        if self.tcp is not None:
            tcp = event.transport  # a TCP key guarantees TcpInfo
            state = self.tcp.update(forward, tcp.flags, tcp.seq, tcp.ack, payload)
        return FlowRef(
            flow_id=record.flow_id,
            direction=Direction.FORWARD if forward else Direction.BACKWARD,
            state=state,
            flow_packet_index=record.packet_count,
        )

    def finish(self, reason: EndReason) -> FlowRecord:
        record = self.record
        record.end_reason = reason
        record.duration = round(record.last_seen - record.start_time, 6)
        return record

    def _observe_application(self, event: PacketEvent) -> None:
        application = event.application
        if application is None:
            return
        normalized = event.normalized
        protocol = application.protocol
        if normalized is not None and normalized.application_protocol:
            protocol = normalized.application_protocol
        if not protocol or protocol == UNKNOWN:
            return
        detection = application.detection
        if detection is None:
            rank = (0, 0.0)
        else:
            rank = (int(detection.method in PAYLOAD_METHODS), detection.confidence or 0.0)
        if self._app_rank is None or rank > self._app_rank:
            self._app_rank = rank
            self.record.application_protocol = protocol
