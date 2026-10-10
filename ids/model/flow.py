from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import ClassVar


class TcpState(str, Enum):
    NEW = "NEW"
    HANDSHAKE = "HANDSHAKE"
    ESTABLISHED = "ESTABLISHED"
    CLOSING = "CLOSING"
    CLOSED = "CLOSED"
    RESET = "RESET"


class Direction(str, Enum):
    FORWARD = "forward"
    BACKWARD = "backward"


class EndReason(str, Enum):
    CLOSED = "closed"
    RESET = "reset"
    IDLE_TIMEOUT = "idle_timeout"
    EVICTED = "evicted"
    END_OF_INPUT = "end_of_input"


@dataclass(slots=True)
class FlowRef:
    flow_id: str | None = None
    direction: Direction | None = None
    state: TcpState | None = None  # None for UDP
    flow_packet_index: int | None = None  # 1-based


@dataclass(slots=True)
class Endpoint:
    ip: str | None = None
    port: int | None = None


@dataclass(slots=True)
class DirectionStats:
    packet_count: int = 0
    byte_count: int = 0
    payload_byte_count: int = 0


@dataclass(slots=True)
class TcpFlowStats:
    state: TcpState | None = None
    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    handshake_complete: bool = False
    midstream: bool = False


@dataclass(slots=True)
class FlowRecord:
    RECORD_TYPE: ClassVar[str] = "flow"
    flow_id: str | None = None
    protocol: str | None = None  # "TCP" | "UDP"
    application_protocol: str | None = None
    endpoint_a: Endpoint | None = None
    endpoint_b: Endpoint | None = None
    start_time: float | None = None
    last_seen: float | None = None
    duration: float | None = None
    packet_count: int = 0
    byte_count: int = 0
    payload_byte_count: int = 0
    forward: DirectionStats = field(default_factory=DirectionStats)
    backward: DirectionStats = field(default_factory=DirectionStats)
    tcp: TcpFlowStats | None = None
    end_reason: EndReason | None = None
    first_packet_id: int | None = None
    last_packet_id: int | None = None
