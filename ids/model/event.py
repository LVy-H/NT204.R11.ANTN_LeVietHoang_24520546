from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import ClassVar

from ..issues import Issue
from .app import ApplicationInfo
from .decoded import DecodedHttp, DecodedMime
from .flow import FlowRecord, FlowRef
from .normalized import Normalized
from .packet import CaptureInfo, Ipv4Info, LinkInfo, Payload, TcpInfo, UdpInfo

UNKNOWN = "UNKNOWN"


class PreprocessStatus(str, Enum):
    VALID = "valid"
    PARTIAL = "partial"
    INVALID = "invalid"


class ProcessingAction(str, Enum):
    FORWARD = "forward"
    MARK = "mark"
    DROP = "drop"


@dataclass(slots=True)
class PacketEvent:
    RECORD_TYPE: ClassVar[str] = "packet"
    packet_id: int | None = None
    timestamp: float | None = None
    capture: CaptureInfo | None = None
    link: LinkInfo | None = None
    network: Ipv4Info | None = None
    transport: TcpInfo | UdpInfo | None = None
    application: ApplicationInfo | None = None
    payload: Payload | None = None
    decoded: DecodedHttp | DecodedMime | None = None
    normalized: Normalized | None = None
    preprocess_status: PreprocessStatus | None = None
    processing_action: ProcessingAction | None = None
    reason: list[str] = field(default_factory=list)
    flow: FlowRef | None = None
    issues: list[Issue] = field(default_factory=list)

    @property
    def application_protocol(self) -> str:
        if self.application is None or not self.application.protocol:
            return UNKNOWN
        return self.application.protocol

    @property
    def protocol(self) -> str | None:
        return self.transport.protocol if self.transport is not None else None

    @property
    def src_ip(self) -> str | None:
        return self.network.src_ip if self.network is not None else None

    @property
    def dst_ip(self) -> str | None:
        return self.network.dst_ip if self.network is not None else None

    @property
    def src_port(self) -> int | None:
        return self.transport.src_port if self.transport is not None else None

    @property
    def dst_port(self) -> int | None:
        return self.transport.dst_port if self.transport is not None else None

    @property
    def is_tcp(self) -> bool:
        return isinstance(self.transport, TcpInfo)

    @property
    def event_type(self) -> str:
        if self.network is None:
            return "unparsed"
        if self.transport is None:
            return "network_only"
        protocol = self.application_protocol
        message = self.application.message if self.application is not None else None
        kind = getattr(message, "kind", None)
        if kind:
            return f"{protocol.lower()}_{kind}"
        if protocol != UNKNOWN:
            return f"{protocol.lower()}_unparsed"
        if self.payload is not None and self.payload.length:
            return "unknown_payload"
        return f"{(self.transport.protocol or 'transport').lower()}_segment"


@dataclass(slots=True)
class MessageEvent:
    RECORD_TYPE: ClassVar[str] = "message"
    message_id: str | None = None  # f"{flow_id}-{n}", n 1-based per flow
    flow_id: str | None = None
    protocol: str | None = None  # "SMTP"
    packet_ids: list[int] = field(default_factory=list)
    start_time: float | None = None
    end_time: float | None = None
    data: bytes | None = None
    complete: bool | None = None
    truncated: bool | None = None
    gap: bool | None = None
    decoded: DecodedMime | None = None
    preprocess_status: PreprocessStatus | None = None
    processing_action: ProcessingAction | None = None
    reason: list[str] = field(default_factory=list)
    issues: list[Issue] = field(default_factory=list)


Record = PacketEvent | MessageEvent | FlowRecord
