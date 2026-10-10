from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..model import MessageEvent, PacketEvent, PreprocessStatus
from .key import make_key
from .records import packet_time
from .table import FlowTable

if TYPE_CHECKING:
    from ..pipeline import Emit
    from ..stats import Stats


@dataclass(slots=True)
class FlowConfig:
    tcp_idle_timeout: float = 300.0
    udp_idle_timeout: float = 60.0
    tcp_closed_timeout: float = 5.0
    max_flows: int = 100_000
    max_message_bytes: int = 1_048_576


class FlowTrackerStage:
    """Annotates packets with `flow`, emits FlowRecords and reassembled SMTP MessageEvents."""

    name = "flow"

    def __init__(self, config: FlowConfig | None = None, stats: Stats | None = None) -> None:
        self.config = config if config is not None else FlowConfig()
        self._stats = stats
        self._table = FlowTable(
            tcp_idle_timeout=self.config.tcp_idle_timeout,
            udp_idle_timeout=self.config.udp_idle_timeout,
            tcp_closed_timeout=self.config.tcp_closed_timeout,
            max_flows=self.config.max_flows,
            max_message_bytes=self.config.max_message_bytes,
        )

    @property
    def active_count(self) -> int:
        return self._table.active_count

    def process(self, record: PacketEvent | MessageEvent, emit: Emit) -> None:
        if not isinstance(record, PacketEvent):
            return
        if record.preprocess_status is PreprocessStatus.INVALID:
            return
        timestamp = packet_time(record)
        if timestamp is None:
            return
        found = make_key(record)
        if found is None:
            return
        key, src, dst = found
        record.flow = self._table.apply(record, key, src, dst, timestamp, emit)

    def tick(self, now: float, emit: Emit) -> None:
        self._table.advance(now, emit)

    def flush(self, emit: Emit) -> None:
        if self._stats is not None:
            self._stats.extra["active_flows"] = self._table.active_count
        self._table.flush(emit)
