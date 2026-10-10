from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from typing import Protocol

from .issues import internal_error
from .model import (
    UNKNOWN,
    FlowRecord,
    MessageEvent,
    PacketEvent,
    ProcessingAction,
    RawPacket,
    Tick,
)
from .parsers import PacketParser
from .stats import Stats

Emit = Callable[[PacketEvent | MessageEvent | FlowRecord], None]

UNKNOWN_POLICIES = ("emit", "skip")


class Stage(Protocol):
    name: str

    def process(self, record: PacketEvent | MessageEvent, emit: Emit) -> None: ...

    def tick(self, now: float, emit: Emit) -> None: ...

    def flush(self, emit: Emit) -> None: ...


class Sink(Protocol):
    def write(self, record: PacketEvent | MessageEvent | FlowRecord) -> None: ...


class Runner:
    def __init__(
        self,
        parser: PacketParser,
        stages: Sequence[Stage],
        sink: Sink,
        stats: Stats,
        *,
        unknown_policy: str = "emit",
    ) -> None:
        if unknown_policy not in UNKNOWN_POLICIES:
            raise ValueError(
                f"unknown_policy must be one of {UNKNOWN_POLICIES}, got {unknown_policy!r}"
            )
        self.parser = parser
        self.stages = tuple(stages)
        self.sink = sink
        self.stats = stats
        self.skip_unknown = unknown_policy == "skip"

    def run(self, source: Iterable[RawPacket | PacketEvent | Tick]) -> None:
        try:
            for item in source:
                if isinstance(item, Tick):
                    self._tick(item.now)
                elif isinstance(item, PacketEvent):
                    self._process(item)
                else:
                    self._process(self.parser.parse(item))
        except KeyboardInterrupt:
            self._flush()
            raise
        self._flush()

    def _process(self, record: PacketEvent | MessageEvent) -> None:
        for stage in self.stages:
            if record.processing_action is ProcessingAction.DROP:
                self.stats.dropped(record)
                return
            emitted: list[PacketEvent | MessageEvent | FlowRecord] = []
            try:
                stage.process(record, emitted.append)
            except Exception as error:
                record.issues.append(internal_error(stage.name, error))
            self._dispatch(emitted)
        if record.processing_action is ProcessingAction.DROP:
            self.stats.dropped(record)
        elif (
            self.skip_unknown
            and isinstance(record, PacketEvent)
            and record.application_protocol == UNKNOWN
        ):
            self.stats.skipped(record)
        else:
            self._write(record)

    def _tick(self, now: float) -> None:
        for stage in self.stages:
            emitted: list[PacketEvent | MessageEvent | FlowRecord] = []
            try:
                stage.tick(now, emitted.append)
            except Exception:
                self.stats.stage_error(stage.name, "tick")
            self._dispatch(emitted)

    def _flush(self) -> None:
        for stage in self.stages:
            emitted: list[PacketEvent | MessageEvent | FlowRecord] = []
            try:
                stage.flush(emitted.append)
            except Exception:
                self.stats.stage_error(stage.name, "flush")
            self._dispatch(emitted)

    def _dispatch(self, emitted: list[PacketEvent | MessageEvent | FlowRecord]) -> None:
        for record in emitted:
            if isinstance(record, MessageEvent):
                self._process(record)
            else:
                self._write(record)

    def _write(self, record: PacketEvent | MessageEvent | FlowRecord) -> None:
        self.sink.write(record)
        self.stats.observe(record)
