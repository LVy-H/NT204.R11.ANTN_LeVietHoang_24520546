from __future__ import annotations

import json
import sys
from collections.abc import Iterable, Iterator
from pathlib import Path

from ..codec import decode_packet
from ..issues import Issue
from ..model import PacketEvent

SKIPPED_RECORD_TYPES = frozenset(("flow", "message"))
STAGE_OUTPUT_ISSUE_STAGES = frozenset(("decoder", "preprocess", "flow"))


def _reject_constant(name: str) -> object:
    raise ValueError(f"{name} is not valid JSON")


def _clear_stage_outputs(event: PacketEvent) -> None:
    """Drop what the decoder, preprocessor and flow tracker wrote; they run again."""
    event.decoded = None
    event.normalized = None
    event.preprocess_status = None
    event.processing_action = None
    event.reason.clear()
    event.flow = None
    event.issues[:] = [
        issue for issue in event.issues if issue.stage not in STAGE_OUTPUT_ISSUE_STAGES
    ]


class EventsSource:
    """Schema v2 packet events from a JSON Lines file; "-" reads stdin."""

    source = "events"

    def __init__(self, path: str | Path, *, count: int | None = None) -> None:
        self.path = str(path)
        self.origin = "stdin" if self.path == "-" else self.path
        self.count = count
        self.warnings: list[str] = []
        self.events_loaded = 0
        self.skipped_records = 0

    def close(self) -> None:
        """The input file lives inside items(); stdin is never closed."""

    def describe(self) -> dict[str, object]:
        return {
            "source": self.source,
            "origin": self.origin,
            "count_limit": self.count,
            "events_loaded": self.events_loaded,
            "skipped_records": self.skipped_records,
        }

    def items(self) -> Iterator[PacketEvent]:
        if self.count is not None and self.count <= 0:
            return
        if self.path == "-":
            yield from self._read(sys.stdin.buffer)
            return
        with open(self.path, "rb") as handle:
            yield from self._read(handle)

    def _read(self, lines: Iterable[bytes]) -> Iterator[PacketEvent]:
        for line_number, line in enumerate(lines, start=1):
            if not line.strip():
                continue
            event = self._load(line_number, line)
            if event is None:
                continue
            self.events_loaded += 1
            yield event
            if self.count is not None and self.events_loaded >= self.count:
                return

    def _load(self, line_number: int, line: bytes) -> PacketEvent | None:
        try:
            obj = json.loads(line, parse_constant=_reject_constant)
        except (ValueError, RecursionError) as error:
            issue = Issue("load", "invalid_json", str(error), {"line": line_number})
            return PacketEvent(packet_id=line_number, issues=[issue])
        record_type = obj.get("record_type") if isinstance(obj, dict) else None
        if isinstance(record_type, str) and record_type in SKIPPED_RECORD_TYPES:
            self.skipped_records += 1
            self.warnings.append(f"line {line_number}: skipped record_type {record_type!r}")
            return None
        event, issues = decode_packet(obj)
        if not isinstance(obj, dict):
            event.packet_id = line_number
            for issue in issues:
                issue.context["line"] = line_number
        _clear_stage_outputs(event)
        event.issues.extend(issues)
        return event
