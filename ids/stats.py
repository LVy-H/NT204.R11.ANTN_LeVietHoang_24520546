from __future__ import annotations

from collections import Counter

from .issues import Issue
from .model import FlowRecord, MessageEvent, PacketEvent

RECORD_TYPES = (PacketEvent.RECORD_TYPE, MessageEvent.RECORD_TYPE, FlowRecord.RECORD_TYPE)


class Stats:
    def __init__(self) -> None:
        self.packets_seen = 0
        self.records_written: Counter[str] = Counter()
        self.dropped_count = 0
        self.skipped_count = 0
        self.packets_with_issues = 0
        self.first_timestamp: float | None = None
        self.last_timestamp: float | None = None
        self.event_types: Counter[str] = Counter()
        self.protocols: Counter[str] = Counter()
        self.application_protocols: Counter[str] = Counter()
        self.detection_methods: Counter[str] = Counter()
        self.issue_codes: Counter[str] = Counter()
        self.preprocess_status: Counter[str] = Counter()
        self.processing_action: Counter[str] = Counter()
        self.flow_end_reasons: Counter[str] = Counter()
        self.messages: Counter[str] = Counter()
        self.stage_errors: Counter[str] = Counter()
        self.extra: dict[str, object] = {}

    @property
    def written(self) -> int:
        return sum(self.records_written.values())

    def observe(self, record: PacketEvent | MessageEvent | FlowRecord) -> None:
        self.records_written[record.RECORD_TYPE] += 1
        if isinstance(record, FlowRecord):
            if record.end_reason is not None:
                self.flow_end_reasons[record.end_reason.value] += 1
            return
        self._outcome(record)
        self._issues(record.issues)
        if isinstance(record, MessageEvent):
            self.messages["complete" if record.complete else "incomplete"] += 1
            return
        self.event_types[record.event_type] += 1
        self.protocols[record.protocol or "none"] += 1
        self.application_protocols[record.application_protocol] += 1
        application = record.application
        if application is not None and application.detection is not None:
            method = application.detection.method
            if method:
                self.detection_methods[method] += 1
        if record.issues:
            self.packets_with_issues += 1

    def dropped(self, record: PacketEvent | MessageEvent) -> None:
        self.dropped_count += 1
        self._outcome(record)

    def skipped(self, record: PacketEvent) -> None:
        self.skipped_count += 1
        self._outcome(record)

    def stage_error(self, stage: str, operation: str) -> None:
        self.stage_errors[f"{stage}/{operation}"] += 1

    def _outcome(self, record: PacketEvent | MessageEvent) -> None:
        if record.preprocess_status is not None:
            self.preprocess_status[record.preprocess_status.value] += 1
        if record.processing_action is not None:
            self.processing_action[record.processing_action.value] += 1
        if isinstance(record, PacketEvent):
            self.packets_seen += 1
            timestamp = record.timestamp
            if timestamp is not None:
                if self.first_timestamp is None:
                    self.first_timestamp = timestamp
                self.last_timestamp = timestamp

    def _issues(self, issues: list[Issue]) -> None:
        for issue in issues:
            self.issue_codes[f"{issue.stage}/{issue.code}"] += 1

    def to_dict(self) -> dict[str, object]:
        summary: dict[str, object] = {
            "packets_seen": self.packets_seen,
            "records_written": {key: self.records_written[key] for key in RECORD_TYPES},
            "dropped": self.dropped_count,
            "skipped": self.skipped_count,
            "packets_with_issues": self.packets_with_issues,
            "first_timestamp": self.first_timestamp,
            "last_timestamp": self.last_timestamp,
            "event_types": dict(self.event_types.most_common()),
            "protocols": dict(self.protocols.most_common()),
            "application_protocols": dict(self.application_protocols.most_common()),
            "detection_methods": dict(self.detection_methods.most_common()),
            "issue_codes": dict(self.issue_codes.most_common()),
            "preprocess_status": dict(self.preprocess_status.most_common()),
            "processing_action": dict(self.processing_action.most_common()),
            "flow_end_reasons": dict(self.flow_end_reasons.most_common()),
            "messages": {
                "complete": self.messages["complete"],
                "incomplete": self.messages["incomplete"],
            },
            "stage_errors": dict(self.stage_errors.most_common()),
        }
        summary.update(self.extra)
        return summary
