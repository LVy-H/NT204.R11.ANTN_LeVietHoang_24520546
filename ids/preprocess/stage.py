"""Preprocessor stage: normalize + validate packet events, grade message events."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..model import (
    MessageEvent,
    PacketEvent,
    PreprocessStatus,
    ProcessingAction,
)
from .normalize import normalize
from .validate import decode_reason, issue_reason, validate

if TYPE_CHECKING:
    from ..pipeline import Emit

PREPROCESS_POLICIES = ("mark", "drop")


@dataclass(slots=True)
class PreprocessConfig:
    invalid_policy: str = "mark"  # "mark" | "drop"
    unsupported_policy: str = "mark"  # "mark" | "drop"
    clock: Callable[[], float] = time.time

    def __post_init__(self) -> None:
        for name in ("invalid_policy", "unsupported_policy"):
            value = getattr(self, name)
            if value not in PREPROCESS_POLICIES:
                raise ValueError(f"{name} must be one of {PREPROCESS_POLICIES}, got {value!r}")


def _action(policy: str) -> ProcessingAction:
    return ProcessingAction.DROP if policy == "drop" else ProcessingAction.MARK


class PreprocessorStage:
    name = "preprocess"

    def __init__(self, config: PreprocessConfig | None = None) -> None:
        self._config = config if config is not None else PreprocessConfig()

    def process(self, record: PacketEvent | MessageEvent, emit: Emit) -> None:
        if isinstance(record, PacketEvent):
            self._packet(record)
        elif isinstance(record, MessageEvent):
            _message(record)

    def tick(self, now: float, emit: Emit) -> None:
        """Stateless stage: nothing expires."""

    def flush(self, emit: Emit) -> None:
        """Stateless stage: nothing is buffered."""

    def _packet(self, event: PacketEvent) -> None:
        normalized, notes = normalize(event)
        status, reasons, unsupported = validate(event, normalized, now=self._config.clock())
        for note in notes:
            if note not in reasons:
                reasons.append(note)
        if notes and status is PreprocessStatus.VALID:
            status = PreprocessStatus.PARTIAL
        event.normalized = normalized
        event.preprocess_status = status
        event.reason = reasons
        if status is PreprocessStatus.INVALID:
            event.processing_action = _action(self._config.invalid_policy)
        elif unsupported:
            event.processing_action = _action(self._config.unsupported_policy)
        elif status is PreprocessStatus.PARTIAL:
            event.processing_action = ProcessingAction.MARK
        else:
            event.processing_action = ProcessingAction.FORWARD


def _message(message: MessageEvent) -> None:
    """Spec §9.7: a reassembled message is partial when incomplete, cut, gapped or mis-decoded."""
    reasons: list[str] = []
    if message.complete is not True:
        reasons.append("message_incomplete")
    if message.truncated:
        reasons.append("message_truncated")
    if message.gap:
        reasons.append("message_gap")
    status = message.decoded.status if message.decoded is not None else None
    decoded = decode_reason("mime", status)
    if decoded is not None:
        reasons.append(decoded)
    for issue in message.issues:
        reason = issue_reason(issue)
        if reason not in reasons:
            reasons.append(reason)
    message.reason = reasons
    if reasons:
        message.preprocess_status = PreprocessStatus.PARTIAL
        message.processing_action = ProcessingAction.MARK
    else:
        message.preprocess_status = PreprocessStatus.VALID
        message.processing_action = ProcessingAction.FORWARD
