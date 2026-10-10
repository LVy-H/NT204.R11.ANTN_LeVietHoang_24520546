from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


def jsonable(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).hex()
    if isinstance(value, dict):
        return {str(k): jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [jsonable(v) for v in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return repr(value)


@dataclass(slots=True)
class Issue:
    stage: str | None = None
    code: str | None = None
    message: str | None = None
    context: dict[str, Any] = field(default_factory=dict)


class ParseError(Exception):
    """Fatal problem inside one parser/decoder call. Carries no stage."""

    def __init__(self, code: str, message: str, **context: Any) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.context = context


def internal_error(stage: str, error: BaseException) -> Issue:
    name = type(error).__name__
    return Issue(stage, "internal_error", str(error) or name, {"exception": name})


class Issues:
    """Collector bound to one stage; `scoped()` shares the same record list."""

    __slots__ = ("records", "stage")

    def __init__(self, stage: str, records: list[Issue] | None = None) -> None:
        self.stage = stage
        self.records: list[Issue] = records if records is not None else []

    def add(self, code: str, message: str, **context: Any) -> None:
        self.records.append(Issue(self.stage, code, message, jsonable(context)))

    def scoped(self, stage: str) -> Issues:
        return Issues(stage, self.records)

    def capture(self, error: BaseException) -> None:
        if isinstance(error, ParseError):
            self.records.append(
                Issue(self.stage, error.code, error.message, jsonable(error.context))
            )
        else:
            self.records.append(internal_error(self.stage, error))

    def __bool__(self) -> bool:
        return bool(self.records)

    def __len__(self) -> int:
        return len(self.records)
