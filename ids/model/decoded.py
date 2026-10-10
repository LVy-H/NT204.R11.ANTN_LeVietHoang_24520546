from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import Enum
from typing import ClassVar


class DecodeStatus(str, Enum):
    NOT_APPLICABLE = "not_applicable"
    UNCHANGED = "unchanged"
    DECODED = "decoded"
    PARTIAL = "partial"
    FAILED = "failed"


_SEVERITY = {
    DecodeStatus.NOT_APPLICABLE: 0,
    DecodeStatus.UNCHANGED: 1,
    DecodeStatus.DECODED: 2,
    DecodeStatus.PARTIAL: 3,
    DecodeStatus.FAILED: 4,
}


def worst_status(statuses: Iterable[DecodeStatus | None]) -> DecodeStatus:
    present = [s for s in statuses if s is not None]
    if not present:
        return DecodeStatus.NOT_APPLICABLE
    return max(present, key=_SEVERITY.__getitem__)


@dataclass(slots=True)
class DecodedText:
    text: str | None = None
    charset: str | None = None  # "ascii" | "utf-8" | declared charset name
    status: DecodeStatus | None = None
    invalid_byte_count: int | None = None
    first_invalid_offset: int | None = None
    truncated: bool | None = None
    entity_count: int | None = None  # set only by HTML entity decoding


@dataclass(slots=True)
class DecodedUri:
    text: str | None = None  # whole target, percent-decoded once
    path: str | None = None
    query: str | None = None
    params: list[list[str]] = field(default_factory=list)  # [[name, value], ...]
    status: DecodeStatus | None = None
    double_encoded: bool | None = None


@dataclass(slots=True)
class DecodedForm:
    params: list[list[str]] = field(default_factory=list)
    status: DecodeStatus | None = None


@dataclass(slots=True)
class DecodedHttp:
    TAG: ClassVar[tuple[str, str]] = ("kind", "http")
    kind: str | None = "http"
    uri: DecodedUri | None = None
    form: DecodedForm | None = None
    body: DecodedText | None = None
    status: DecodeStatus | None = None  # worst of the parts present


@dataclass(slots=True)
class MimeHeaders:
    subject: str | None = None
    from_: str | None = field(default=None, metadata={"json": "from"})
    to: str | None = None
    cc: str | None = None
    date: str | None = None
    message_id: str | None = None


@dataclass(slots=True)
class MimePart:
    index: int | None = None
    content_type: str | None = None
    charset: str | None = None
    transfer_encoding: str | None = None
    filename: str | None = None
    size: int | None = None  # decoded byte size
    sha256: str | None = None  # of decoded bytes
    text: str | None = None  # text/* parts only
    status: DecodeStatus | None = None
    truncated: bool | None = None


@dataclass(slots=True)
class DecodedMime:
    TAG: ClassVar[tuple[str, str]] = ("kind", "mime")
    kind: str | None = "mime"
    headers: MimeHeaders | None = None
    parts: list[MimePart] = field(default_factory=list)
    status: DecodeStatus | None = None
