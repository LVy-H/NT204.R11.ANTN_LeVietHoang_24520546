from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..issues import Issues
from ..model import (
    DecodedHttp,
    DecodedText,
    DecodeStatus,
    HttpMessage,
    MessageEvent,
    PacketEvent,
    Payload,
    SmtpSession,
    worst_status,
)
from ..payload import looks_binary
from .html import decode_entities
from .mime import decode_message, has_mime_headers
from .text import decode_text
from .url import decode_form, decode_uri

if TYPE_CHECKING:
    from ..pipeline import Emit

FORM_TYPE = "application/x-www-form-urlencoded"
ENTITY_TYPES = frozenset({"text/html", "text/xml", "application/xhtml+xml", "text/plain"})
TEXT_TYPES = frozenset({FORM_TYPE, "application/json", "application/xml", "application/javascript"})
_CHARSET = re.compile(r';\s*charset\s*=\s*"?([^";\s]+)', re.IGNORECASE)
_INVALID_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")
_INVALID_ESCAPE_BYTES = re.compile(rb"%(?![0-9A-Fa-f]{2})")
_LEADING_BOUNDARY = re.compile(rb"\A--[^\r\n]*\r?\n")


@dataclass(slots=True)
class DecoderConfig:
    max_decoded_bytes: int = 1_048_576


def _media_type(content_type: str | None) -> tuple[str | None, str | None]:
    """`text/html; charset="UTF-8"` → ("text/html", "UTF-8"); absent header → (None, None)."""
    if content_type is None:
        return None, None
    media = content_type.split(";", 1)[0].strip().lower() or None
    charset = _CHARSET.search(content_type)
    return media, charset.group(1) if charset else None


def _is_text(media: str) -> bool:
    return media.startswith("text/") or media in TEXT_TYPES or media.endswith(("+json", "+xml"))


def _report_escapes(
    issues: Issues, field: str, status: DecodeStatus | None, invalid_escape: bool
) -> None:
    if status is not DecodeStatus.PARTIAL:
        return
    if invalid_escape:
        issues.add(
            "invalid_escape", f"invalid percent escape kept literally in {field}", field=field
        )
    else:
        issues.add(
            "invalid_charset_bytes", f"{field} is not valid UTF-8 after decoding", field=field
        )


class DecoderStage:
    name = "decoder"

    def __init__(self, config: DecoderConfig | None = None) -> None:
        self.config = config if config is not None else DecoderConfig()

    def process(self, record: PacketEvent | MessageEvent, emit: Emit) -> None:
        issues = Issues(self.name, record.issues)
        limit = self.config.max_decoded_bytes
        if isinstance(record, MessageEvent):
            record.decoded = decode_message(record.data or b"", issues, max_bytes=limit)
            return
        message = record.application.message if record.application is not None else None
        if isinstance(message, HttpMessage):
            record.decoded = self._http(message, record.payload, issues)
        elif isinstance(message, SmtpSession):
            data = record.payload.data if record.payload is not None else None
            if data:
                # a segment may start mid-message at a part delimiter; parse the part's own headers
                data = _LEADING_BOUNDARY.sub(b"", data, count=1)
            if data and has_mime_headers(data):
                decoded = decode_message(data, issues, max_bytes=limit)
                if record.payload.data_truncated:
                    issues.add(
                        "decoded_truncated",
                        "SMTP payload was cut at --max-payload-bytes before MIME decoding",
                        field="payload",
                    )
                    decoded.status = worst_status((decoded.status, DecodeStatus.PARTIAL))
                record.decoded = decoded

    def tick(self, now: float, emit: Emit) -> None:
        return None

    def flush(self, emit: Emit) -> None:
        return None

    def _http(self, message: HttpMessage, payload: Payload | None, issues: Issues) -> DecodedHttp:
        decoded = DecodedHttp()
        if message.kind == "request" and message.uri is not None:
            decoded.uri = decode_uri(message.uri)
            _report_escapes(
                issues, "uri", decoded.uri.status, _INVALID_ESCAPE.search(message.uri) is not None
            )
        body = message.body
        encoding = message.header("content-encoding")
        # chunked transfer decoding and compressed bodies are spec §3 non-goals: the bytes are
        # not the text a form or body decoder would read
        if (
            body is not None
            and body.length
            and body.transfer_encoding != "chunked"
            and (encoding is None or encoding.strip().lower() in ("", "identity"))
        ):
            start = body.offset or 0
            data = payload.data if payload is not None else None
            raw = data[start : start + body.length] if data is not None else b""
            media, charset = _media_type(message.header("content-type"))
            if media == FORM_TYPE:
                decoded.form = decode_form(raw)
                _report_escapes(
                    issues,
                    "form",
                    decoded.form.status,
                    _INVALID_ESCAPE_BYTES.search(raw) is not None,
                )
            decoded.body = self._body(raw, body.length, media, charset, issues)
        decoded.status = worst_status(
            part.status for part in (decoded.uri, decoded.form, decoded.body) if part is not None
        )
        return decoded

    def _body(
        self,
        raw: bytes,
        length: int,
        media: str | None,
        charset: str | None,
        issues: Issues,
    ) -> DecodedText | None:
        if media is None:
            if looks_binary(raw):
                return None
        elif not _is_text(media):
            return None
        limit = self.config.max_decoded_bytes
        text = decode_text(raw, charset, max_bytes=limit)
        if text.status is DecodeStatus.PARTIAL:
            issues.add(
                "invalid_charset_bytes",
                f"HTTP body has bytes that are not valid {text.charset}",
                field="body",
                invalid_byte_count=text.invalid_byte_count,
                first_invalid_offset=text.first_invalid_offset,
            )
        if media is None or media in ENTITY_TYPES:
            text.text, text.entity_count = decode_entities(text.text or "")
            if text.entity_count and text.status is DecodeStatus.UNCHANGED:
                text.status = DecodeStatus.DECODED
        if text.truncated:
            issues.add("decoded_truncated", f"HTTP body text cut at {limit} bytes", field="body")
        if len(raw) < length:
            issues.add(
                "decoded_truncated",
                "HTTP body bytes are missing from the captured payload",
                field="body",
                expected=length,
                available=len(raw),
            )
            text.status = worst_status((text.status, DecodeStatus.PARTIAL))
        return text
