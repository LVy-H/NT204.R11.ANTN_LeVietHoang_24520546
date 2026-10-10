from __future__ import annotations

import re

from ..issues import Issues, ParseError
from ..model import HttpBody, HttpHeader, HttpMessage

NAME = "HTTP"
PORTS = frozenset((80, 3128, 8000, 8008, 8080, 8081, 8888, 9080))

METHODS = frozenset(b"GET POST PUT DELETE HEAD OPTIONS PATCH TRACE CONNECT PROPFIND".split())
METHODS |= frozenset(b"PROPPATCH MKCOL COPY MOVE LOCK UNLOCK".split())

REQUEST_LINE = re.compile(rb"^([A-Z]{3,12})[ \t]+(\S+)[ \t]+HTTP/(\d+\.\d+)$")
STATUS_LINE = re.compile(rb"^HTTP/(\d+\.\d+)[ \t]+(\d{3})(?:[ \t]+(.*))?$")
HEADER_LINE = re.compile(rb"^([!-9;-~]+):[ \t]*(.*)$")
CONTINUATION = re.compile(rb"^[ \t]+(.*)$")

KNOWN_REQUEST_PREFIX = re.compile(
    rb"^(?:" + rb"|".join(sorted(METHODS)) + rb")[ \t]+\S+[ \t]+HTTP/\d\.\d"
)
STATUS_PREFIX = re.compile(rb"^HTTP/\d\.\d[ \t]+\d{3}")
METHOD_TOKEN = re.compile(rb"^[A-Z]{3,12}[ \t]+\S")
VERSION_TOKEN = re.compile(rb"HTTP/\d\.\d")

MAX_HEADER_BYTES = 65536
SCORE_WINDOW = 512
SEPARATORS = (b"\r\n\r\n", b"\n\n")


def first_line(data: bytes) -> bytes:
    end = data.find(b"\r\n")
    newline = data.find(b"\n")
    if end < 0 or (0 <= newline < end):
        end = newline
    return data if end < 0 else data[:end]


def score(payload: bytes, tcp: bool) -> tuple[float, str | None]:
    window = payload[:SCORE_WINDOW]
    line = first_line(window)
    if STATUS_PREFIX.match(line):
        return 0.95, "HTTP status line"
    if KNOWN_REQUEST_PREFIX.match(line):
        return 0.95, "HTTP request line"
    if METHOD_TOKEN.match(line):
        if VERSION_TOKEN.search(window):
            return 0.8, "HTTP request line without a strict version token"
        return 0.6, "HTTP method token"
    return 0.0, None


def _split(payload: bytes) -> tuple[int, int, bool]:
    """Return (header block end, body offset, terminator found); the earliest terminator wins."""
    found = []
    for separator in SEPARATORS:
        index = payload.find(separator, 0, MAX_HEADER_BYTES + len(separator))
        if index >= 0:
            found.append((index, index + len(separator)))
    if found:
        block_end, body_offset = min(found)
        return block_end, body_offset, True
    return min(len(payload), MAX_HEADER_BYTES), len(payload), False


def _headers(lines: list[bytes], issues: Issues) -> list[HttpHeader]:
    headers: list[HttpHeader] = []
    for raw in lines:
        if not raw:
            continue
        continuation = CONTINUATION.match(raw)
        if continuation and headers:
            last = headers[-1]
            last.value = f"{last.value} {continuation.group(1).decode('latin-1').strip()}"
            continue
        match = HEADER_LINE.match(raw)
        if not match:
            issues.add(
                "malformed_header_line",
                "HTTP header line has no field name",
                line=raw[:120].decode("latin-1"),
            )
            continue
        headers.append(
            HttpHeader(
                name=match.group(1).decode("latin-1"),
                value=match.group(2).decode("latin-1").strip(),
            )
        )
    return headers


def _int_or_none(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value.strip())
    except ValueError:
        return None


def _body(
    message: HttpMessage, offset: int, available: int, complete: bool, issues: Issues
) -> HttpBody:
    transfer = message.header("transfer-encoding")
    if transfer and "chunked" in transfer.lower():
        return HttpBody(
            offset=offset, length=available, transfer_encoding="chunked", truncated=False
        )

    declared = message.header("content-length")
    declared_length = _int_or_none(declared)
    length = available
    truncated = False
    if declared is not None and declared_length is None:
        issues.add("invalid_content_length", f"Content-Length {declared!r} is not an integer")
    if declared_length is not None:
        if declared_length < 0:
            issues.add("invalid_content_length", f"Content-Length {declared_length} is negative")
            declared_length = None
        elif declared_length > available:
            truncated = True
            issues.add(
                "truncated_body",
                "HTTP body is shorter than Content-Length",
                declared=declared_length,
                captured=available,
            )
        else:
            length = declared_length
    elif not complete:
        issues.add(
            "incomplete_message",
            "HTTP message header terminator not found in the captured bytes",
        )
    return HttpBody(
        offset=offset,
        length=length,
        declared_length=declared_length,
        transfer_encoding="identity",
        truncated=truncated,
    )


def parse(payload: bytes, *, tcp: bool, issues: Issues) -> HttpMessage:
    if not payload:
        raise ParseError("decode_error", "HTTP payload is empty")

    block_end, body_offset, complete = _split(payload)
    lines = payload[:block_end].splitlines()
    if not lines:
        raise ParseError("decode_error", "HTTP message has no start line")

    start = lines[0]
    message = HttpMessage(start_line=start.decode("latin-1"), complete=complete)
    request = REQUEST_LINE.match(start)
    if request:
        message.kind = "request"
        message.method = request.group(1).decode("ascii")
        message.uri = request.group(2).decode("latin-1")
        message.version = request.group(3).decode("ascii")
    else:
        status = STATUS_LINE.match(start)
        if not status:
            raise ParseError(
                "decode_error",
                "payload does not start with an HTTP request or status line",
                start_line=start[:120].decode("latin-1"),
            )
        message.kind = "response"
        message.version = status.group(1).decode("ascii")
        message.status_code = int(status.group(2))
        reason = status.group(3)
        message.reason = reason.decode("latin-1").strip() if reason else ""

    message.headers = _headers(lines[1:], issues)
    message.body = _body(message, body_offset, len(payload) - body_offset, complete, issues)
    return message
