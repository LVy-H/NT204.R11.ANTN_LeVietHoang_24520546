from __future__ import annotations

import re
from urllib.parse import parse_qs, urlsplit

from ..errors import DecodeError
from ..payload import describe

METHODS = frozenset(
    b"GET POST PUT DELETE HEAD OPTIONS PATCH TRACE CONNECT PROPFIND PROPPATCH MKCOL COPY MOVE LOCK UNLOCK".split()
)

REQUEST_LINE = re.compile(rb"^([A-Z]{3,12})[ \t]+(\S+)[ \t]+HTTP/(\d+\.\d+)$")
STATUS_LINE = re.compile(rb"^HTTP/(\d+\.\d+)[ \t]+(\d{3})(?:[ \t]+(.*))?$")
HEADER_LINE = re.compile(rb"^([!-9;-~]+):[ \t]*(.*)$")
CONTINUATION = re.compile(rb"^[ \t]+(.*)$")

MAX_HEADER_BYTES = 65536
FORM_TYPES = ("application/x-www-form-urlencoded",)


def first_line(data: bytes) -> bytes:
    end = data.find(b"\r\n")
    newline = data.find(b"\n")
    if end < 0 or (0 <= newline < end):
        end = newline
    return data if end < 0 else data[:end]


def _split(data: bytes) -> tuple[bytes, bytes, bool]:
    for separator in (b"\r\n\r\n", b"\n\n"):
        index = data.find(separator)
        if 0 <= index <= MAX_HEADER_BYTES:
            return data[:index], data[index + len(separator) :], True
    return data[:MAX_HEADER_BYTES], b"", False


def _headers(block: bytes, errors: list[dict]) -> tuple[dict, list[str]]:
    headers: dict[str, list[str]] = {}
    order: list[str] = []
    for raw in block.splitlines()[1:]:
        if not raw:
            continue
        continuation = CONTINUATION.match(raw)
        if continuation and order:
            last = order[-1]
            headers[last][-1] = f"{headers[last][-1]} {continuation.group(1).decode('latin-1').strip()}"
            continue
        match = HEADER_LINE.match(raw)
        if not match:
            errors.append(
                {
                    "stage": "application",
                    "code": "malformed_header_line",
                    "message": "HTTP header line has no field name",
                    "context": {"line": raw[:120].decode("latin-1", "replace")},
                }
            )
            continue
        name = match.group(1).decode("latin-1").strip().lower()
        value = match.group(2).decode("latin-1").strip()
        if name in headers:
            headers[name].append(value)
        else:
            headers[name] = [value]
            order.append(name)
    return headers, order


def _last(headers: dict, name: str):
    values = headers.get(name)
    return values[-1] if values else None


def _int_or_none(value):
    if value is None:
        return None
    try:
        return int(value.strip())
    except ValueError:
        return None


def _body(data: bytes, headers: dict, complete: bool, errors: list[dict]) -> dict:
    transfer = _last(headers, "transfer-encoding")
    if transfer and "chunked" in transfer.lower():
        summary = describe(data)
        summary["encoding"] = "chunked"
        summary["chunked_decoded"] = False
        summary["declared_length"] = None
        summary["truncated"] = False
        return summary

    declared = _last(headers, "content-length")
    declared_length = _int_or_none(declared)
    truncated = False
    if declared is not None and declared_length is None:
        errors.append(
            {
                "stage": "application",
                "code": "invalid_content_length",
                "message": f"Content-Length {declared!r} is not an integer",
            }
        )
    if declared_length is not None:
        if declared_length < 0:
            errors.append(
                {
                    "stage": "application",
                    "code": "invalid_content_length",
                    "message": f"Content-Length {declared_length} is negative",
                }
            )
            declared_length = None
        else:
            truncated = declared_length > len(data)
            if truncated:
                errors.append(
                    {
                        "stage": "application",
                        "code": "truncated_body",
                        "message": "HTTP body is shorter than Content-Length",
                        "context": {"declared": declared_length, "captured": len(data)},
                    }
                )
            data = data[:declared_length]
    elif not complete:
        errors.append(
            {
                "stage": "application",
                "code": "incomplete_message",
                "message": "HTTP message header terminator not found in the captured bytes",
            }
        )

    summary = describe(data)
    summary["encoding"] = "identity"
    summary["declared_length"] = declared_length
    summary["truncated"] = truncated
    return summary


def _target(uri: str) -> dict:
    parts = urlsplit(uri)
    query = parse_qs(parts.query, keep_blank_values=True)
    return {
        "uri": uri,
        "path": parts.path,
        "query": parts.query,
        "query_params": {name: values for name, values in query.items()},
        "authority": parts.netloc,
        "scheme": parts.scheme or None,
    }


def parse(payload: bytes) -> dict:
    if not payload:
        raise DecodeError("HTTP payload is empty", stage="application")

    block, rest, complete = _split(payload)
    lines = block.splitlines()
    if not lines:
        raise DecodeError("HTTP message has no start line", stage="application")

    errors: list[dict] = []
    request = REQUEST_LINE.match(lines[0])
    status = STATUS_LINE.match(lines[0])
    if request:
        method, uri, version = request.group(1), request.group(2), request.group(3)
    elif status:
        method = uri = None
        version = status.group(1)
    else:
        raise DecodeError(
            "payload does not start with an HTTP request or status line",
            stage="application",
            start_line=first_line(block)[:120].decode("latin-1", "replace"),
        )

    headers, order = _headers(block, errors)
    info: dict = {
        "version": version.decode("ascii"),
        "headers": {name: (values[0] if len(values) == 1 else values) for name, values in headers.items()},
        "header_order": order,
        "header_count": len(order),
        "host": _last(headers, "host"),
        "content_type": _last(headers, "content-type"),
        "content_length": _last(headers, "content-length"),
        "connection": _last(headers, "connection"),
        "body": _body(rest, headers, complete, errors),
        "errors": errors,
    }

    if request:
        info["kind"] = "request"
        info["method"] = method.decode("ascii")
        info.update(_target(uri.decode("latin-1")))
        info["user_agent"] = _last(headers, "user-agent")
        info["referer"] = _last(headers, "referer")
        info["accept"] = _last(headers, "accept")
        cookies = _last(headers, "cookie")
        info["cookie"] = cookies
        info["cookie_count"] = len(cookies.split(";")) if cookies else 0
        content_type = _last(headers, "content-type") or ""
        if any(content_type.lower().startswith(kind) for kind in FORM_TYPES):
            form_length = _int_or_none(_last(headers, "content-length"))
            raw_form = rest[:form_length] if form_length is not None else rest
            form = parse_qs(raw_form.decode("latin-1", "replace"), keep_blank_values=True)
            info["form"] = {name: values for name, values in form.items()}
    else:
        info["kind"] = "response"
        info["status_code"] = int(status.group(2))
        reason = status.group(3)
        info["reason"] = reason.decode("latin-1").strip() if reason else ""
        info["server"] = _last(headers, "server")
        cookies = headers.get("set-cookie")
        info["set_cookie"] = cookies if cookies else None

    return info
