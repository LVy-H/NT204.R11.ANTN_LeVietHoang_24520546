from __future__ import annotations

import re

from ..model import DecodedForm, DecodedUri, DecodeStatus
from .text import decode_text

_HEX = frozenset(b"0123456789abcdefABCDEF")
_REMAINING_ESCAPE = re.compile(r"%[0-9A-Fa-f]{2}")
_SCHEME = re.compile(rb"[A-Za-z][A-Za-z0-9+.-]*://")


def percent_decode(raw: bytes) -> tuple[bytes, bool]:
    """One left-to-right pass: `%XX` → that byte; every other `%` is kept literally.

    Returns (decoded, had_invalid_escape). Output of one escape is never re-read, so
    `%2541` becomes `%41`, not `A`."""
    pos = raw.find(b"%")
    if pos < 0:
        return raw, False
    out = bytearray()
    invalid = False
    start = 0
    size = len(raw)
    while pos >= 0:
        out += raw[start:pos]
        if pos + 2 < size and raw[pos + 1] in _HEX and raw[pos + 2] in _HEX:
            out.append(int(raw[pos + 1 : pos + 3], 16))
            start = pos + 3
        else:
            out.append(0x25)  # "%"
            invalid = True
            start = pos + 1
        pos = raw.find(b"%", start)
    out += raw[start:]
    return bytes(out), invalid


def _component(raw: bytes, *, plus: bool) -> tuple[str, bool, bool]:
    """Decode one URI component → (text, changed, partial)."""
    changed = False
    if plus and b"+" in raw:
        raw = raw.replace(b"+", b" ")
        changed = True
    decoded, invalid = percent_decode(raw)
    if len(decoded) != len(raw):  # every valid escape shortens the data by two bytes
        changed = True
    text = decode_text(decoded)
    if text.status is DecodeStatus.DECODED:
        changed = True
    return text.text or "", changed, invalid or text.status is DecodeStatus.PARTIAL


def _pairs(raw: bytes) -> tuple[list[list[str]], bool, bool]:
    """`a=1&b=&c&a=2` → [["a","1"],["b",""],["c",""],["a","2"]]; empty segments dropped."""
    params: list[list[str]] = []
    changed = partial = False
    for segment in raw.split(b"&"):
        if not segment:
            continue
        name, _, value = segment.partition(b"=")
        name_text, name_changed, name_partial = _component(name, plus=True)
        value_text, value_changed, value_partial = _component(value, plus=True)
        params.append([name_text, value_text])
        changed = changed or name_changed or value_changed
        partial = partial or name_partial or value_partial
    return params, changed, partial


def _status(changed: bool, partial: bool) -> DecodeStatus:
    if partial:
        return DecodeStatus.PARTIAL
    return DecodeStatus.DECODED if changed else DecodeStatus.UNCHANGED


def _target_bytes(uri: str) -> bytes:
    # The parser stores the target latin-1 decoded, so latin-1 restores the wire bytes.
    # Loaded events may carry other code points; their UTF-8 form is the best guess.
    try:
        return uri.encode("latin-1")
    except UnicodeEncodeError:
        return uri.encode("utf-8", "surrogatepass")


def decode_uri(uri: str) -> DecodedUri:
    raw = _target_bytes(uri)
    head, mark, query = raw.partition(b"?")
    head_text, _, partial = _component(head, plus=False)
    scheme = _SCHEME.match(head)
    if scheme is None:
        path = head_text
    else:  # absolute-form: drop scheme://authority
        slash = head.find(b"/", scheme.end())
        path = _component(head[slash:], plus=False)[0] if slash >= 0 else ""
    text = head_text
    query_text: str | None = None
    params: list[list[str]] = []
    if mark:
        query_text, _, query_partial = _component(query, plus=True)
        params = _pairs(query)[0]
        text = f"{head_text}?{query_text}"
        partial = partial or query_partial
    return DecodedUri(
        text=text,
        path=path,
        query=query_text,
        params=params,
        status=_status(text != uri, partial),
        double_encoded=_REMAINING_ESCAPE.search(text) is not None,
    )


def decode_form(data: bytes) -> DecodedForm:
    params, changed, partial = _pairs(data)
    return DecodedForm(params=params, status=_status(changed, partial))
