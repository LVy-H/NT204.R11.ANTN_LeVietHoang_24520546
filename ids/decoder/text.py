from __future__ import annotations

import re

from ..model import DecodedText, DecodeStatus

_ESCAPED = re.compile("[\udc80-\udcff]")
_SURROGATE = re.compile("[\ud800-\udfff]")


def _declared(data: bytes, declared_charset: str | None) -> tuple[str, str] | None:
    """Strict decode with a charset Python knows; None when unknown, failing or unsafe.

    Escape codecs (unicode_escape, utf-7, ...) can yield lone surrogates, which no UTF-8
    writer accepts, so such a result counts as a failed decode."""
    if not declared_charset:
        return None
    name = declared_charset.strip().lower()
    if not name:
        return None
    try:
        text = data.decode(name)
    except (LookupError, ValueError):  # unknown / non-text codec, bad name, UnicodeError
        return None
    if not text.isascii() and _SURROGATE.search(text):
        return None
    return text, name


def _decode_utf8_replace(data: bytes) -> tuple[str, int, int | None]:
    """UTF-8 with errors="replace", plus invalid byte count and first invalid offset.

    surrogateescape maps each invalid byte to one lone surrogate, so the bytes lost by
    re-encoding with "ignore" are the invalid bytes; both passes are linear C codecs."""
    text = data.decode("utf-8", "replace")
    escaped = data.decode("utf-8", "surrogateescape")
    invalid = len(data) - len(escaped.encode("utf-8", "ignore"))
    match = _ESCAPED.search(escaped)
    first = len(escaped[: match.start()].encode("utf-8")) if match is not None else None
    return text, invalid, first


def _cap(text: str, max_bytes: int) -> tuple[str, bool]:
    if len(text) * 4 <= max_bytes:  # a code point is at most 4 UTF-8 bytes
        return text, False
    encoded = text.encode("utf-8")
    if len(encoded) <= max_bytes:
        return text, False
    return encoded[:max_bytes].decode("utf-8", "ignore"), True


def decode_text(
    data: bytes, declared_charset: str | None = None, *, max_bytes: int = 1_048_576
) -> DecodedText:
    """Bytes → text; never raises. `max_bytes` caps the UTF-8 length of the returned text."""
    invalid = 0
    first: int | None = None
    declared = _declared(data, declared_charset)
    if declared is not None:
        text, charset = declared
        # an ASCII-compatible codec reproduces ASCII input exactly; EBCDIC and friends do not
        same = data.isascii() and text == data.decode("ascii")
        status = DecodeStatus.UNCHANGED if same else DecodeStatus.DECODED
    else:
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text, invalid, first = _decode_utf8_replace(data)
            charset = "utf-8"
            status = DecodeStatus.PARTIAL
        else:
            if data.isascii():
                charset, status = "ascii", DecodeStatus.UNCHANGED
            else:
                charset, status = "utf-8", DecodeStatus.DECODED
    text, truncated = _cap(text, max_bytes)
    return DecodedText(
        text=text,
        charset=charset,
        status=status,
        invalid_byte_count=invalid,
        first_invalid_offset=first,
        truncated=truncated,
    )
