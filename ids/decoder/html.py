from __future__ import annotations

import html
import re

# Same reference syntax html.unescape scans for, so per-match unescaping equals unescaping
# the whole string; a match whose unescape is itself is an unknown entity.
_REFERENCE = re.compile(r"&(#[0-9]+;?|#[xX][0-9a-fA-F]+;?|[^\t\n\f <&#;]{1,32};?)")


def decode_entities(text: str) -> tuple[str, int]:
    """Replace HTML character references; returns (text, number of references replaced)."""
    if "&" not in text:
        return text, 0
    count = 0

    def replace(match: re.Match[str]) -> str:
        nonlocal count
        reference = match.group(0)
        try:
            value = html.unescape(reference)
        except ValueError:
            # More decimal digits than int() accepts: a code point far above 0x10FFFF,
            # which html.unescape itself maps to U+FFFD.
            value = "\ufffd"
        if value != reference:
            count += 1
        return value

    return _REFERENCE.sub(replace, text), count
