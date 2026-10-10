from __future__ import annotations

import hashlib

PREVIEW_LIMIT = 256
HEX_LIMIT = 64


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def printable_ratio(data):
    if not data:
        return 1.0
    return sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13)) / len(data)


def looks_binary(data):
    if not data:
        return False
    return 0 in data or printable_ratio(data) < 0.75


def render(data, limit=PREVIEW_LIMIT):
    truncated = len(data) > limit
    chunk = data[:limit]
    if looks_binary(chunk):
        return "".join(chr(b) if 32 <= b < 127 else "." for b in chunk), truncated, "binary"
    try:
        return chunk.decode("utf-8"), truncated, "utf-8"
    except UnicodeDecodeError:
        return chunk.decode("latin-1", "replace"), truncated, "latin-1"


def describe(data, limit=PREVIEW_LIMIT, hex_limit=HEX_LIMIT):
    text, truncated, encoding = render(data, limit)
    summary = {
        "length": len(data),
        "sha256": sha256_hex(data),
        "preview": text,
        "preview_truncated": truncated,
        "preview_encoding": encoding,
        "binary": looks_binary(data),
    }
    if summary["binary"] and data:
        summary["preview_hex"] = data[:hex_limit].hex()
    return summary
