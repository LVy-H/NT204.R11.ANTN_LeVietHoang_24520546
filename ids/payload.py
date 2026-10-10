from __future__ import annotations

import hashlib

from .model.packet import Payload

PREVIEW_LIMIT = 256
HEX_LIMIT = 64

_PRINTABLE = bytes(range(32, 127)) + b"\t\n\r"
_MASK = bytes(b if 32 <= b < 127 else 0x2E for b in range(256))


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def printable_ratio(data: bytes) -> float:
    if not data:
        return 1.0
    return (len(data) - len(data.translate(None, _PRINTABLE))) / len(data)


def looks_binary(data: bytes) -> bool:
    if not data:
        return False
    return 0 in data or printable_ratio(data) < 0.75


def _render(chunk: bytes, binary: bool, cut: bool) -> tuple[str, str]:
    if binary:
        return chunk.translate(_MASK).decode("ascii"), "binary"
    try:
        return chunk.decode("utf-8"), "utf-8"
    except UnicodeDecodeError as error:
        if cut and error.reason == "unexpected end of data":
            return chunk[: error.start].decode("utf-8"), "utf-8"
        return chunk.decode("latin-1"), "latin-1"


def make_payload(data: bytes, *, max_bytes: int = 65535, preview_limit: int = 256) -> Payload:
    length = len(data)
    binary = looks_binary(data)
    preview_truncated = length > preview_limit
    preview, encoding = _render(data[:preview_limit], binary, preview_truncated)
    return Payload(
        length=length,
        sha256=sha256_hex(data),
        data=data[:max_bytes],
        data_truncated=length > max_bytes,
        preview=preview,
        preview_truncated=preview_truncated,
        preview_encoding=encoding,
        binary=binary,
        preview_hex=data[:HEX_LIMIT].hex() if binary else None,
    )


def describe(
    data: bytes, limit: int = PREVIEW_LIMIT, hex_limit: int = HEX_LIMIT
) -> dict[str, object]:
    binary = looks_binary(data)
    truncated = len(data) > limit
    text, encoding = _render(data[:limit], binary, truncated)
    summary: dict[str, object] = {
        "length": len(data),
        "sha256": sha256_hex(data),
        "preview": text,
        "preview_truncated": truncated,
        "preview_encoding": encoding,
        "binary": binary,
    }
    if binary:
        summary["preview_hex"] = data[:hex_limit].hex()
    return summary
