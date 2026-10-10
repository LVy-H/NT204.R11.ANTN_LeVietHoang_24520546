from __future__ import annotations

import base64
import quopri
import re
from email import policy
from email.errors import HeaderParseError
from email.header import decode_header
from email.message import Message
from email.parser import BytesParser

from ..issues import Issues
from ..model import DecodedMime, DecodeStatus, MimeHeaders, MimePart, worst_status
from ..payload import sha256_hex
from .text import decode_text, refused_charset


class _SafeMessage(Message):
    def get_param(
        self, param: str, failobj: object = None, header: str = "content-type", unquote: bool = True
    ) -> object:
        # get_content_charset, get_filename and get_boundary all read RFC 2231 values here;
        # a refused charset (quadratic punycode, escape codecs) is read as us-ascii instead
        value = super().get_param(param, failobj, header, unquote)
        if isinstance(value, tuple) and value[0] and refused_charset(value[0]):
            return ("us-ascii", value[1], value[2])
        return value

    def get_boundary(self, failobj: str | None = None) -> str | None:
        try:
            return super().get_boundary(failobj)
        except ValueError:  # RFC 2231 charset name with NUL; the feedparser calls this unguarded
            return failobj


_PARSER = BytesParser(_class=_SafeMessage, policy=policy.compat32)
_MIME_HEADER = re.compile(
    rb"^(?:mime-version|content-type|content-transfer-encoding)[ \t]*:",
    re.IGNORECASE | re.MULTILINE,
)
_DOT_STUFFED = re.compile(rb"^\.\.", re.MULTILINE)
_FOLD = re.compile(r"\r?\n(?=[ \t])")
_B64_WHITESPACE = b" \t\r\n\x0b\x0c"
_B64_OUTSIDE_ALPHABET = re.compile(rb"[^A-Za-z0-9+/=]")
_QP_MALFORMED = re.compile(rb"=(?![0-9A-Fa-f]{2}|\r?\n|\Z)")
_UNCHANGED_ENCODINGS = frozenset({"7bit", "8bit", "binary"})
# decode_header is quadratic in the number of encoded words, so its input is bounded
MAX_HEADER_CHARS = 8192


def has_mime_headers(data: bytes) -> bool:
    """True when the header area (up to the first blank line) has a MIME header line."""
    end = data.find(b"\r\n\r\n")
    if end < 0:
        end = data.find(b"\n\n")
    return _MIME_HEADER.search(data, 0, end if end >= 0 else len(data)) is not None


def unstuff(data: bytes) -> bytes:
    """Drop the SMTP end-of-data line and undo dot-stuffing (RFC 5321 §4.5.2)."""
    if data.endswith(b"\r\n.\r\n") or data == b".\r\n":
        data = data[:-3]
    elif data.endswith(b"\n.\n") or data == b".\n":
        data = data[:-2]
    if data.startswith(b"..") or b"\n.." in data:
        data = _DOT_STUFFED.sub(b".", data)
    return data


def _decode_base64(raw: bytes) -> tuple[bytes, str | None]:
    """Strict base64 → (bytes, problem). With a problem, only the valid prefix is decoded."""
    compact = raw.translate(None, _B64_WHITESPACE)
    bad = _B64_OUTSIDE_ALPHABET.search(compact)
    end = bad.start() if bad is not None else len(compact)
    pad = compact.find(b"=", 0, end)
    stop = end if pad < 0 else pad
    rest = stop % 4
    problem: str | None = None
    if bad is not None:
        problem = f"byte 0x{compact[end]:02x} at offset {end} is outside the base64 alphabet"
    elif pad >= 0:
        if rest < 2 or compact[pad:] != b"=" * (4 - rest):
            problem = "invalid base64 padding"
    elif rest == 1:
        problem = "dangling base64 character"
    elif rest:
        problem = "missing base64 padding"
    if problem is None:
        return base64.b64decode(compact, validate=True), None
    whole = stop - rest
    decoded = base64.b64decode(compact[:whole], validate=True)
    if rest >= 2:  # a final 2- or 3-character quantum still carries whole bytes
        decoded += base64.b64decode(compact[whole:stop] + b"=" * (4 - rest), validate=True)
    return decoded, problem


def _decode_quoted_printable(raw: bytes) -> tuple[bytes, int, int | None]:
    """→ (bytes, malformed escape count, first malformed offset). Malformed `=` stay literal."""
    first: int | None = None
    count = 0
    if b"=" in raw:
        for match in _QP_MALFORMED.finditer(raw):
            if first is None:
                first = match.start()
            count += 1
    return quopri.decodestring(raw), count, first


def _header(message: Message, name: str, issues: Issues, max_bytes: int) -> str | None:
    """First `name` header, RFC 2047 words decoded, unfolded; None when absent."""
    value = message.get(name)
    field = name.lower()
    if value is None:
        return None
    if isinstance(value, str):  # compat32 hands out raw 8-bit headers as Header objects
        value = _FOLD.sub("", value)
        if len(value) > MAX_HEADER_CHARS:
            value = value[:MAX_HEADER_CHARS]
            issues.add(
                "decoded_truncated",
                f"{name} header cut at {MAX_HEADER_CHARS} characters before decoding",
                field=field,
            )
    try:
        chunks = decode_header(value)
    except HeaderParseError as error:
        issues.add("invalid_base64", f"{name} header: {error}", field=field)
        return _FOLD.sub("", str(value)).strip()
    pieces: list[str] = []
    for chunk, charset in chunks:
        if isinstance(chunk, str):
            pieces.append(chunk)
        elif charset is None:  # text between encoded words; ASCII because value was str
            pieces.append(chunk.decode("latin-1"))
        else:
            decoded = decode_text(chunk, charset, max_bytes=max_bytes)
            if decoded.status is DecodeStatus.PARTIAL:
                issues.add(
                    "invalid_charset_bytes",
                    f"{name} header has bytes that are not valid {decoded.charset}",
                    field=field,
                    invalid_byte_count=decoded.invalid_byte_count,
                )
            if decoded.truncated:
                issues.add(
                    "decoded_truncated", f"{name} header cut at {max_bytes} bytes", field=field
                )
            pieces.append(decoded.text or "")
    return _FOLD.sub("", "".join(pieces)).strip()


def _transfer_decode(
    index: int, encoding: str | None, raw: bytes, issues: Issues
) -> tuple[bytes | None, DecodeStatus]:
    if encoding is None or encoding in _UNCHANGED_ENCODINGS:
        return raw, DecodeStatus.UNCHANGED
    if encoding == "base64":
        body, problem = _decode_base64(raw)
        if problem is None:
            return body, DecodeStatus.DECODED
        issues.add("invalid_base64", problem, part=index, decoded_bytes=len(body))
        return body, DecodeStatus.PARTIAL
    if encoding == "quoted-printable":
        body, malformed, first = _decode_quoted_printable(raw)
        if not malformed:
            return body, DecodeStatus.DECODED
        issues.add(
            "invalid_quoted_printable",
            f"{malformed} malformed quoted-printable escape(s) kept literally",
            part=index,
            count=malformed,
            first_offset=first,
        )
        return body, DecodeStatus.PARTIAL
    issues.add(
        "unsupported_encoding",
        f"Content-Transfer-Encoding {encoding!r} is not supported",
        part=index,
        encoding=encoding,
    )
    return None, DecodeStatus.FAILED


def _raw_body(part: Message) -> bytes:
    # BytesParser stores a leaf body as ASCII text with 8-bit bytes surrogate-escaped.
    # get_payload() re-decodes such bodies with errors="replace" and get_payload(decode=True)
    # applies its own lenient transfer decoding, so the stored value is read directly.
    payload = part._payload
    if isinstance(payload, str):
        return payload.encode("ascii", "surrogateescape")
    return payload if isinstance(payload, bytes) else b""


def _param(part: Message, getter: str, index: int, issues: Issues) -> str | None:
    try:
        value = getattr(part, getter)()
    except ValueError as error:  # RFC 2231 charset name with NUL (str(bytes, name))
        issues.add("invalid_charset_bytes", f"part {index} {getter}: {error}", part=index)
        return None
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:  # RFC 2231 value decoded to lone surrogates
            issues.add(
                "invalid_charset_bytes", f"part {index} {getter}: lone surrogate", part=index
            )
            return None
    return value


def _part(index: int, part: Message, issues: Issues, max_bytes: int) -> MimePart:
    content_type = part.get_content_type()
    declared_charset = _param(part, "get_content_charset", index, issues)
    header = part.get("Content-Transfer-Encoding")
    encoding = str(header).strip().lower() if header is not None else None
    raw = _raw_body(part)
    body, status = _transfer_decode(index, encoding, raw, issues)
    result = MimePart(
        index=index,
        content_type=content_type,
        charset=declared_charset,
        transfer_encoding=encoding,
        filename=_param(part, "get_filename", index, issues),
        status=status,
        truncated=False,
    )
    if body is None:
        return result
    result.size = len(body)
    result.sha256 = sha256_hex(body)
    if content_type.startswith("text/"):
        text = decode_text(body, declared_charset, max_bytes=max_bytes)
        result.text = text.text
        result.charset = text.charset
        result.truncated = text.truncated
        result.status = worst_status((status, text.status))
        if text.status is DecodeStatus.PARTIAL:
            issues.add(
                "invalid_charset_bytes",
                f"part {index} has bytes that are not valid {text.charset}",
                part=index,
                invalid_byte_count=text.invalid_byte_count,
                first_invalid_offset=text.first_invalid_offset,
            )
        if text.truncated:
            issues.add(
                "decoded_truncated", f"part {index} text cut at {max_bytes} bytes", part=index
            )
    return result


def decode_message(data: bytes, issues: Issues, *, max_bytes: int = 1_048_576) -> DecodedMime:
    """Decode an RFC 5322/MIME message carried in SMTP DATA; problems go to `issues`."""
    message = _PARSER.parsebytes(unstuff(data))
    headers = MimeHeaders(
        subject=_header(message, "Subject", issues, max_bytes),
        from_=_header(message, "From", issues, max_bytes),
        to=_header(message, "To", issues, max_bytes),
        cc=_header(message, "Cc", issues, max_bytes),
        date=_header(message, "Date", issues, max_bytes),
        message_id=_header(message, "Message-ID", issues, max_bytes),
    )
    parts = [
        _part(index, part, issues, max_bytes)
        for index, part in enumerate(p for p in message.walk() if not p.is_multipart())
    ]
    return DecodedMime(
        headers=headers, parts=parts, status=worst_status(part.status for part in parts)
    )
