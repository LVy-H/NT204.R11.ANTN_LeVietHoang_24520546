"""Canonical forms for the values detection rules compare.

Raw fields are never touched; every function returns the canonical value plus the
normalization notes (reason strings) it produced.
"""

from __future__ import annotations

import math
import re
from datetime import datetime, timezone
from ipaddress import IPv4Address
from urllib.parse import urlsplit

from ..codec import iso_timestamp
from ..model import (
    DecodedHttp,
    DnsMessage,
    HttpMessage,
    Normalized,
    NormalizedDns,
    NormalizedHttp,
    NormalizedSmtp,
    PacketEvent,
    SmtpSession,
    TcpInfo,
)

CANONICAL_PROTOCOLS: dict[str, str] = {
    name.lower(): name for name in ("IPv4", "TCP", "UDP", "HTTP", "DNS", "SMTP", "UNKNOWN")
}
MS_THRESHOLD = 1e11
MAX_DOMAIN_LENGTH = 253
MAX_PORT = 65535

IP_NORMALIZED = "ip_normalized"
TIMESTAMP_SCALED = "timestamp_scaled"
INVALID_DOMAIN = "invalid_domain"
INVALID_HOST = "invalid_host"
BACKSLASH_IN_PATH = "backslash_in_path"

# LDH label; one leading underscore is allowed for DNS service/attribute labels
# (RFC 8552: `_sip._tcp`, `_dmarc`, `_domainkey`). Underscores anywhere else are invalid.
_LABEL = re.compile(r"_?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_DIGITS = re.compile(r"[0-9]{1,3}")
_SLASHES = re.compile(r"/{2,}")


def canonical_protocol(name: object) -> str | None:
    """Known names map case-insensitively to the canonical set; others are upper-cased."""
    if not isinstance(name, str):
        return None
    key = name.strip()
    if not key:
        return None
    return CANONICAL_PROTOCOLS.get(key.lower(), key.upper())


def normalize_ip(value: object) -> tuple[str | None, list[str]]:
    if not isinstance(value, str):
        return None, []
    text = value.strip()
    try:
        return str(IPv4Address(text)), []
    except ValueError:
        pass
    parts = text.split(".")
    if len(parts) != 4 or not all(_DIGITS.fullmatch(part) for part in parts):
        return None, []
    octets = [int(part) for part in parts]
    if any(octet > 255 for octet in octets):
        return None, []
    return ".".join(map(str, octets)), [IP_NORMALIZED]


def normalize_domain(value: object) -> tuple[str | None, list[str]]:
    """Lowercase, strip one trailing dot, IDNA-encode; invalid names keep a best-effort value."""
    if not isinstance(value, str):
        return None, []
    text = value.strip().lower()
    if text == ".":
        return ".", []
    if text.endswith("."):
        text = text[:-1]
    if not text:
        return None, []
    try:
        name = text.encode("idna").decode("ascii")
    except UnicodeError:
        return text, [INVALID_DOMAIN]
    if len(name) > MAX_DOMAIN_LENGTH or not all(
        _LABEL.fullmatch(label) for label in name.split(".")
    ):
        return name, [INVALID_DOMAIN]
    return name, []


def split_host(value: object) -> tuple[str | None, int | None, list[str]]:
    """Split an HTTP `Host` / authority into (host, port). IPv6 literals are not supported."""
    if not isinstance(value, str):
        return None, None, []
    text = value.strip()
    if not text:
        return None, None, []
    if text.startswith("[") or text.count(":") > 1:
        return None, None, [INVALID_HOST]
    host_text, colon, port_text = text.partition(":")
    port: int | None = None
    notes: list[str] = []
    if colon and port_text:
        if (
            len(port_text) <= 5
            and port_text.isascii()
            and port_text.isdigit()
            and int(port_text) <= MAX_PORT
        ):
            port = int(port_text)
        else:
            notes.append(INVALID_HOST)
    host, domain_notes = normalize_domain(host_text)
    if host is None:
        notes.append(INVALID_HOST)
    return host, port, notes + domain_notes


def remove_dot_segments(path: str) -> str:
    """RFC 3986 §5.2.4, step for step; the output buffer holds one entry per segment."""
    output: list[str] = []
    i, end = 0, len(path)
    while i < end:
        if path.startswith("../", i):
            i += 3
        elif path.startswith(("./", "/./"), i):
            i += 2
        elif i + 2 == end and path.startswith("/.", i):
            output.append("/")
            i = end
        elif path.startswith("/../", i):
            i += 3
            if output:
                output.pop()
        elif i + 3 == end and path.startswith("/..", i):
            if output:
                output.pop()
            output.append("/")
            i = end
        elif path[i:] in (".", ".."):
            i = end
        else:
            stop = path.find("/", i + 1 if path.startswith("/", i) else i)
            if stop == -1:
                stop = end
            output.append(path[i:stop])
            i = stop
    return "".join(output)


def normalize_path(path: str) -> tuple[str, list[str]]:
    """Collapse repeated `/`, then remove dot segments; case is kept, backslashes only flagged."""
    notes = [BACKSLASH_IN_PATH] if "\\" in path else []
    return remove_dot_segments(_SLASHES.sub("/", path)), notes


def normalize_timestamp(value: object) -> tuple[float | None, str | None, list[str]]:
    """Epoch seconds (ms when > 1e11) or ISO-8601 (trailing `Z` allowed, naive = UTC)."""
    if isinstance(value, bool):
        return None, None, []
    if isinstance(value, (int, float)):
        seconds = float(value)
        if not math.isfinite(seconds):
            return None, None, []
        notes: list[str] = []
        if seconds > MS_THRESHOLD:
            seconds /= 1000
            notes.append(TIMESTAMP_SCALED)
        return seconds, iso_timestamp(seconds), notes
    if isinstance(value, str):
        text = value.strip()
        if text[-1:] in ("Z", "z"):
            text = text[:-1] + "+00:00"
        try:
            moment = datetime.fromisoformat(text)
        except ValueError:
            return None, None, []
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        seconds = moment.timestamp()
        return seconds, iso_timestamp(seconds), []
    return None, None, []


def normalize_address(value: str | None) -> tuple[str | None, list[str]]:
    """Mail address: local part kept as is, domain normalized."""
    if value is None:
        return None, []
    text = value.strip()
    local, at, domain_text = text.rpartition("@")
    if not at:
        return text, []
    domain, notes = normalize_domain(domain_text)
    return f"{local}@{domain if domain is not None else ''}", notes


def _http(message: HttpMessage, decoded: DecodedHttp | None, notes: list[str]) -> NormalizedHttp:
    headers: dict[str, list[str]] = {}
    for header in message.headers:
        if header.name is None or header.value is None:
            continue
        name = header.name.strip().lower()
        if name:
            headers.setdefault(name, []).append(header.value)
    result = NormalizedHttp(method=message.method, headers=headers)
    authority: str | None = None
    raw_path: str | None = None
    uri = message.uri
    if uri is not None:
        if "://" in uri:
            try:
                parts = urlsplit(uri)
            except ValueError:  # urllib rejects bad brackets / NFKC-unsafe netlocs
                notes.append(INVALID_HOST)
                return result
            result.scheme = parts.scheme.lower() or None
            authority = parts.netloc.rpartition("@")[2] or None
            raw_path = parts.path
        elif uri.startswith("/"):
            raw_path = uri.split("?", 1)[0].split("#", 1)[0]
    if authority is None:
        authority = message.header("host")
    host, port, host_notes = split_host(authority)
    result.host, result.port = host, port
    notes.extend(host_notes)
    if isinstance(decoded, DecodedHttp) and decoded.uri is not None:
        path: str | None = decoded.uri.path
    else:
        path = raw_path
    if path is not None:
        result.path, path_notes = normalize_path(path)
        notes.extend(path_notes)
    return result


def _dns(message: DnsMessage, notes: list[str]) -> NormalizedDns:
    names: list[str] = []
    for entry in (*message.questions, *message.answers):
        name, name_notes = normalize_domain(entry.name)
        notes.extend(name_notes)
        if name is not None and name not in names:
            names.append(name)
    return NormalizedDns(names=names)


def _smtp(session: SmtpSession, notes: list[str]) -> NormalizedSmtp:
    result = NormalizedSmtp()
    for command in session.commands:
        if command.verb is not None and command.verb.upper() in ("HELO", "EHLO"):
            domain = (command.domain or "").strip()
            if domain.startswith("[") and domain.endswith("]"):
                result.helo = domain  # address literal, RFC 5321 §4.1.3
            else:
                result.helo, helo_notes = normalize_domain(domain)
                notes.extend(helo_notes)
            break
    result.mail_from, address_notes = normalize_address(session.mail_from)
    notes.extend(address_notes)
    for recipient in session.rcpt_to:
        address, address_notes = normalize_address(recipient)
        notes.extend(address_notes)
        if address is not None:
            result.rcpt_to.append(address)
    return result


def is_int(value: object) -> bool:
    """True for a real int; bool is excluded although it subclasses int."""
    return isinstance(value, int) and not isinstance(value, bool)


def _port(value: object) -> int | None:
    return value if is_int(value) else None


def normalize(event: PacketEvent) -> tuple[Normalized, list[str]]:
    """Build `event.normalized`; notes are de-duplicated in first-seen order."""
    notes: list[str] = []
    normalized = Normalized()
    normalized.timestamp, normalized.timestamp_iso, stamp_notes = normalize_timestamp(
        event.timestamp
    )
    notes.extend(stamp_notes)
    network = event.network
    if network is not None:
        normalized.network_protocol = canonical_protocol(network.protocol) or "IPv4"
        normalized.src_ip, src_notes = normalize_ip(network.src_ip)
        normalized.dst_ip, dst_notes = normalize_ip(network.dst_ip)
        notes.extend(src_notes + dst_notes)
    transport = event.transport
    if transport is not None:
        # the codec picks TcpInfo/UdpInfo by a case-insensitive tag, so the type is canonical
        normalized.protocol = "TCP" if isinstance(transport, TcpInfo) else "UDP"
        normalized.src_port = _port(transport.src_port)
        normalized.dst_port = _port(transport.dst_port)
    normalized.application_protocol = canonical_protocol(event.application_protocol)
    message = event.application.message if event.application is not None else None
    if isinstance(message, HttpMessage):
        decoded = event.decoded if isinstance(event.decoded, DecodedHttp) else None
        normalized.http = _http(message, decoded, notes)
    elif isinstance(message, DnsMessage):
        normalized.dns = _dns(message, notes)
    elif isinstance(message, SmtpSession):
        normalized.smtp = _smtp(message, notes)
    return normalized, list(dict.fromkeys(notes))
