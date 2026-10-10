"""Validation rules of spec §8.1: one verdict and an ordered reason list per packet event."""

from __future__ import annotations

from ..issues import Issue
from ..model import (
    DecodedHttp,
    DecodedMime,
    DecodeStatus,
    Normalized,
    PacketEvent,
    PreprocessStatus,
)
from .normalize import MAX_PORT, canonical_protocol, is_int

FUTURE_TOLERANCE = 86400.0
LOAD_STAGE = "load"
IP_FIELDS = frozenset(("src_ip", "dst_ip"))
PORT_FIELDS = frozenset(("src_port", "dst_port"))
TRANSPORT_NAMES = frozenset(("TCP", "UDP"))

# Load-issue `field` paths (codec, plan 1a) that point at a required field, by field name.
REQUIRED_FIELD_PATHS: dict[str, str] = {
    "packet_id": "packet_id",
    "timestamp": "timestamp",
    "network.src_ip": "src_ip",
    "src_ip": "src_ip",
    "network.dst_ip": "dst_ip",
    "dst_ip": "dst_ip",
    "transport.src_port": "src_port",
    "src_port": "src_port",
    "transport.dst_port": "dst_port",
    "dst_port": "dst_port",
}


class _Verdict:
    __slots__ = ("invalid", "reasons", "unsupported")

    def __init__(self) -> None:
        self.reasons: list[str] = []
        self.invalid = False
        self.unsupported = False

    def add(self, reason: str, *, invalid: bool = False) -> None:
        self.invalid = self.invalid or invalid
        if reason not in self.reasons:
            self.reasons.append(reason)

    @property
    def status(self) -> PreprocessStatus:
        if self.invalid:
            return PreprocessStatus.INVALID
        return PreprocessStatus.PARTIAL if self.reasons else PreprocessStatus.VALID


def issue_reason(issue: Issue) -> str:
    return f"{issue.stage or 'unknown'}/{issue.code or 'unknown'}"


def _load_failed(issues: list[Issue]) -> set[str]:
    """Required field names whose JSON value the codec rejected."""
    failed: set[str] = set()
    for issue in issues:
        if issue.stage == LOAD_STAGE:
            path = str(issue.context.get("field"))
            name = REQUIRED_FIELD_PATHS.get(path)
            if name is not None:
                failed.add(name)
            elif path == "network":
                failed |= IP_FIELDS
            elif path in ("protocol", "transport_protocol") or (
                # a union tag mismatch (got == dict) is an unsupported protocol, not a bad type
                path == "transport" and issue.context.get("got") != "dict"
            ):
                failed |= PORT_FIELDS
    return failed


def _check_packet_id(event: PacketEvent, failed: set[str], verdict: _Verdict) -> None:
    value = event.packet_id
    if value is None and "packet_id" not in failed:
        verdict.add("missing_field:packet_id", invalid=True)
    elif not is_int(value) or value < 1:
        verdict.add("invalid_field:packet_id", invalid=True)


def _check_timestamp(
    event: PacketEvent, normalized: Normalized, now: float, failed: set[str], verdict: _Verdict
) -> None:
    if event.timestamp is None and "timestamp" not in failed:
        verdict.add("missing_field:timestamp", invalid=True)
        return
    seconds = normalized.timestamp
    if seconds is None or seconds <= 0 or seconds > now + FUTURE_TOLERANCE:
        verdict.add("invalid_timestamp", invalid=True)


def _check_ip(
    name: str, raw: object, canonical: str | None, failed: set[str], verdict: _Verdict
) -> None:
    if raw is None and name not in failed:
        verdict.add(f"missing_field:{name}", invalid=True)
    elif canonical is None:
        verdict.add(f"invalid_ip:{name}", invalid=True)


def _check_port(name: str, value: object, failed: set[str], verdict: _Verdict) -> None:
    if value is None and name not in failed:
        verdict.add(f"missing_field:{name}", invalid=True)
    elif not is_int(value) or not 0 <= value <= MAX_PORT:
        verdict.add(f"invalid_port:{name}", invalid=True)
    elif value == 0:
        verdict.add(f"reserved_port:{name}")


def _check_layers(
    event: PacketEvent, normalized: Normalized, failed: set[str], verdict: _Verdict
) -> None:
    network = event.network
    transport = event.transport
    # IPv4 announced by the link layer but no IPv4 header parsed: broken, not unsupported
    broken_ipv4 = network is None and event.link is not None and event.link.ethertype_name == "IPv4"
    if network is not None or transport is not None or failed & IP_FIELDS or broken_ipv4:
        _check_ip("src_ip", event.src_ip, normalized.src_ip, failed, verdict)
        _check_ip("dst_ip", event.dst_ip, normalized.dst_ip, failed, verdict)
    if transport is not None:
        _check_port("src_port", transport.src_port, failed, verdict)
        _check_port("dst_port", transport.dst_port, failed, verdict)
        return
    if broken_ipv4:
        return
    if failed & PORT_FIELDS or (
        network is not None
        and not network.fragment_offset
        and canonical_protocol(network.protocol_name) in TRANSPORT_NAMES
    ):
        # TCP/UDP announced but no transport header parsed: broken, not unsupported
        _check_port("src_port", None, failed, verdict)
        _check_port("dst_port", None, failed, verdict)
        return
    verdict.unsupported = True
    if network is None:
        name = event.link.ethertype_name if event.link is not None else None
    elif network.fragment_offset:
        name = "fragment"
    else:
        name = network.protocol_name
    verdict.add(f"unsupported_protocol:{name or 'unknown'}")


def _check_decoded(event: PacketEvent, verdict: _Verdict) -> None:
    decoded = event.decoded
    if isinstance(decoded, DecodedHttp):
        parts = (("uri", decoded.uri), ("form", decoded.form), ("body", decoded.body))
        for part, value in parts:
            if value is not None:
                _add_decode_reason(verdict, part, value.status)
    elif isinstance(decoded, DecodedMime):
        _add_decode_reason(verdict, "mime", decoded.status)


def _add_decode_reason(verdict: _Verdict, part: str, status: DecodeStatus | None) -> None:
    reason = decode_reason(part, status)
    if reason is not None:
        verdict.add(reason)


def decode_reason(part: str, status: DecodeStatus | None) -> str | None:
    """`decode_partial:<part>` / `decode_failed:<part>`, or None for a clean decode."""
    if status is DecodeStatus.PARTIAL:
        return f"decode_partial:{part}"
    if status is DecodeStatus.FAILED:
        return f"decode_failed:{part}"
    return None


def validate(
    event: PacketEvent, normalized: Normalized, *, now: float
) -> tuple[PreprocessStatus, list[str], bool]:
    """Return (status, reasons, unsupported); `now` bounds future timestamps."""
    verdict = _Verdict()
    failed = _load_failed(event.issues)
    _check_packet_id(event, failed, verdict)
    _check_timestamp(event, normalized, now, failed, verdict)
    _check_layers(event, normalized, failed, verdict)
    for issue in event.issues:
        verdict.add(issue_reason(issue))
    _check_decoded(event, verdict)
    return verdict.status, verdict.reasons, verdict.unsupported
