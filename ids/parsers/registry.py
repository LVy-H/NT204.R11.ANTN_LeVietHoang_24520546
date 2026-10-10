from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from ..model import DnsMessage, HttpMessage, SmtpSession
from . import dns, http, smtp


@dataclass(frozen=True, slots=True)
class AppProtocol:
    name: str
    ports: frozenset[int]
    score: Callable[[bytes, bool], tuple[float, str | None]]
    parse: Callable[..., HttpMessage | DnsMessage | SmtpSession]


PROTOCOLS: tuple[AppProtocol, ...] = tuple(
    AppProtocol(module.NAME, module.PORTS, module.score, module.parse)
    for module in (http, dns, smtp)
)

STANDARD_PORTS: dict[int, str] = {
    port: protocol.name for protocol in PROTOCOLS for port in sorted(protocol.ports)
}

_BY_NAME = {protocol.name: protocol for protocol in PROTOCOLS}


def by_name(name: str) -> AppProtocol | None:
    return _BY_NAME.get(name)
