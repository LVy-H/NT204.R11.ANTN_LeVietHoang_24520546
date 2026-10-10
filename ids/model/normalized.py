from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class NormalizedHttp:
    method: str | None = None
    scheme: str | None = None
    host: str | None = None
    port: int | None = None
    path: str | None = None
    headers: dict[str, list[str]] = field(default_factory=dict)


@dataclass(slots=True)
class NormalizedDns:
    names: list[str] = field(default_factory=list)


@dataclass(slots=True)
class NormalizedSmtp:
    helo: str | None = None
    mail_from: str | None = None
    rcpt_to: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Normalized:
    timestamp: float | None = None
    timestamp_iso: str | None = None
    network_protocol: str | None = None
    protocol: str | None = None
    application_protocol: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    http: NormalizedHttp | None = None
    dns: NormalizedDns | None = None
    smtp: NormalizedSmtp | None = None
