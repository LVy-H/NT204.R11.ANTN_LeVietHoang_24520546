from __future__ import annotations

from dataclasses import dataclass, field
from typing import ClassVar

from ..issues import Issue


@dataclass(slots=True)
class Detection:
    protocol: str | None = None
    method: str | None = None  # "port+payload" | "payload" | "port" | "none"
    confidence: float | None = None
    port_matched: bool | None = None
    port_hint: str | None = None
    evidence: str | None = None
    scores: dict[str, float] = field(default_factory=dict)


@dataclass(slots=True)
class HttpHeader:
    name: str | None = None  # original case
    value: str | None = None


@dataclass(slots=True)
class HttpBody:
    offset: int | None = None  # into the application payload bytes
    length: int | None = None  # bytes of body present in the capture
    declared_length: int | None = None  # Content-Length
    transfer_encoding: str | None = None  # "identity" | "chunked"
    truncated: bool | None = None


@dataclass(slots=True)
class HttpMessage:
    TAG: ClassVar[tuple[str, str]] = ("protocol", "HTTP")
    protocol: str | None = "HTTP"
    kind: str | None = None  # "request" | "response"
    version: str | None = None
    start_line: str | None = None
    method: str | None = None
    uri: str | None = None  # raw request target, latin-1 decoded, never percent-decoded
    status_code: int | None = None
    reason: str | None = None
    headers: list[HttpHeader] = field(default_factory=list)
    body: HttpBody | None = None
    complete: bool | None = None  # header terminator found

    def header_values(self, name: str) -> list[str]:
        wanted = name.lower()
        return [
            h.value
            for h in self.headers
            if h.name is not None and h.value is not None and h.name.lower() == wanted
        ]

    def header(self, name: str) -> str | None:
        values = self.header_values(name)
        return values[-1] if values else None


@dataclass(slots=True)
class DnsFlags:
    qr: bool | None = None
    opcode: int | None = None
    aa: bool | None = None
    tc: bool | None = None
    rd: bool | None = None
    ra: bool | None = None
    z: bool | None = None
    ad: bool | None = None
    cd: bool | None = None
    rcode: int | None = None


@dataclass(slots=True)
class DnsCounts:
    questions: int | None = None
    answers: int | None = None
    authorities: int | None = None
    additionals: int | None = None


@dataclass(slots=True)
class DnsQuestion:
    name: str | None = None
    type: int | None = None
    type_name: str | None = None
    class_: int | None = field(default=None, metadata={"json": "class"})
    class_name: str | None = None


@dataclass(slots=True)
class DnsRecord:
    name: str | None = None
    type: int | None = None
    type_name: str | None = None
    class_: int | None = field(default=None, metadata={"json": "class"})
    class_name: str | None = None
    ttl: int | None = None
    rdlength: int | None = None
    value: object = None  # str | list[str] | dict[str, int | str], JSON-native
    rdata: str | None = None  # hex, when value is None
    rdata_error: Issue | None = None
    udp_payload_size: int | None = None  # OPT records


@dataclass(slots=True)
class DnsMessage:
    TAG: ClassVar[tuple[str, str]] = ("protocol", "DNS")
    protocol: str | None = "DNS"
    kind: str | None = None  # "query" | "response"
    id: int | None = None
    flags: DnsFlags | None = None
    opcode: int | None = None
    opcode_name: str | None = None
    rcode: int | None = None
    rcode_name: str | None = None
    counts: DnsCounts | None = None
    questions: list[DnsQuestion] = field(default_factory=list)
    answers: list[DnsRecord] = field(default_factory=list)
    authorities: list[DnsRecord] = field(default_factory=list)
    additionals: list[DnsRecord] = field(default_factory=list)
    tcp: bool | None = None


@dataclass(slots=True)
class SmtpCommand:
    verb: str | None = None
    arguments: str | None = None
    address: str | None = None
    parameters: list[str] = field(default_factory=list)
    path: str | None = None
    domain: str | None = None
    mechanism: str | None = None
    credentials_present: bool | None = None


@dataclass(slots=True)
class SmtpReply:
    code: int | None = None
    text: str | None = None
    lines: list[str] = field(default_factory=list)
    continuation: bool | None = None


@dataclass(slots=True)
class SmtpSession:
    TAG: ClassVar[tuple[str, str]] = ("protocol", "SMTP")
    protocol: str | None = "SMTP"
    kind: str | None = None  # "command" | "response" | "mixed" | "data"
    commands: list[SmtpCommand] = field(default_factory=list)
    replies: list[SmtpReply] = field(default_factory=list)
    unparsed_lines: list[str] = field(default_factory=list)
    command: str | None = None  # first verb
    status_code: int | None = None  # first reply code
    last_status_code: int | None = None
    mail_from: str | None = None
    rcpt_to: list[str] = field(default_factory=list)


AppMessage = HttpMessage | DnsMessage | SmtpSession


@dataclass(slots=True)
class ApplicationInfo:
    protocol: str | None = None  # "HTTP" | "DNS" | "SMTP" | "UNKNOWN"
    detection: Detection | None = None
    message: HttpMessage | DnsMessage | SmtpSession | None = None
