# Shared interface contract for plans 1a–5

Spec: `docs/specs/2026-10-10-decoder-preprocessor-flow-tracker.md`.

Every plan in `docs/plans/2026-10-10-*.md` implements against the names, types and signatures
in this file. If a plan needs something not listed here, it defines it inside its own package
and does not change anything listed here.

## 0. Plan map, file ownership, order

| Plan | File | Owns (creates or rewrites) | Depends on |
|---|---|---|---|
| 1a | `2026-10-10-1a-foundation-model.md` | rename `pcparser`→`ids`, `ids/issues.py`, `ids/model/*`, `ids/codec.py`, `ids/payload.py` | — |
| 1b | `2026-10-10-1b-foundation-parsers.md` | `ids/parsers/{link,network,transport,http,dns,smtp,detector,registry,checksum}.py` + their unit tests | 1a |
| 1c | `2026-10-10-1c-foundation-pipeline.md` | `ids/parsers/__init__.py` (`PacketParser`), `ids/capture/*` (pcap, live, events), `ids/pipeline.py`, `ids/sink.py`, `ids/stats.py`, `ids/cli.py`, `main.py`, their tests, `TEST/` move to `TEST/capture-parser/` + `TEST/run_cases.sh` | 1a, 1b |
| 2 | `2026-10-10-2-decoder.md` | `ids/decoder/*`, decoder wiring in `ids/cli.py` | 1a–1c |
| 3 | `2026-10-10-3-preprocessor.md` | `ids/preprocess/*`, preprocessor wiring in `ids/cli.py` | 1a–1c (2 for decode-status reasons) |
| 4 | `2026-10-10-4-flow-tracker.md` | `ids/flow/*`, `Tick` emission in `ids/capture/live.py`, flow wiring + `--flows-output` in `ids/cli.py` | 1a–1c, 3 |
| 5 | `2026-10-10-5-cases-docs.md` | `TEST/flow-tracker/*`, `tests/test_cases.py`, regenerate `TEST/capture-parser/*`, `docs/schema.md`, READMEs, AI disclosure | all |

Execution order: 1a → 1b → 1c → 2 → 3 → 4 → 5. Stage order inside the runner is always
`[DecoderStage, PreprocessorStage, FlowTrackerStage]`; each plan appends its stage at that
position in `build_stages()` (§9).

**Green rule.** Every commit keeps `uv run pytest -q` green, with one declared exception:
during plan 1b the legacy dict pipeline (`ids/pipeline.py`, `ids/event.py`, `ids/errors.py`,
`ids/logger.py`, `ids/stats.py`, `ids/cli.py`, and `tests/test_pipeline.py`,
`tests/test_cli.py`) is left untouched and may fail, because the parsers it calls change
type. Plan 1b runs only the parser test files it owns. Plan 1c starts by replacing the legacy
layer and names the exact commit after which the full suite is green again; every later commit
keeps it green. Legacy helpers stay in place until the
plan that removes their last caller: `ids/payload.py:describe` and `ids/errors.py` are deleted
in plan 1c.

## 1. Conventions

- Python `>=3.10` (`requires-python`). No 3.11+ APIs (`tomllib`, `binascii` `strict_mode`,
  `datetime.UTC`, `typing.Self`). Every module starts with `from __future__ import annotations`.
- No new runtime dependencies. Scapy stays (live capture + fixture generation only).
- Models are `@dataclass(slots=True)`. Defaults rule: scalars `None`, lists
  `field(default_factory=list)`, dicts `field(default_factory=dict)`, nested dataclasses
  `None`. Exceptions: union-tag fields default to their tag value; flow counters default `0`.
- Tests: `uv run pytest -q`; lint: `uv run ruff check . && uv run ruff format --check .`.
- Commit message style (existing history): `feat: …`, `fix: …`, `refactor: …`, `test: …`,
  `docs: …`, lower case, imperative, one task per commit. Test-case commits:
  `test: add T07 tcp handshake results`, `test: regenerate capture-parser case 04 http get`.

## 2. `ids/issues.py`

```python
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


def jsonable(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).hex()
    if isinstance(value, dict):
        return {str(k): jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [jsonable(v) for v in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return repr(value)


@dataclass(slots=True)
class Issue:
    stage: str | None = None
    code: str | None = None
    message: str | None = None
    context: dict[str, Any] = field(default_factory=dict)


class ParseError(Exception):
    """Fatal problem inside one parser/decoder call. Carries no stage."""

    def __init__(self, code: str, message: str, **context: Any) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.context = context


class Issues:
    """Collector bound to one stage; `scoped()` shares the same record list."""

    __slots__ = ("records", "stage")

    def __init__(self, stage: str, records: list[Issue] | None = None) -> None:
        self.stage = stage
        self.records: list[Issue] = records if records is not None else []

    def add(self, code: str, message: str, **context: Any) -> None:
        self.records.append(Issue(self.stage, code, message, jsonable(context)))

    def scoped(self, stage: str) -> Issues:
        return Issues(stage, self.records)

    def capture(self, error: BaseException) -> None:
        if isinstance(error, ParseError):
            self.records.append(Issue(self.stage, error.code, error.message, jsonable(error.context)))
        else:
            self.records.append(
                Issue(
                    self.stage,
                    "internal_error",
                    str(error) or type(error).__name__,
                    {"exception": type(error).__name__},
                )
            )

    def __bool__(self) -> bool:
        return bool(self.records)

    def __len__(self) -> int:
        return len(self.records)
```

### Issue codes

| Code | Raised/added by |
|---|---|
| `truncated_packet` | capture, link, network, transport, application parsers |
| `malformed_header` | link, network, transport, capture file header |
| `unsupported_protocol` | link (linktype), network (IPv6/other version), transport (other IP proto, non-first fragment) |
| `decode_error` | application parsers |
| `truncated_body`, `incomplete_message`, `invalid_content_length`, `malformed_header_line` | HTTP parser |
| `incomplete_reply` | SMTP parser |
| `invalid_type`, `invalid_json`, `unsupported_schema` | codec / events source (stage `load`) |
| `invalid_escape`, `invalid_charset_bytes`, `invalid_base64`, `invalid_quoted_printable`, `unsupported_encoding`, `decoded_truncated` | decoder (stage `decoder`) |
| `internal_error` | runner / any stage on unexpected exception |

Stages: `capture`, `link`, `network`, `transport`, `detect`, `application`, `load`, `decoder`,
`preprocess`, `flow`, `pipeline`.

Refinement of spec §6.4: the codec never reports *missing* fields; absent keys load as
defaults. The Preprocessor reports missing required fields (`missing_field:<name>`).

## 3. `ids/model/` (exact code, created in plan 1a)

`ids/model/__init__.py` re-exports every public name below.

### 3.1 `ids/model/packet.py`

```python
from __future__ import annotations

from dataclasses import dataclass, field
from typing import ClassVar


@dataclass(frozen=True, slots=True)
class RawPacket:
    packet_id: int
    timestamp: float
    data: bytes
    linktype: int
    source: str
    origin: str
    original_length: int | None = None
    declared_capture_length: int | None = None

    @property
    def captured_length(self) -> int:
        return len(self.data)

    @property
    def truncated(self) -> bool:
        return self.declared_capture_length is not None and self.declared_capture_length > len(
            self.data
        )


@dataclass(frozen=True, slots=True)
class Tick:
    now: float


@dataclass(slots=True)
class CaptureInfo:
    source: str | None = None
    origin: str | None = None
    linktype: int | None = None
    linktype_name: str | None = None
    captured_length: int | None = None
    original_length: int | None = None
    declared_capture_length: int | None = None
    truncated_by_capture: bool | None = None


@dataclass(slots=True)
class VlanTag:
    tpid: str | None = None
    pcp: int | None = None
    dei: bool | None = None
    vid: int | None = None


@dataclass(slots=True)
class LlcHeader:
    dsap: str | None = None
    ssap: str | None = None
    control: int | None = None


@dataclass(slots=True)
class SnapHeader:
    oui: str | None = None
    protocol: int | None = None


@dataclass(slots=True)
class LinkInfo:
    protocol: str | None = None
    src_mac: str | None = None
    dst_mac: str | None = None
    ethertype: int | None = None
    ethertype_name: str | None = None
    vlan: list[VlanTag] = field(default_factory=list)
    length_field: int | None = None
    llc: LlcHeader | None = None
    snap: SnapHeader | None = None
    address_family: int | None = None
    packet_type: int | None = None
    address_type: int | None = None
    address: str | None = None
    interface_index: int | None = None


@dataclass(slots=True)
class IpOption:
    type: int | None = None
    name: str | None = None
    length: int | None = None
    data: str | None = None  # hex
    malformed: bool | None = None
    declared_length: int | None = None
    available: int | None = None


@dataclass(slots=True)
class Ipv4Flags:
    reserved: bool | None = None
    df: bool | None = None
    mf: bool | None = None


@dataclass(slots=True)
class Ipv4Info:
    protocol: str | None = None  # "IPv4" when produced by the parser
    version: int | None = None
    header_length: int | None = None
    dscp: int | None = None
    ecn: int | None = None
    tos: int | None = None
    total_length: int | None = None
    identification: int | None = None
    flags: Ipv4Flags | None = None
    fragment_offset: int | None = None
    fragmented: bool | None = None
    ttl: int | None = None
    protocol_number: int | None = None
    protocol_name: str | None = None
    header_checksum: str | None = None
    header_checksum_valid: bool | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    options: list[IpOption] = field(default_factory=list)
    captured_truncated: bool | None = None
    declared_payload_length: int | None = None
    captured_payload_length: int | None = None


@dataclass(slots=True)
class TcpFlags:
    fin: bool | None = None
    syn: bool | None = None
    rst: bool | None = None
    psh: bool | None = None
    ack: bool | None = None
    urg: bool | None = None
    ece: bool | None = None
    cwr: bool | None = None
    ns: bool | None = None


@dataclass(slots=True)
class TcpOption:
    type: int | None = None
    name: str | None = None
    length: int | None = None
    malformed: bool | None = None
    declared_length: int | None = None
    available: int | None = None
    mss: int | None = None
    shift: int | None = None
    tsval: int | None = None
    tsecr: int | None = None
    blocks: list[list[int]] = field(default_factory=list)
    data: str | None = None  # hex


@dataclass(slots=True)
class TcpInfo:
    TAG: ClassVar[tuple[str, str]] = ("protocol", "TCP")
    protocol: str | None = "TCP"
    src_port: int | None = None
    dst_port: int | None = None
    seq: int | None = None
    ack: int | None = None
    header_length: int | None = None
    reserved: int | None = None
    flags: TcpFlags | None = None
    flags_list: list[str] = field(default_factory=list)
    flags_string: str | None = None
    window: int | None = None
    checksum: str | None = None
    checksum_valid: bool | None = None
    urgent_pointer: int | None = None
    options: list[TcpOption] = field(default_factory=list)
    payload_length: int | None = None


@dataclass(slots=True)
class UdpInfo:
    TAG: ClassVar[tuple[str, str]] = ("protocol", "UDP")
    protocol: str | None = "UDP"
    src_port: int | None = None
    dst_port: int | None = None
    length: int | None = None
    checksum: str | None = None
    checksum_valid: bool | None = None
    declared_payload_length: int | None = None
    payload_length: int | None = None
    captured_truncated: bool | None = None


@dataclass(slots=True)
class Payload:
    length: int | None = None  # full captured L7 length
    sha256: str | None = None  # of the full captured L7 bytes
    data: bytes | None = None  # first `max_payload_bytes` bytes
    data_truncated: bool | None = None
    preview: str | None = None
    preview_truncated: bool | None = None
    preview_encoding: str | None = None  # "utf-8" | "latin-1" | "binary"
    binary: bool | None = None
    preview_hex: str | None = None
```

### 3.2 `ids/model/app.py`

```python
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
```

### 3.3 `ids/model/decoded.py`

```python
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import Enum
from typing import ClassVar


class DecodeStatus(str, Enum):
    NOT_APPLICABLE = "not_applicable"
    UNCHANGED = "unchanged"
    DECODED = "decoded"
    PARTIAL = "partial"
    FAILED = "failed"


_SEVERITY = {
    DecodeStatus.NOT_APPLICABLE: 0,
    DecodeStatus.UNCHANGED: 1,
    DecodeStatus.DECODED: 2,
    DecodeStatus.PARTIAL: 3,
    DecodeStatus.FAILED: 4,
}


def worst_status(statuses: Iterable[DecodeStatus | None]) -> DecodeStatus:
    present = [s for s in statuses if s is not None]
    if not present:
        return DecodeStatus.NOT_APPLICABLE
    return max(present, key=_SEVERITY.__getitem__)


@dataclass(slots=True)
class DecodedText:
    text: str | None = None
    charset: str | None = None  # "ascii" | "utf-8" | declared charset name
    status: DecodeStatus | None = None
    invalid_byte_count: int | None = None
    first_invalid_offset: int | None = None
    truncated: bool | None = None
    entity_count: int | None = None  # set only by HTML entity decoding


@dataclass(slots=True)
class DecodedUri:
    text: str | None = None  # whole target, percent-decoded once
    path: str | None = None
    query: str | None = None
    params: list[list[str]] = field(default_factory=list)  # [[name, value], ...]
    status: DecodeStatus | None = None
    double_encoded: bool | None = None


@dataclass(slots=True)
class DecodedForm:
    params: list[list[str]] = field(default_factory=list)
    status: DecodeStatus | None = None


@dataclass(slots=True)
class DecodedHttp:
    TAG: ClassVar[tuple[str, str]] = ("kind", "http")
    kind: str | None = "http"
    uri: DecodedUri | None = None
    form: DecodedForm | None = None
    body: DecodedText | None = None
    status: DecodeStatus | None = None  # worst of the parts present


@dataclass(slots=True)
class MimeHeaders:
    subject: str | None = None
    from_: str | None = field(default=None, metadata={"json": "from"})
    to: str | None = None
    cc: str | None = None
    date: str | None = None
    message_id: str | None = None


@dataclass(slots=True)
class MimePart:
    index: int | None = None
    content_type: str | None = None
    charset: str | None = None
    transfer_encoding: str | None = None
    filename: str | None = None
    size: int | None = None  # decoded byte size
    sha256: str | None = None  # of decoded bytes
    text: str | None = None  # text/* parts only
    status: DecodeStatus | None = None
    truncated: bool | None = None


@dataclass(slots=True)
class DecodedMime:
    TAG: ClassVar[tuple[str, str]] = ("kind", "mime")
    kind: str | None = "mime"
    headers: MimeHeaders | None = None
    parts: list[MimePart] = field(default_factory=list)
    status: DecodeStatus | None = None
```

### 3.4 `ids/model/normalized.py`

```python
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
```

### 3.5 `ids/model/flow.py`

```python
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import ClassVar


class TcpState(str, Enum):
    NEW = "NEW"
    HANDSHAKE = "HANDSHAKE"
    ESTABLISHED = "ESTABLISHED"
    CLOSING = "CLOSING"
    CLOSED = "CLOSED"
    RESET = "RESET"


class Direction(str, Enum):
    FORWARD = "forward"
    BACKWARD = "backward"


class EndReason(str, Enum):
    CLOSED = "closed"
    RESET = "reset"
    IDLE_TIMEOUT = "idle_timeout"
    EVICTED = "evicted"
    END_OF_INPUT = "end_of_input"


@dataclass(slots=True)
class FlowRef:
    flow_id: str | None = None
    direction: Direction | None = None
    state: TcpState | None = None  # None for UDP
    flow_packet_index: int | None = None  # 1-based


@dataclass(slots=True)
class Endpoint:
    ip: str | None = None
    port: int | None = None


@dataclass(slots=True)
class DirectionStats:
    packet_count: int = 0
    byte_count: int = 0
    payload_byte_count: int = 0


@dataclass(slots=True)
class TcpFlowStats:
    state: TcpState | None = None
    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    handshake_complete: bool = False
    midstream: bool = False


@dataclass(slots=True)
class FlowRecord:
    RECORD_TYPE: ClassVar[str] = "flow"
    flow_id: str | None = None
    protocol: str | None = None  # "TCP" | "UDP"
    application_protocol: str | None = None
    endpoint_a: Endpoint | None = None
    endpoint_b: Endpoint | None = None
    start_time: float | None = None
    last_seen: float | None = None
    duration: float | None = None
    packet_count: int = 0
    byte_count: int = 0
    payload_byte_count: int = 0
    forward: DirectionStats = field(default_factory=DirectionStats)
    backward: DirectionStats = field(default_factory=DirectionStats)
    tcp: TcpFlowStats | None = None
    end_reason: EndReason | None = None
    first_packet_id: int | None = None
    last_packet_id: int | None = None
```

### 3.6 `ids/model/event.py`

```python
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import ClassVar

from ..issues import Issue
from .app import ApplicationInfo
from .decoded import DecodedHttp, DecodedMime
from .flow import FlowRecord, FlowRef
from .normalized import Normalized
from .packet import CaptureInfo, Ipv4Info, LinkInfo, Payload, TcpInfo, UdpInfo

UNKNOWN = "UNKNOWN"


class PreprocessStatus(str, Enum):
    VALID = "valid"
    PARTIAL = "partial"
    INVALID = "invalid"


class ProcessingAction(str, Enum):
    FORWARD = "forward"
    MARK = "mark"
    DROP = "drop"


@dataclass(slots=True)
class PacketEvent:
    RECORD_TYPE: ClassVar[str] = "packet"
    packet_id: int | None = None
    timestamp: float | None = None
    capture: CaptureInfo | None = None
    link: LinkInfo | None = None
    network: Ipv4Info | None = None
    transport: TcpInfo | UdpInfo | None = None
    application: ApplicationInfo | None = None
    payload: Payload | None = None
    decoded: DecodedHttp | DecodedMime | None = None
    normalized: Normalized | None = None
    preprocess_status: PreprocessStatus | None = None
    processing_action: ProcessingAction | None = None
    reason: list[str] = field(default_factory=list)
    flow: FlowRef | None = None
    issues: list[Issue] = field(default_factory=list)

    @property
    def application_protocol(self) -> str:
        if self.application is None or not self.application.protocol:
            return UNKNOWN
        return self.application.protocol

    @property
    def protocol(self) -> str | None:
        return self.transport.protocol if self.transport is not None else None

    @property
    def src_ip(self) -> str | None:
        return self.network.src_ip if self.network is not None else None

    @property
    def dst_ip(self) -> str | None:
        return self.network.dst_ip if self.network is not None else None

    @property
    def src_port(self) -> int | None:
        return self.transport.src_port if self.transport is not None else None

    @property
    def dst_port(self) -> int | None:
        return self.transport.dst_port if self.transport is not None else None

    @property
    def is_tcp(self) -> bool:
        return isinstance(self.transport, TcpInfo)

    @property
    def event_type(self) -> str:
        if self.network is None:
            return "unparsed"
        if self.transport is None:
            return "network_only"
        protocol = self.application_protocol
        message = self.application.message if self.application is not None else None
        kind = getattr(message, "kind", None)
        if kind:
            return f"{protocol.lower()}_{kind}"
        if protocol != UNKNOWN:
            return f"{protocol.lower()}_unparsed"
        if self.payload is not None and self.payload.length:
            return "unknown_payload"
        return f"{(self.transport.protocol or 'transport').lower()}_segment"


@dataclass(slots=True)
class MessageEvent:
    RECORD_TYPE: ClassVar[str] = "message"
    message_id: str | None = None  # f"{flow_id}-{n}", n 1-based per flow
    flow_id: str | None = None
    protocol: str | None = None  # "SMTP"
    packet_ids: list[int] = field(default_factory=list)
    start_time: float | None = None
    end_time: float | None = None
    data: bytes | None = None
    complete: bool | None = None
    truncated: bool | None = None
    gap: bool | None = None
    decoded: DecodedMime | None = None
    preprocess_status: PreprocessStatus | None = None
    processing_action: ProcessingAction | None = None
    reason: list[str] = field(default_factory=list)
    issues: list[Issue] = field(default_factory=list)


Record = PacketEvent | MessageEvent | FlowRecord
```

## 4. `ids/payload.py`

```python
def sha256_hex(data: bytes) -> str: ...
def looks_binary(data: bytes) -> bool: ...   # NUL present or printable ratio < 0.75
def make_payload(data: bytes, *, max_bytes: int = 65535, preview_limit: int = 256) -> Payload:
    """length/sha256 over all `data`; `data` field = data[:max_bytes];
    data_truncated = len(data) > max_bytes; preview of data[:preview_limit] rendered as utf-8,
    else latin-1, or '.'-masked when binary; preview_hex = data[:64].hex() when binary.
    looks_binary is computed once on the full data and reused for the preview."""
```

## 5. `ids/codec.py`

```python
SCHEMA_VERSION = 2

def to_jsonable(obj: object) -> object
    # dataclass → dict in field order using metadata["json"] aliases;
    # bytes field `x` → key "x_b64" (base64 str) or None; Enum → .value; list/dict recurse;
    # JSON-native pass through; anything else → TypeError.

def encode(record: PacketEvent | MessageEvent | FlowRecord) -> dict[str, object]
def encode_line(record) -> str
    # json.dumps(encode(record), ensure_ascii=False, separators=(",", ":"), allow_nan=False)

def from_jsonable(cls: type[T], obj: object, issues: Issues, path: str) -> T | None
    # tolerant typed load driven by typing.get_type_hints(cls) (cached per class):
    # missing key → field default; wrong type → default + issues.add("invalid_type", ...,
    # field=path); int accepted for float; bool never accepted for int; `<x>_b64` → bytes
    # (bad base64 → invalid_type); Enum by value (unknown → invalid_type); unions of
    # dataclasses resolved by each member's TAG (key, value); `object` fields pass JSON-native
    # values through; unknown keys ignored.

def decode_packet(obj: object) -> tuple[PacketEvent, list[Issue]]
    # never raises; Issues stage "load". Non-dict → stub PacketEvent + invalid_type.
    # schema_version present and != 2 → unsupported_schema (still loads).
    # record_type present and != "packet" → unsupported_schema (still loads).
    # Fallback: when "network" is absent but top-level src_ip/dst_ip exist, build
    # Ipv4Info(protocol="IPv4", src_ip, dst_ip, protocol_name from "protocol").
    # When "transport" is absent but top-level "protocol"/"transport_protocol" is TCP/UDP
    # (any case), build TcpInfo/UdpInfo(src_port, dst_port) from top-level ports.
    # Derived top-level keys (event_type, timestamp_iso, application_protocol) are ignored.
```

### 5.1 Packet record key order

`schema_version, record_type, packet_id, timestamp, timestamp_iso, event_type, src_ip,
dst_ip, src_port, dst_port, protocol, application_protocol, preprocess_status,
processing_action, reason, flow, capture, link, network, transport, application, payload,
decoded, normalized, issues`.

`timestamp_iso` = UTC ISO-8601 of `timestamp` or `null`. Message records:
`schema_version, record_type` then fields in declaration order. Flow records: same rule.
Every declared field is always present (`null` / `[]` / `{}`).

## 6. Parsers (plan 1b; `PacketParser` in plan 1c)

```python
# ids/parsers/link.py
@dataclass(frozen=True, slots=True)
class LinkResult:
    info: LinkInfo
    payload: bytes
    network_protocol: str | None  # "IPv4" | "IPv6" | "ARP" | ... | None
def parse_link(data: bytes, linktype: int) -> LinkResult            # raises ParseError

# ids/parsers/network.py
IPPROTO_TCP = 6
IPPROTO_UDP = 17
@dataclass(frozen=True, slots=True)
class NetworkResult:
    info: Ipv4Info
    payload: bytes
def parse_ipv4(data: bytes, issues: Issues) -> NetworkResult        # raises ParseError;
    # adds truncated_packet issue when total_length > captured

# ids/parsers/transport.py
@dataclass(frozen=True, slots=True)
class TransportResult:
    info: TcpInfo | UdpInfo
    payload: bytes
def parse_transport(protocol_number: int, data: bytes, *, src_ip: str, dst_ip: str,
                    declared_length: int | None = None, fragment_offset: int = 0) -> TransportResult

# ids/parsers/http.py, dns.py, smtp.py — each module exposes:
NAME: str                                   # "HTTP" | "DNS" | "SMTP"
PORTS: frozenset[int]
def score(payload: bytes, tcp: bool) -> tuple[float, str | None]
def parse(payload: bytes, *, tcp: bool, issues: Issues) -> HttpMessage | DnsMessage | SmtpSession
# smtp.parse never raises for non-empty input; no command/reply line → kind "data".

# ids/parsers/registry.py
@dataclass(frozen=True, slots=True)
class AppProtocol:
    name: str
    ports: frozenset[int]
    score: Callable[[bytes, bool], tuple[float, str | None]]
    parse: Callable[..., HttpMessage | DnsMessage | SmtpSession]
PROTOCOLS: tuple[AppProtocol, ...]          # (HTTP, DNS, SMTP)
STANDARD_PORTS: dict[int, str]              # derived from PROTOCOLS
def by_name(name: str) -> AppProtocol | None

# ids/parsers/detector.py
def detect(payload: bytes, *, src_port: int | None, dst_port: int | None, tcp: bool) -> Detection

# ids/parsers/__init__.py
@dataclass(slots=True)
class ParserConfig:
    max_payload_bytes: int = 65535
    preview_limit: int = 256
class PacketParser:
    def __init__(self, config: ParserConfig | None = None) -> None: ...
    def parse(self, raw: RawPacket) -> PacketEvent: ...   # never raises
```

`PacketParser.parse` sets `PacketEvent.payload` to the L7 payload (or deepest bytes
reached), `application = ApplicationInfo(protocol, detection, message)` whenever a
transport was parsed (`protocol` = detection protocol, `UNKNOWN` when nothing matched), and
`application = None` otherwise.

## 7. Sources (plan 1c; `Tick` emission plan 4)

```python
# ids/capture/base.py
class CaptureSource(Protocol):
    source: str          # "pcap" | "live" | "events"
    origin: str
    warnings: list[str]
    def items(self) -> Iterator[RawPacket | PacketEvent | Tick]: ...
    def describe(self) -> dict[str, object]: ...
    def close(self) -> None: ...

class PcapSource:   def __init__(self, path: str | Path, *, count: int | None = None)
class LiveSource:   def __init__(self, interface: str, *, bpf_filter: str | None = None,
                                 count: int | None = None, promiscuous: bool = True,
                                 capture_idle_timeout: float | None = None,
                                 poll_interval: float = 1.0, tick: bool = False)
class EventsSource: def __init__(self, path: str | Path, *, count: int | None = None)
    # "-" = stdin; one PacketEvent per non-blank line; load issues appended to event.issues;
    # non-JSON line → PacketEvent(packet_id=line_number) + Issue("load","invalid_json");
    # record_type "flow"/"message" lines → skipped, counted in warnings.
def list_interfaces() -> list[dict[str, object]]
```

## 8. Runner, stages, sink, stats (plan 1c)

```python
# ids/pipeline.py
Emit = Callable[[PacketEvent | MessageEvent | FlowRecord], None]

class Stage(Protocol):
    name: str
    def process(self, record: PacketEvent | MessageEvent, emit: Emit) -> None: ...
    def tick(self, now: float, emit: Emit) -> None: ...
    def flush(self, emit: Emit) -> None: ...

UNKNOWN_POLICIES = ("emit", "skip")

class Runner:
    def __init__(self, parser: PacketParser, stages: Sequence[Stage], sink: Sink,
                 stats: Stats, *, unknown_policy: str = "emit") -> None: ...
    def run(self, source: Iterable[RawPacket | PacketEvent | Tick]) -> None: ...
```

Runner semantics:
- `RawPacket` → `parser.parse`; `PacketEvent` → used as is; `Tick` → every stage's
  `tick(now, emit)`.
- A record goes through `stages` in order. Before each stage and after the last, if
  `record.processing_action is ProcessingAction.DROP` → `stats.dropped(record)` and stop.
- Each `stage.process` runs in `try`; any exception → `record.issues.append(Issue(stage.name,
  "internal_error", …))` and continue with the next stage.
- `emit(r)` from a stage: `FlowRecord` → written immediately; `MessageEvent` → processed
  through all stages from index 0 (stages ignore record types they do not handle), then written.
- After the stages, a `PacketEvent` with `application_protocol == "UNKNOWN"` and
  `unknown_policy == "skip"` → `stats.skipped(record)`; otherwise `sink.write` +
  `stats.observe`.
- End of input: `stage.flush(emit)` for every stage in order.

```python
# ids/sink.py
class JsonlSink:
    def __init__(self, path: str | None = "-", *, flows_path: str | None = None,
                 flush_every: int = 100) -> None: ...
    def write(self, record: PacketEvent | MessageEvent | FlowRecord) -> None: ...
    def close(self) -> None: ...
    # context manager; stdout never closed; flow records go to flows_path when set.

# ids/stats.py
class Stats:
    def observe(self, record) -> None    # written records
    def dropped(self, record) -> None
    def skipped(self, record) -> None
    def to_dict(self) -> dict[str, object]
    extra: dict[str, object]             # stages may set e.g. extra["active_flows"]
    # counters: packets_seen, records_written by record_type, dropped, skipped,
    # event_types, protocols, application_protocols, detection_methods,
    # issue codes "stage/code", preprocess_status, processing_action,
    # flow end_reason, messages complete/incomplete, first/last timestamp.
```

## 9. CLI composition (`ids/cli.py`)

```python
def build_parser() -> argparse.ArgumentParser
def build_stages(args: argparse.Namespace) -> list[Stage]
    # plan 1c: return []
    # plan 2:  [DecoderStage(DecoderConfig(max_decoded_bytes=args.max_decoded_bytes))]
    # plan 3:  + PreprocessorStage(PreprocessConfig(invalid_policy=..., unsupported_policy=...))
    # plan 4:  + FlowTrackerStage(FlowConfig(...))
def main(argv: Sequence[str] | None = None) -> int
```

Flag ownership: plan 1c — `-i/--interface`, `-r/--pcap`, `-e/--events`,
`-L/--list-interfaces`, `-o/--output`, `-c/--count`, `--filter`, `--capture-idle-timeout`,
`--max-payload-bytes`, `--preview-limit`, `--unknown-policy`, `--stats`, `-q/--quiet`,
`--version`. Plan 2 — `--max-decoded-bytes`. Plan 3 — `--invalid-policy`,
`--unsupported-policy`. Plan 4 — `--flows-output`, `--tcp-idle-timeout`,
`--udp-idle-timeout`, `--tcp-closed-timeout`, `--max-flows`, `--max-message-bytes`.
Numeric flags use argparse `type=` helpers `non_negative_int`, `positive_int`,
`non_negative_float` defined in `ids/cli.py` by plan 1c (negative → exit 2).
Exit codes: 0 ok, 1 runtime error, 2 usage, 130 interrupted.

## 10. Stage APIs (plans 2–4)

```python
# ids/decoder/stage.py
@dataclass(slots=True)
class DecoderConfig:
    max_decoded_bytes: int = 1_048_576
class DecoderStage:          # name = "decoder"
    def __init__(self, config: DecoderConfig | None = None) -> None: ...

# ids/decoder/text.py
def decode_text(data: bytes, declared_charset: str | None = None, *,
                max_bytes: int = 1_048_576) -> DecodedText
# ids/decoder/url.py
def decode_uri(uri: str) -> DecodedUri
def decode_form(data: bytes) -> DecodedForm
# ids/decoder/html.py
def decode_entities(text: str) -> tuple[str, int]
# ids/decoder/mime.py
def decode_message(data: bytes, issues: Issues, *, max_bytes: int = 1_048_576) -> DecodedMime

# ids/preprocess/stage.py
@dataclass(slots=True)
class PreprocessConfig:
    invalid_policy: str = "mark"        # "mark" | "drop"
    unsupported_policy: str = "mark"    # "mark" | "drop"
    clock: Callable[[], float] = time.time
class PreprocessorStage:     # name = "preprocess"
    def __init__(self, config: PreprocessConfig | None = None) -> None: ...

# ids/flow/stage.py
@dataclass(slots=True)
class FlowConfig:
    tcp_idle_timeout: float = 300.0
    udp_idle_timeout: float = 60.0
    tcp_closed_timeout: float = 5.0
    max_flows: int = 100_000
    max_message_bytes: int = 1_048_576
class FlowTrackerStage:      # name = "flow"
    def __init__(self, config: FlowConfig | None = None, stats: Stats | None = None) -> None: ...
    @property
    def active_count(self) -> int: ...
```
