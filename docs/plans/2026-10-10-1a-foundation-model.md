# Plan 1a: Foundation — rename, issues, typed model, payload, codec

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rename the package `pcparser` → `ids` and add the typed schema v2 foundation (`Issue` model, `ids/model/` dataclasses, `make_payload`, and the `ids/codec.py` encoder/tolerant decoder) that plans 1b–5 build on.

**Architecture:** A pure `git mv` rename comes first so every later commit targets `ids/...`. The model is a set of `@dataclass(slots=True)` classes copied verbatim from the shared contract; nothing outside `ids/codec.py` knows the JSON layout. The codec derives field order, JSON aliases (`metadata["json"]`) and `*_b64` byte keys from `dataclasses.fields()` + `typing.get_type_hints()` (cached per class), so encode and decode cannot drift from the model. The legacy dict pipeline stays untouched and green; `ids/payload.py:describe` is kept for it until plan 1c.

**Tech Stack:** Python ≥3.10 stdlib only (`dataclasses`, `typing`, `enum`, `json`, `base64`, `datetime`, `functools.cache`), pytest, ruff, uv.

**Spec:** `docs/specs/2026-10-10-decoder-preprocessor-flow-tracker.md` (design) and `docs/plans/2026-10-10-interfaces.md` (shared contract: names, types, signatures — used verbatim).

## Global Constraints

- `requires-python = ">=3.10"`; no 3.11+ APIs (`tomllib`, `binascii` `strict_mode`, `datetime.UTC`, `typing.Self`); `datetime.fromisoformat` is the 3.10 variant (no `Z` suffix support — handled by hand).
- Every module starts with `from __future__ import annotations`.
- No new runtime dependencies; scapy stays (live capture + fixture generation only).
- Models are `@dataclass(slots=True)`. Defaults: scalars `None`, lists `field(default_factory=list)`, dicts `field(default_factory=dict)`, nested dataclasses `None`; union-tag fields default to their tag value; flow counters default `0`.
- Contract §2 (`ids/issues.py`) and §3 (`ids/model/*`) are copied exactly; the only permitted difference is ruff formatting (one over-long line in §2 is wrapped by `ruff format`, tokens unchanged).
- Lint: line-length 100, rules `E,F,W,I,UP,B,C4,SIM,RUF`, ignore `SIM108,SIM115,BLE001`. Commands in this plan lint explicit Python paths (`ruff format --check .` also formats Python blocks inside `docs/**/*.md` with ruff 0.16 and is not used here).
- Schema v2: every record has `schema_version: 2` and `record_type`; every declared field is always present (`null`/`[]`/`{}`); bytes are base64 under `<name>_b64`; non-JSON values raise `TypeError`; `json.dumps(..., allow_nan=False)`.
- Tolerant decode never raises; issues carry stage `load`; missing keys load as defaults with no issue.
- Green rule: `uv run pytest -q` is green after every commit of this plan. Legacy `ids/errors.py`, `ids/event.py`, `ids/pipeline.py`, `ids/payload.py:describe` stay (removed in plan 1c).
- pytest `addopts = "-q --strict-markers"`: with the extra `-q` the run prints only progress dots and `[100%]` (no `N passed` line). "PASS — N tests" below means N dots, no `F`/`E`, exit status 0.
- One task = one commit; lower-case conventional messages (`refactor: …`, `feat: …`).
- Repo docs (README.md, TEST/README.md) are Vietnamese; edits here are one-word path/name substitutions.

## Review Focus

1. **`NaN` / `Infinity` in a loaded event** (Python's `json.loads` accepts them): the field must load as `None` + `invalid_type`, because otherwise `encode_line(..., allow_nan=False)` raises later and kills the run. Test: Task 6 `test_non_finite_floats_are_rejected`, `test_object_fields_reject_non_finite_numbers`.
2. **Loaded event with an out-of-range timestamp** (`1e20`, `nan`): encoding must still succeed with `timestamp_iso: null` instead of raising `OverflowError`/`ValueError`. Test: Task 5 `test_iso_timestamp`, `test_out_of_range_timestamp_encodes_with_null_iso`.
3. **Hand-written JSONL with lower/mixed-case union tags** (`"transport": {"protocol": "tcp"}`, `"message": {"protocol": "dns"}`): the right member must still be chosen (raw text kept for the Preprocessor to normalise), not dropped as `invalid_type`. Test: Task 6 `test_union_member_is_chosen_by_tag_case_insensitively`.
4. **ISO-8601 string timestamps in loaded events** (spec §8.2; `…Z`, `+07:00`, naive): converted to epoch float at load, since the typed field cannot carry the string to the Preprocessor. Test: Task 6 `test_iso_timestamp_strings_are_converted_to_epoch_seconds`, `test_unparsable_timestamp_string_is_invalid`.
5. **UTF-8 payload whose preview cut falls inside a multi-byte character**: the preview stays `utf-8` with the partial character dropped instead of flipping the whole preview to latin-1 mojibake. Test: Task 4 `test_utf8_cut_inside_a_character_drops_the_partial_character`, `test_invalid_byte_before_the_cut_still_falls_back_to_latin1`.

---

## File structure

| Path | Task | Responsibility |
|---|---|---|
| `ids/` (was `pcparser/`) | 1 | package rename only; legacy modules unchanged apart from `cli.py` `prog` and `__init__.py` version |
| `main.py`, `pyproject.toml`, `uv.lock`, `requirements.txt`, `README.md`, `TEST/README.md`, `tests/test_*.py` | 1 | references to the new package name / console script |
| `ids/issues.py` | 2 | `jsonable`, `Issue`, `ParseError`, `Issues` (contract §2) |
| `tests/test_issues.py` | 2 | collector behaviour |
| `ids/model/packet.py` | 3 | `RawPacket`, `Tick`, capture/link/IPv4/TCP/UDP blocks, `Payload` (contract §3.1) |
| `ids/model/app.py` | 3 | detection + HTTP/DNS/SMTP messages, `ApplicationInfo` (§3.2) |
| `ids/model/decoded.py` | 3 | `DecodeStatus`, `worst_status`, decoded HTTP/MIME blocks (§3.3) |
| `ids/model/normalized.py` | 3 | `Normalized*` (§3.4) |
| `ids/model/flow.py` | 3 | flow enums, `FlowRef`, `FlowRecord` (§3.5) |
| `ids/model/event.py` | 3 | `PacketEvent`, `MessageEvent`, `Record`, status enums (§3.6) |
| `ids/model/__init__.py` | 3 | re-exports every public model name |
| `tests/test_model.py` | 3 | derived properties and helpers |
| `ids/payload.py` | 4 | `sha256_hex`, `looks_binary`, `make_payload` (§4) + legacy `describe` |
| `tests/test_payload.py` | 4 | payload summary rules |
| `ids/codec.py` | 5, 6 | `SCHEMA_VERSION`, `iso_timestamp`, `to_jsonable`, `encode`, `encode_line` (5); `from_jsonable`, `decode_packet` (6) |
| `tests/codec_samples.py` | 5 | richly populated sample records shared by the codec tests |
| `tests/test_codec.py` | 5 | encoder |
| `tests/test_codec_decode.py` | 6 | tolerant decoder + round trip |

Extra public name (inside plan 1a's own module, not altering the contract): `ids.codec.iso_timestamp(value: float | None) -> str | None`, used by the encoder for `timestamp_iso` and by plan 3 for `normalized.timestamp_iso` so both strings are identical.

### Task 1: Rename package `pcparser` → `ids`

Pure rename: no behaviour change except the console-script / argparse program name and the version string. Occurrence checklist (from `git grep -n pcparser`, excluding `docs/`):

| File | Occurrence | Action |
|---|---|---|
| `pcparser/` (21 tracked `.py` files) | package directory; internal imports are all relative | `git mv pcparser ids` |
| `pcparser/cli.py:22` | `prog="pcparser",` | → `prog="ids",` |
| `pcparser/__init__.py:1` | `__version__ = "0.1.0"` | → `"0.2.0"` |
| `main.py:1` | `from pcparser.cli import main` | → `from ids.cli import main` |
| `pyproject.toml:2,3,19,26,31` | name, version, script, hatch packages, filterwarnings | see Step 3 |
| `uv.lock:45-46` | `name = "pcparser"`, `version = "0.1.0"` | regenerated by `uv lock` |
| `requirements.txt:5` | `# via pcparser` | regenerated by `uv export` |
| `README.md:55` | console script `pcparser` | → `ids` |
| `README.md:78` | `pcparser/` in the repo tree | → `ids/` |
| `TEST/README.md:77` | "còn `pcparser` đọc và parse" | → `ids` |
| `tests/test_capture.py:5-7`, `test_cli.py:6`, `test_detector.py:12`, `test_dns.py:6-7`, `test_http.py:4-5`, `test_link.py:4-6,93`, `test_live.py:6-7`, `test_network.py:4-5`, `test_pipeline.py:7-9,235,253`, `test_smtp.py:11-12`, `test_transport.py:4-7` | imports and `monkeypatch.setattr("pcparser....")` targets | `pcparser` → `ids` |
| `tests/test_cli.py:97` | `"pcparser 0.1.0"` | → `"ids 0.2.0"` |
| `TEST/generate_fixtures.py:137`, `TEST/case-04-http-get/output.jsonl`, `TEST/case-13-mixed/output.jsonl` | `User-Agent: pcparser-test/1.0` inside fixture bytes | **keep** — fixture payload data, not a package reference |
| `TEST/run_cases.sh` | no occurrence | unchanged |

**Files:**
- Rename: `pcparser/` → `ids/`
- Modify: `ids/cli.py:22`, `ids/__init__.py:1`, `main.py:1`, `pyproject.toml:2-3,19,26,31`, `uv.lock`, `requirements.txt`, `README.md:55,78`, `TEST/README.md:77`
- Test: `tests/test_capture.py`, `tests/test_cli.py`, `tests/test_detector.py`, `tests/test_dns.py`, `tests/test_http.py`, `tests/test_link.py`, `tests/test_live.py`, `tests/test_network.py`, `tests/test_pipeline.py`, `tests/test_smtp.py`, `tests/test_transport.py`

**Interfaces:**
- Consumes: nothing.
- Produces: importable package `ids` (all legacy modules at `ids/...` with unchanged APIs: `ids.capture.base` keeps `RawPacket`, `DLT_*`, `linktype_name`; `ids.errors`, `ids.event`, `ids.pipeline`, `ids.payload.describe` unchanged); `ids.__version__ == "0.2.0"`; console script `ids = "ids.cli:main"`; `python main.py` still works.

- [ ] **Step 1: Point the tests at the new package**

```bash
sed -i 's/\bpcparser\b/ids/g' tests/test_*.py
```

Then in `tests/test_cli.py` change line 97 to:

```text
    assert capsys.readouterr().out.strip() == "ids 0.2.0"
```

- [ ] **Step 2: Run the suite to verify it fails**

Run: `uv run pytest -q`
Expected: collection errors, `ModuleNotFoundError: No module named 'ids'`.

- [ ] **Step 3: Rename the package and every reference**

```bash
git mv pcparser ids
test ! -e pcparser
sed -i 's/\bpcparser\b/ids/g' main.py
```

`ids/cli.py` line 22 becomes:

```text
        prog="ids",
```

`ids/__init__.py` becomes:

```python
__version__ = "0.2.0"

__all__ = ["__version__"]
```

`pyproject.toml`: lines 2-3 become

```toml
name = "ids"
version = "0.2.0"
```

line 19 (`[project.scripts]`) becomes

```toml
ids = "ids.cli:main"
```

line 26 (`[tool.hatch.build.targets.wheel]`) becomes

```toml
packages = ["ids"]
```

line 31 (`[tool.pytest.ini_options]`) becomes

```toml
filterwarnings = ["error::DeprecationWarning:ids.*"]
```

Regenerate the lock file, the environment and `requirements.txt`:

```bash
uv lock
uv sync
uv export --no-hashes --no-dev --output-file requirements.txt
```

`uv lock` prints `Added ids v0.2.0` / `Removed pcparser v0.1.0`. `requirements.txt` must then read exactly:

```text
# This file was autogenerated by uv via the following command:
#    uv export --no-hashes --no-dev --output-file requirements.txt
-e .
scapy==2.7.0
    # via ids
```

`README.md` line 55 becomes:

```markdown
gọi `python main.py ...` hoặc console script `ids`.
```

`README.md` line 78 becomes:

```text
ids/
```

`TEST/README.md` line 77 becomes:

```markdown
- Fixture sinh bằng Scapy, còn `ids` đọc và parse bằng code tự viết, nên output
```

- [ ] **Step 4: Verify the rename is complete and the suite is green**

Run: `git grep -n pcparser -- ':!docs' ':!TEST/generate_fixtures.py' ':!TEST/case-*'`
Expected: no output (exit status 1).

Run: `uv run pytest -q`
Expected: PASS — 179 tests, exit status 0.

Run: `uv run ids --version && uv run python main.py --version`
Expected: `ids 0.2.0` twice.

Run: `uv run ruff check ids tests main.py TEST && uv run ruff format --check ids tests main.py TEST`
Expected: `All checks passed!` and `36 files already formatted`.

- [ ] **Step 5: Commit**

```bash
git add ids main.py pyproject.toml uv.lock requirements.txt README.md TEST/README.md tests
git commit -m "refactor: rename package pcparser to ids"
```

### Task 2: Issue model and stage-scoped collector

**Files:**
- Create: `ids/issues.py`
- Test: `tests/test_issues.py`

**Interfaces:**
- Consumes: nothing.
- Produces (contract §2, exact):
  - `jsonable(value: Any) -> Any` — bytes-like → hex str, dict keys → str (recursive), list/tuple → list, JSON scalars pass, anything else → `repr`.
  - `@dataclass(slots=True) class Issue: stage: str | None = None; code: str | None = None; message: str | None = None; context: dict[str, Any] = field(default_factory=dict)`
  - `class ParseError(Exception): __init__(self, code: str, message: str, **context: Any)`; attributes `code`, `message`, `context`; `str(err) == message`.
  - `class Issues: __init__(self, stage: str, records: list[Issue] | None = None)`; `records: list[Issue]`; `add(code: str, message: str, **context: Any) -> None`; `scoped(stage: str) -> Issues` (shares `records`); `capture(error: BaseException) -> None` (`ParseError` → its code/message/context, other → `internal_error` with `{"exception": type name}`, message `str(error) or type name`); `__bool__`, `__len__`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_issues.py`:

```python
from __future__ import annotations

from ids.issues import Issue, Issues, ParseError, jsonable


class Opaque:
    def __repr__(self) -> str:
        return "<opaque>"


def test_jsonable_converts_bytes_tuples_keys_and_unknown_objects():
    value = {1: b"\x00\xff", "nested": (bytearray(b"ab"), memoryview(b"c")), "obj": Opaque()}
    assert jsonable(value) == {"1": "00ff", "nested": ["6162", "63"], "obj": "<opaque>"}


def test_jsonable_passes_json_scalars_through():
    assert jsonable([None, "s", 1, 2.5, True]) == [None, "s", 1, 2.5, True]


def test_add_stamps_the_collector_stage_and_makes_context_jsonable():
    issues = Issues("network")
    issues.add("truncated_packet", "short header", needed=20, data=b"\x45")
    assert issues.records == [
        Issue("network", "truncated_packet", "short header", {"needed": 20, "data": "45"})
    ]


def test_scoped_collectors_share_one_record_list_in_order():
    root = Issues("transport")
    app = root.scoped("application")
    root.add("a", "first")
    app.add("b", "second")
    assert app.records is root.records
    assert [(issue.stage, issue.code) for issue in root.records] == [
        ("transport", "a"),
        ("application", "b"),
    ]


def test_capture_parse_error_keeps_code_message_and_context():
    issues = Issues("link")
    error = ParseError("unsupported_protocol", "linktype 999", linktype=999, raw=b"\x01")
    issues.capture(error)
    assert str(error) == "linktype 999"
    assert issues.records == [
        Issue("link", "unsupported_protocol", "linktype 999", {"linktype": 999, "raw": "01"})
    ]


def test_capture_other_exception_becomes_internal_error():
    issues = Issues("decoder")
    issues.capture(ValueError("bad value"))
    issues.capture(KeyError())
    assert issues.records == [
        Issue("decoder", "internal_error", "bad value", {"exception": "ValueError"}),
        Issue("decoder", "internal_error", "KeyError", {"exception": "KeyError"}),
    ]


def test_truthiness_and_length_follow_the_records():
    issues = Issues("load")
    assert not issues
    assert len(issues) == 0
    issues.add("invalid_type", "x")
    assert issues
    assert len(issues) == 1


def test_issue_defaults_are_independent():
    first, second = Issue(), Issue()
    first.context["k"] = 1
    assert second.context == {}
    assert (second.stage, second.code, second.message) == (None, None, None)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_issues.py -q`
Expected: collection error `ModuleNotFoundError: No module named 'ids.issues'`.

- [ ] **Step 3: Write the implementation**

Create `ids/issues.py` (contract §2; the `capture` `ParseError` branch is wrapped by `ruff format` to fit 100 columns):

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
            self.records.append(
                Issue(self.stage, error.code, error.message, jsonable(error.context))
            )
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

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_issues.py -q`
Expected: PASS — 8 tests, exit status 0.

Run: `uv run pytest -q`
Expected: PASS — 187 tests, exit status 0.

Run: `uv run ruff check ids/issues.py tests/test_issues.py && uv run ruff format --check ids/issues.py tests/test_issues.py`
Expected: `All checks passed!`, `2 files already formatted`.

- [ ] **Step 5: Commit**

```bash
git add ids/issues.py tests/test_issues.py
git commit -m "feat: add issue model and stage-scoped collector"
```

### Task 3: Typed schema v2 model

**Files:**
- Create: `ids/model/__init__.py`, `ids/model/packet.py`, `ids/model/app.py`, `ids/model/decoded.py`, `ids/model/normalized.py`, `ids/model/flow.py`, `ids/model/event.py`
- Test: `tests/test_model.py`

**Interfaces:**
- Consumes: `ids.issues.Issue` (Task 2) — used by `DnsRecord.rdata_error`, `PacketEvent.issues`, `MessageEvent.issues`.
- Produces (contract §3, exact; all re-exported from `ids.model`):
  - `ids.model.packet`: `RawPacket` (frozen; `captured_length -> int`, `truncated -> bool`), `Tick(now: float)` (frozen), `CaptureInfo`, `VlanTag`, `LlcHeader`, `SnapHeader`, `LinkInfo`, `IpOption`, `Ipv4Flags`, `Ipv4Info`, `TcpFlags`, `TcpOption`, `TcpInfo` (`TAG = ("protocol", "TCP")`), `UdpInfo` (`TAG = ("protocol", "UDP")`), `Payload` (`data: bytes | None`).
  - `ids.model.app`: `Detection`, `HttpHeader`, `HttpBody`, `HttpMessage` (`TAG`, `header_values(name: str) -> list[str]`, `header(name: str) -> str | None`), `DnsFlags`, `DnsCounts`, `DnsQuestion`/`DnsRecord` (`class_` with `metadata={"json": "class"}`; `DnsRecord.value: object`), `DnsMessage` (`TAG`), `SmtpCommand`, `SmtpReply`, `SmtpSession` (`TAG`), `AppMessage = HttpMessage | DnsMessage | SmtpSession`, `ApplicationInfo(protocol, detection, message)`.
  - `ids.model.decoded`: `DecodeStatus(str, Enum)` (`not_applicable`, `unchanged`, `decoded`, `partial`, `failed`), `worst_status(statuses: Iterable[DecodeStatus | None]) -> DecodeStatus`, `DecodedText`, `DecodedUri`, `DecodedForm`, `DecodedHttp` (`TAG = ("kind", "http")`), `MimeHeaders` (`from_` → JSON `from`), `MimePart`, `DecodedMime` (`TAG = ("kind", "mime")`).
  - `ids.model.normalized`: `NormalizedHttp`, `NormalizedDns`, `NormalizedSmtp`, `Normalized`.
  - `ids.model.flow`: `TcpState`, `Direction`, `EndReason` (str Enums), `FlowRef`, `Endpoint`, `DirectionStats`, `TcpFlowStats`, `FlowRecord` (`RECORD_TYPE = "flow"`).
  - `ids.model.event`: `UNKNOWN = "UNKNOWN"`, `PreprocessStatus`, `ProcessingAction`, `PacketEvent` (`RECORD_TYPE = "packet"`; properties `application_protocol -> str`, `protocol`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `is_tcp -> bool`, `event_type -> str`), `MessageEvent` (`RECORD_TYPE = "message"`), `Record = PacketEvent | MessageEvent | FlowRecord`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_model.py`:

```python
from __future__ import annotations

import pytest

from ids.model import (
    UNKNOWN,
    ApplicationInfo,
    DecodedHttp,
    DecodedMime,
    DecodeStatus,
    DnsMessage,
    FlowRecord,
    HttpHeader,
    HttpMessage,
    Ipv4Info,
    MessageEvent,
    PacketEvent,
    Payload,
    RawPacket,
    SmtpSession,
    TcpInfo,
    UdpInfo,
    worst_status,
)

NETWORK = Ipv4Info(protocol="IPv4", src_ip="10.0.0.1", dst_ip="10.0.0.2")


def event(**fields) -> PacketEvent:
    return PacketEvent(packet_id=1, timestamp=1759000000.0, network=NETWORK, **fields)


@pytest.mark.parametrize(
    ("packet", "expected"),
    [
        (PacketEvent(packet_id=1), "unparsed"),
        (event(), "network_only"),
        (
            event(
                transport=TcpInfo(src_port=51234, dst_port=80),
                application=ApplicationInfo("HTTP", None, HttpMessage(kind="request")),
            ),
            "http_request",
        ),
        (
            event(
                transport=UdpInfo(src_port=53, dst_port=40000),
                application=ApplicationInfo("DNS", None, DnsMessage(kind="response")),
            ),
            "dns_response",
        ),
        (
            event(
                transport=TcpInfo(src_port=40000, dst_port=25),
                application=ApplicationInfo("SMTP", None, SmtpSession(kind="data")),
            ),
            "smtp_data",
        ),
        (
            event(transport=TcpInfo(), application=ApplicationInfo("HTTP", None, None)),
            "http_unparsed",
        ),
        (
            event(transport=TcpInfo(), application=ApplicationInfo("SMTP", None, SmtpSession())),
            "smtp_unparsed",
        ),
        (
            event(
                transport=TcpInfo(),
                application=ApplicationInfo(UNKNOWN, None, None),
                payload=Payload(length=12),
            ),
            "unknown_payload",
        ),
        (event(transport=TcpInfo(), payload=Payload(length=0)), "tcp_segment"),
        (event(transport=UdpInfo(), payload=None), "udp_segment"),
        (event(transport=TcpInfo(protocol=None)), "transport_segment"),
    ],
)
def test_event_type_covers_every_branch(packet, expected):
    assert packet.event_type == expected


def test_missing_network_is_unparsed_even_with_upper_layers():
    packet = PacketEvent(transport=TcpInfo(), application=ApplicationInfo("HTTP"))
    assert packet.event_type == "unparsed"


@pytest.mark.parametrize(
    "application",
    [None, ApplicationInfo(protocol=None), ApplicationInfo(protocol="")],
)
def test_application_protocol_falls_back_to_unknown(application):
    assert PacketEvent(application=application).application_protocol == UNKNOWN


def test_application_protocol_reports_the_detected_name():
    assert PacketEvent(application=ApplicationInfo("DNS")).application_protocol == "DNS"


def test_convenience_properties_read_the_nested_blocks():
    packet = event(transport=TcpInfo(src_port=51234, dst_port=80))
    assert (packet.src_ip, packet.dst_ip, packet.src_port, packet.dst_port) == (
        "10.0.0.1",
        "10.0.0.2",
        51234,
        80,
    )
    assert packet.protocol == "TCP"
    assert packet.is_tcp is True


def test_convenience_properties_are_none_without_blocks():
    packet = PacketEvent()
    assert (packet.src_ip, packet.dst_ip, packet.src_port, packet.dst_port) == (
        None,
        None,
        None,
        None,
    )
    assert packet.protocol is None
    assert packet.is_tcp is False


def test_udp_transport_is_not_tcp():
    packet = event(transport=UdpInfo(src_port=1, dst_port=2))
    assert packet.protocol == "UDP"
    assert packet.is_tcp is False


def test_union_tag_fields_default_to_their_tag():
    assert TcpInfo().protocol == "TCP"
    assert UdpInfo().protocol == "UDP"
    assert HttpMessage().protocol == "HTTP"
    assert DnsMessage().protocol == "DNS"
    assert SmtpSession().protocol == "SMTP"
    assert DecodedHttp().kind == "http"
    assert DecodedMime().kind == "mime"
    assert (PacketEvent.RECORD_TYPE, MessageEvent.RECORD_TYPE, FlowRecord.RECORD_TYPE) == (
        "packet",
        "message",
        "flow",
    )


def test_mutable_defaults_are_not_shared():
    first, second = PacketEvent(), PacketEvent()
    first.reason.append("x")
    first.issues.append(None)
    assert second.reason == []
    assert second.issues == []
    flow_a, flow_b = FlowRecord(), FlowRecord()
    flow_a.forward.packet_count += 1
    assert flow_b.forward.packet_count == 0
    assert flow_a.backward is not flow_a.forward


def http(*headers: tuple[str | None, str | None]) -> HttpMessage:
    return HttpMessage(headers=[HttpHeader(name, value) for name, value in headers])


def test_header_lookup_is_case_insensitive_and_last_value_wins():
    message = http(("Host", "a.example"), ("X-Tag", "1"), ("HOST", "b.example"))
    assert message.header("host") == "b.example"
    assert message.header("HoSt") == "b.example"
    assert message.header_values("host") == ["a.example", "b.example"]


def test_header_lookup_misses_return_none_and_empty_list():
    message = http(("Host", "a.example"))
    assert message.header("cookie") is None
    assert message.header_values("cookie") == []


def test_header_lookup_skips_entries_with_missing_name_or_value():
    message = http((None, "x"), ("Host", None), ("Host", "kept"))
    assert message.header_values("host") == ["kept"]
    assert message.header("host") == "kept"


def test_header_lookup_keeps_original_order_and_case_of_values():
    message = http(("Set-Cookie", "A=1"), ("set-cookie", "b=2"))
    assert message.header_values("SET-COOKIE") == ["A=1", "b=2"]


def test_worst_status_of_nothing_is_not_applicable():
    assert worst_status([]) is DecodeStatus.NOT_APPLICABLE
    assert worst_status([None, None]) is DecodeStatus.NOT_APPLICABLE


@pytest.mark.parametrize(
    ("statuses", "expected"),
    [
        ([DecodeStatus.NOT_APPLICABLE, DecodeStatus.UNCHANGED], DecodeStatus.UNCHANGED),
        ([DecodeStatus.DECODED, DecodeStatus.UNCHANGED], DecodeStatus.DECODED),
        ([DecodeStatus.DECODED, DecodeStatus.PARTIAL], DecodeStatus.PARTIAL),
        ([DecodeStatus.FAILED, DecodeStatus.PARTIAL], DecodeStatus.FAILED),
        ([None, DecodeStatus.UNCHANGED, None], DecodeStatus.UNCHANGED),
        (
            [DecodeStatus.PARTIAL, DecodeStatus.FAILED, DecodeStatus.DECODED],
            DecodeStatus.FAILED,
        ),
    ],
)
def test_worst_status_picks_the_most_severe(statuses, expected):
    assert worst_status(statuses) is expected


def test_worst_status_accepts_a_generator():
    parts = [DecodeStatus.DECODED, DecodeStatus.PARTIAL]
    assert worst_status(status for status in parts) is DecodeStatus.PARTIAL


def raw(data: bytes, declared: int | None) -> RawPacket:
    return RawPacket(1, 0.0, data, 1, "pcap", "x.pcap", 60, declared)


def test_raw_packet_captured_length_is_the_data_length():
    assert raw(b"\x00" * 42, 42).captured_length == 42


@pytest.mark.parametrize(
    ("declared", "truncated"),
    [(None, False), (41, False), (42, False), (43, True)],
)
def test_raw_packet_is_truncated_only_when_declared_exceeds_data(declared, truncated):
    assert raw(b"\x00" * 42, declared).truncated is truncated
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_model.py -q`
Expected: collection error `ModuleNotFoundError: No module named 'ids.model'`.

- [ ] **Step 3: Write the implementation**

Create `ids/model/packet.py` (contract §3.1):

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

Create `ids/model/app.py` (contract §3.2):

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

Create `ids/model/decoded.py` (contract §3.3):

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

Create `ids/model/normalized.py` (contract §3.4):

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

Create `ids/model/flow.py` (contract §3.5):

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

Create `ids/model/event.py` (contract §3.6):

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

Create `ids/model/__init__.py`:

```python
from __future__ import annotations

from .app import (
    ApplicationInfo,
    AppMessage,
    Detection,
    DnsCounts,
    DnsFlags,
    DnsMessage,
    DnsQuestion,
    DnsRecord,
    HttpBody,
    HttpHeader,
    HttpMessage,
    SmtpCommand,
    SmtpReply,
    SmtpSession,
)
from .decoded import (
    DecodedForm,
    DecodedHttp,
    DecodedMime,
    DecodedText,
    DecodedUri,
    DecodeStatus,
    MimeHeaders,
    MimePart,
    worst_status,
)
from .event import UNKNOWN, MessageEvent, PacketEvent, PreprocessStatus, ProcessingAction, Record
from .flow import (
    Direction,
    DirectionStats,
    Endpoint,
    EndReason,
    FlowRecord,
    FlowRef,
    TcpFlowStats,
    TcpState,
)
from .normalized import Normalized, NormalizedDns, NormalizedHttp, NormalizedSmtp
from .packet import (
    CaptureInfo,
    IpOption,
    Ipv4Flags,
    Ipv4Info,
    LinkInfo,
    LlcHeader,
    Payload,
    RawPacket,
    SnapHeader,
    TcpFlags,
    TcpInfo,
    TcpOption,
    Tick,
    UdpInfo,
    VlanTag,
)

__all__ = [
    "UNKNOWN",
    "AppMessage",
    "ApplicationInfo",
    "CaptureInfo",
    "DecodeStatus",
    "DecodedForm",
    "DecodedHttp",
    "DecodedMime",
    "DecodedText",
    "DecodedUri",
    "Detection",
    "Direction",
    "DirectionStats",
    "DnsCounts",
    "DnsFlags",
    "DnsMessage",
    "DnsQuestion",
    "DnsRecord",
    "EndReason",
    "Endpoint",
    "FlowRecord",
    "FlowRef",
    "HttpBody",
    "HttpHeader",
    "HttpMessage",
    "IpOption",
    "Ipv4Flags",
    "Ipv4Info",
    "LinkInfo",
    "LlcHeader",
    "MessageEvent",
    "MimeHeaders",
    "MimePart",
    "Normalized",
    "NormalizedDns",
    "NormalizedHttp",
    "NormalizedSmtp",
    "PacketEvent",
    "Payload",
    "PreprocessStatus",
    "ProcessingAction",
    "RawPacket",
    "Record",
    "SmtpCommand",
    "SmtpReply",
    "SmtpSession",
    "SnapHeader",
    "TcpFlags",
    "TcpFlowStats",
    "TcpInfo",
    "TcpOption",
    "TcpState",
    "Tick",
    "UdpInfo",
    "VlanTag",
    "worst_status",
]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_model.py -q`
Expected: PASS — 38 tests, exit status 0.

Run: `uv run pytest -q`
Expected: PASS — 225 tests, exit status 0.

Run: `uv run ruff check ids/model tests/test_model.py && uv run ruff format --check ids/model tests/test_model.py`
Expected: `All checks passed!`, `8 files already formatted`.

- [ ] **Step 5: Commit**

```bash
git add ids/model tests/test_model.py
git commit -m "feat: add typed schema v2 model"
```

### Task 4: `make_payload` with a single binary check

The current module computes `looks_binary` twice per call (once on the preview chunk inside `render`, once on the full data) and walks bytes in a Python generator. The rewrite computes it once on the full data, reuses it for the preview, counts printable bytes with `bytes.translate`, and masks binary previews with a translation table. `render` (no callers outside this module) is replaced by the private `_render`. `describe` keeps its signature and dict shape for the legacy callers (`ids/pipeline.py`, `ids/parsers/http.py`) until plan 1c; its preview now follows the full-data binary decision too (the existing pipeline/http tests pin the visible values and stay green).

Preview rule (`_render`): binary → printable ASCII kept, every other byte `.`, encoding `binary`; else strict UTF-8 → `utf-8`; if the only UTF-8 error is an incomplete sequence at the end of a chunk that was cut by the limit, the partial character is dropped and the encoding stays `utf-8`; otherwise latin-1.

**Files:**
- Modify: `ids/payload.py` (full rewrite, all 48 lines)
- Test: `tests/test_payload.py`

**Interfaces:**
- Consumes: `ids.model.packet.Payload` (Task 3).
- Produces:
  - `sha256_hex(data: bytes) -> str`
  - `looks_binary(data: bytes) -> bool` — `False` for empty; `True` when a NUL byte is present or the printable ratio (bytes 32-126, `\t`, `\n`, `\r`) is `< 0.75`.
  - `make_payload(data: bytes, *, max_bytes: int = 65535, preview_limit: int = 256) -> Payload` — `length`/`sha256` over all of `data`; `data = data[:max_bytes]`; `data_truncated = len(data) > max_bytes`; preview of `data[:preview_limit]`; `preview_truncated = len(data) > preview_limit`; `binary = looks_binary(data)`; `preview_hex = data[:64].hex()` when binary else `None`.
  - legacy, unchanged signature: `describe(data: bytes, limit: int = PREVIEW_LIMIT, hex_limit: int = HEX_LIMIT) -> dict[str, object]`; constants `PREVIEW_LIMIT = 256`, `HEX_LIMIT = 64`; `printable_ratio(data: bytes) -> float`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_payload.py`:

```python
from __future__ import annotations

import hashlib

import pytest

from ids.model import Payload
from ids.payload import looks_binary, make_payload


def test_empty_payload():
    assert make_payload(b"") == Payload(
        length=0,
        sha256=hashlib.sha256(b"").hexdigest(),
        data=b"",
        data_truncated=False,
        preview="",
        preview_truncated=False,
        preview_encoding="utf-8",
        binary=False,
        preview_hex=None,
    )


def test_payload_at_max_bytes_is_kept_whole():
    data = b"A" * 16
    payload = make_payload(data, max_bytes=16)
    assert payload.data == data
    assert payload.data_truncated is False
    assert payload.length == 16


def test_payload_over_max_bytes_keeps_the_prefix_but_hashes_everything():
    data = b"A" * 16 + b"B"
    payload = make_payload(data, max_bytes=16)
    assert payload.data == b"A" * 16
    assert payload.data_truncated is True
    assert payload.length == 17
    assert payload.sha256 == hashlib.sha256(data).hexdigest()


def test_max_bytes_zero_keeps_no_bytes():
    payload = make_payload(b"abc", max_bytes=0)
    assert payload.data == b""
    assert payload.data_truncated is True
    assert payload.length == 3


def test_preview_at_limit_is_not_truncated():
    payload = make_payload(b"PAYL", preview_limit=4)
    assert (payload.preview, payload.preview_truncated) == ("PAYL", False)


def test_preview_over_limit_is_cut_and_flagged():
    payload = make_payload(b"PAYLOAD-01", preview_limit=4)
    assert (payload.preview, payload.preview_truncated) == ("PAYL", True)
    assert payload.data == b"PAYLOAD-01"


def test_utf8_preview():
    payload = make_payload("price: 5€ only".encode())
    assert (payload.preview, payload.preview_encoding, payload.binary) == (
        "price: 5€ only",
        "utf-8",
        False,
    )
    assert payload.preview_hex is None


def test_invalid_utf8_text_falls_back_to_latin1():
    payload = make_payload(b"caf\xe9 au lait")
    assert (payload.preview, payload.preview_encoding, payload.binary) == (
        "café au lait",
        "latin-1",
        False,
    )
    assert payload.preview_hex is None


def test_binary_preview_is_masked_and_hex_is_added():
    data = b"\x00\x01GET\x7f\xff"
    payload = make_payload(data)
    assert payload.binary is True
    assert payload.preview_encoding == "binary"
    assert payload.preview == "..GET.."
    assert payload.preview_hex == data.hex()


def test_preview_hex_is_capped_at_64_bytes():
    data = bytes(range(200))
    payload = make_payload(data)
    assert payload.preview_hex == data[:64].hex()


def test_binary_is_decided_on_the_full_data_not_the_preview():
    data = b"GET / HTTP/1.1\r\n" + b"\x00" * 64
    payload = make_payload(data, preview_limit=4)
    assert payload.binary is True
    assert payload.preview_encoding == "binary"
    assert payload.preview == "GET "


def test_utf8_cut_inside_a_character_drops_the_partial_character():
    data = b"a" * 255 + "é".encode()
    payload = make_payload(data, preview_limit=256)
    assert payload.preview == "a" * 255
    assert payload.preview_encoding == "utf-8"
    assert payload.preview_truncated is True


def test_invalid_byte_before_the_cut_still_falls_back_to_latin1():
    data = b"abcdefghijklmnop\xff" + "é".encode()
    payload = make_payload(data, preview_limit=18)
    assert payload.preview_encoding == "latin-1"
    assert payload.preview == "abcdefghijklmnopÿÃ"


@pytest.mark.parametrize(
    ("data", "binary"),
    [
        (b"", False),
        (b"abc\x01", False),
        (b"ab\x01", True),
        (b"text\x00", True),
        (b"line one\r\n\tline two\n", False),
    ],
)
def test_looks_binary_threshold(data, binary):
    assert looks_binary(data) is binary
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_payload.py -q`
Expected: collection error `ImportError: cannot import name 'make_payload' from 'ids.payload'`.

- [ ] **Step 3: Write the implementation**

Replace the whole of `ids/payload.py` with:

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_payload.py -q`
Expected: PASS — 18 tests, exit status 0.

Run: `uv run pytest -q`
Expected: PASS — 243 tests, exit status 0 (the legacy `tests/test_pipeline.py` / `tests/test_http.py` preview assertions still pass through `describe`).

Run: `uv run ruff check ids/payload.py tests/test_payload.py && uv run ruff format --check ids/payload.py tests/test_payload.py`
Expected: `All checks passed!`, `2 files already formatted`.

- [ ] **Step 5: Commit**

```bash
git add ids/payload.py tests/test_payload.py
git commit -m "feat: add make_payload with a single binary check"
```

### Task 5: Schema v2 encoder

Rules implemented (contract §5, §5.1):
- `to_jsonable`: `None`/`str`/`int`/`float`/`bool` (exact types) pass through; `Enum` → `.value` (checked before anything else that is not an exact scalar, since `DecodeStatus` etc. subclass `str`); dataclass → dict in `dataclasses.fields()` order with the key `metadata["json"]` or the field name; a field whose type hint is `bytes` / `bytes | None` is written as `<key>_b64` with standard base64 text or `null`; `list`/`tuple` → list; `dict` with `str` keys → dict; anything else (sets, objects, bytes outside a bytes field, non-`str` dict keys) → `TypeError`.
- `encode(PacketEvent)`: keys in the exact §5.1 order; `timestamp_iso`, `event_type`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `application_protocol` come from the model properties (never stored).
- `encode(MessageEvent | FlowRecord)`: `schema_version`, `record_type`, then the declared fields in order. Any other object → `TypeError`.
- `iso_timestamp`: `datetime.fromtimestamp(v, timezone.utc).isoformat(timespec="microseconds")` with `+00:00` replaced by `Z`; `None` for `None` or for values `datetime` cannot represent (`OverflowError`, `OSError`, `ValueError`, e.g. `1e20`, `nan`).
- Field metadata is resolved once per class with `typing.get_type_hints` behind `functools.cache`.

**Files:**
- Create: `ids/codec.py`
- Create: `tests/codec_samples.py` (shared sample records; imported as `from codec_samples import ...`, the same way the existing tests import `golden`)
- Test: `tests/test_codec.py`

**Interfaces:**
- Consumes: `ids.model` (Task 3): `PacketEvent`, `MessageEvent`, `FlowRecord` and every nested dataclass; `ids.issues.Issue` (Task 2).
- Produces:
  - `SCHEMA_VERSION = 2`
  - `iso_timestamp(value: float | None) -> str | None`
  - `to_jsonable(obj: object) -> object`
  - `encode(record: PacketEvent | MessageEvent | FlowRecord) -> dict[str, object]`
  - `encode_line(record: PacketEvent | MessageEvent | FlowRecord) -> str` — `json.dumps(encode(record), ensure_ascii=False, separators=(",", ":"), allow_nan=False)`
  - test helpers in `tests/codec_samples.py`: `TS: float`, `rich_http_event() -> PacketEvent`, `rich_dns_event() -> PacketEvent`, `rich_smtp_event() -> PacketEvent`, `mime() -> DecodedMime`, `message_event() -> MessageEvent`, `flow_record() -> FlowRecord` (Task 6 reuses them).

- [ ] **Step 1: Write the failing test**

Create `tests/codec_samples.py`:

```python
from __future__ import annotations

from ids.issues import Issue
from ids.model import (
    ApplicationInfo,
    CaptureInfo,
    DecodedForm,
    DecodedHttp,
    DecodedMime,
    DecodedText,
    DecodedUri,
    DecodeStatus,
    Detection,
    Direction,
    DirectionStats,
    DnsCounts,
    DnsFlags,
    DnsMessage,
    DnsQuestion,
    DnsRecord,
    Endpoint,
    EndReason,
    FlowRecord,
    FlowRef,
    HttpBody,
    HttpHeader,
    HttpMessage,
    IpOption,
    Ipv4Flags,
    Ipv4Info,
    LinkInfo,
    MessageEvent,
    MimeHeaders,
    MimePart,
    Normalized,
    NormalizedDns,
    NormalizedHttp,
    NormalizedSmtp,
    PacketEvent,
    Payload,
    PreprocessStatus,
    ProcessingAction,
    SmtpCommand,
    SmtpReply,
    SmtpSession,
    TcpFlags,
    TcpFlowStats,
    TcpInfo,
    TcpOption,
    TcpState,
    UdpInfo,
    VlanTag,
)

TS = 1759000000.1
HTTP_BYTES = b"POST /login?next=%2Fhome HTTP/1.1\r\nHost: Example.COM\r\n\r\nuser=a+b&pw=%27x"


def capture(length: int) -> CaptureInfo:
    return CaptureInfo(
        source="pcap",
        origin="TEST/fixtures/x.pcap",
        linktype=1,
        linktype_name="EN10MB",
        captured_length=length,
        original_length=length,
        declared_capture_length=length,
        truncated_by_capture=False,
    )


def ethernet() -> LinkInfo:
    return LinkInfo(
        protocol="Ethernet",
        src_mac="02:00:00:00:00:01",
        dst_mac="02:00:00:00:00:02",
        ethertype=0x0800,
        ethertype_name="IPv4",
        vlan=[VlanTag(tpid="0x8100", pcp=5, dei=False, vid=42)],
    )


def ipv4(protocol_number: int, protocol_name: str) -> Ipv4Info:
    return Ipv4Info(
        protocol="IPv4",
        version=4,
        header_length=24,
        dscp=0,
        ecn=0,
        tos=0,
        total_length=120,
        identification=1,
        flags=Ipv4Flags(reserved=False, df=True, mf=False),
        fragment_offset=0,
        fragmented=False,
        ttl=64,
        protocol_number=protocol_number,
        protocol_name=protocol_name,
        header_checksum="0x1234",
        header_checksum_valid=True,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        options=[IpOption(type=1, name="NOP", length=1), IpOption(type=7, data="0409")],
        captured_truncated=False,
        declared_payload_length=96,
        captured_payload_length=96,
    )


def rich_http_event() -> PacketEvent:
    return PacketEvent(
        packet_id=7,
        timestamp=TS,
        capture=capture(134),
        link=ethernet(),
        network=ipv4(6, "TCP"),
        transport=TcpInfo(
            src_port=51234,
            dst_port=80,
            seq=1001,
            ack=1,
            header_length=32,
            reserved=0,
            flags=TcpFlags(psh=True, ack=True, syn=False, fin=False, rst=False),
            flags_list=["PSH", "ACK"],
            flags_string="PA",
            window=8192,
            checksum="0x54ac",
            checksum_valid=True,
            urgent_pointer=0,
            options=[
                TcpOption(type=2, name="MSS", length=4, mss=1460),
                TcpOption(type=5, name="SACK", length=10, blocks=[[1, 2], [3, 4]]),
                TcpOption(type=8, name="Timestamp", length=10, tsval=111, tsecr=0),
            ],
            payload_length=len(HTTP_BYTES),
        ),
        application=ApplicationInfo(
            protocol="HTTP",
            detection=Detection(
                protocol="HTTP",
                method="port+payload",
                confidence=1.0,
                port_matched=True,
                port_hint="HTTP",
                evidence="HTTP request line",
                scores={"HTTP": 1.0, "DNS": 0.0, "SMTP": 0.25},
            ),
            message=HttpMessage(
                kind="request",
                version="HTTP/1.1",
                start_line="POST /login?next=%2Fhome HTTP/1.1",
                method="POST",
                uri="/login?next=%2Fhome",
                headers=[HttpHeader("Host", "Example.COM")],
                body=HttpBody(
                    offset=58,
                    length=17,
                    declared_length=None,
                    transfer_encoding="identity",
                    truncated=False,
                ),
                complete=True,
            ),
        ),
        payload=Payload(
            length=len(HTTP_BYTES),
            sha256="ab" * 32,
            data=HTTP_BYTES,
            data_truncated=False,
            preview=HTTP_BYTES.decode(),
            preview_truncated=False,
            preview_encoding="utf-8",
            binary=False,
        ),
        decoded=DecodedHttp(
            uri=DecodedUri(
                text="/login?next=/home",
                path="/login",
                query="next=/home",
                params=[["next", "/home"]],
                status=DecodeStatus.DECODED,
                double_encoded=False,
            ),
            form=DecodedForm(params=[["user", "a b"], ["pw", "'x"]], status=DecodeStatus.DECODED),
            body=DecodedText(
                text="user=a+b&pw=%27x",
                charset="ascii",
                status=DecodeStatus.UNCHANGED,
                invalid_byte_count=0,
                truncated=False,
            ),
            status=DecodeStatus.DECODED,
        ),
        normalized=Normalized(
            timestamp=TS,
            timestamp_iso="2025-09-27T19:06:40.100000Z",
            network_protocol="IPv4",
            protocol="TCP",
            application_protocol="HTTP",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=51234,
            dst_port=80,
            http=NormalizedHttp(
                method="POST",
                scheme="http",
                host="example.com",
                port=80,
                path="/login",
                headers={"host": ["Example.COM"]},
            ),
        ),
        preprocess_status=PreprocessStatus.PARTIAL,
        processing_action=ProcessingAction.MARK,
        reason=["transport/truncated_packet"],
        flow=FlowRef(
            flow_id="0123456789abcdef",
            direction=Direction.FORWARD,
            state=TcpState.ESTABLISHED,
            flow_packet_index=4,
        ),
        issues=[
            Issue("transport", "truncated_packet", "short segment", {"needed": 20, "have": 12})
        ],
    )


def rich_dns_event() -> PacketEvent:
    return PacketEvent(
        packet_id=8,
        timestamp=TS + 1,
        capture=capture(90),
        link=ethernet(),
        network=ipv4(17, "UDP"),
        transport=UdpInfo(
            src_port=53,
            dst_port=40000,
            length=56,
            checksum="0x0000",
            checksum_valid=None,
            declared_payload_length=48,
            payload_length=48,
            captured_truncated=False,
        ),
        application=ApplicationInfo(
            protocol="DNS",
            detection=Detection(protocol="DNS", method="port", confidence=0.5),
            message=DnsMessage(
                kind="response",
                id=0x1234,
                flags=DnsFlags(qr=True, opcode=0, aa=False, tc=False, rd=True, ra=True, rcode=0),
                opcode=0,
                opcode_name="QUERY",
                rcode=0,
                rcode_name="NOERROR",
                counts=DnsCounts(questions=1, answers=2, authorities=0, additionals=1),
                questions=[DnsQuestion("Example.com", 1, "A", 1, "IN")],
                answers=[
                    DnsRecord("example.com", 1, "A", 1, "IN", 60, 4, "93.184.216.34"),
                    DnsRecord(
                        "example.com",
                        16,
                        "TXT",
                        1,
                        "IN",
                        60,
                        12,
                        ["v=spf1", "-all"],
                    ),
                ],
                additionals=[
                    DnsRecord(
                        name="",
                        type=41,
                        type_name="OPT",
                        rdlength=3,
                        value={"flags": 0, "note": "x"},
                        rdata="00ff01",
                        rdata_error=Issue("application", "decode_error", "bad", {"offset": 3}),
                        udp_payload_size=1232,
                    )
                ],
                tcp=False,
            ),
        ),
        payload=Payload(
            length=4,
            sha256="cd" * 32,
            data=b"\x12\x34\x81\x80",
            data_truncated=False,
            preview=".4..",
            preview_truncated=False,
            preview_encoding="binary",
            binary=True,
            preview_hex="12348180",
        ),
        normalized=Normalized(dns=NormalizedDns(names=["example.com"])),
        preprocess_status=PreprocessStatus.VALID,
        processing_action=ProcessingAction.FORWARD,
        flow=FlowRef(flow_id="fedcba9876543210", direction=Direction.BACKWARD, flow_packet_index=2),
    )


def rich_smtp_event() -> PacketEvent:
    return PacketEvent(
        packet_id=9,
        timestamp=TS + 2,
        network=ipv4(6, "TCP"),
        transport=TcpInfo(src_port=40000, dst_port=25),
        application=ApplicationInfo(
            protocol="SMTP",
            message=SmtpSession(
                kind="mixed",
                commands=[
                    SmtpCommand(verb="EHLO", arguments="client.example", domain="client.example"),
                    SmtpCommand(
                        verb="MAIL",
                        arguments="FROM:<a@example.com> SIZE=10",
                        address="a@example.com",
                        parameters=["SIZE=10"],
                        path="<a@example.com>",
                    ),
                    SmtpCommand(verb="AUTH", mechanism="PLAIN", credentials_present=True),
                ],
                replies=[
                    SmtpReply(
                        code=250, text="ok", lines=["250-hello", "250 ok"], continuation=False
                    )
                ],
                unparsed_lines=["???"],
                command="EHLO",
                status_code=250,
                last_status_code=250,
                mail_from="a@example.com",
                rcpt_to=["b@example.com"],
            ),
        ),
        decoded=mime(),
        normalized=Normalized(
            smtp=NormalizedSmtp(
                helo="client.example", mail_from="a@example.com", rcpt_to=["b@example.com"]
            )
        ),
    )


def mime() -> DecodedMime:
    return DecodedMime(
        headers=MimeHeaders(
            subject="Chào",
            from_="a@example.com",
            to="b@example.com",
            cc=None,
            date="Sat, 27 Sep 2025 19:06:40 +0000",
            message_id="<1@example.com>",
        ),
        parts=[
            MimePart(
                index=0,
                content_type="text/plain",
                charset="utf-8",
                transfer_encoding="base64",
                size=5,
                sha256="ef" * 32,
                text="Chào",
                status=DecodeStatus.DECODED,
                truncated=False,
            )
        ],
        status=DecodeStatus.DECODED,
    )


def message_event() -> MessageEvent:
    return MessageEvent(
        message_id="0123456789abcdef-1",
        flow_id="0123456789abcdef",
        protocol="SMTP",
        packet_ids=[5, 6],
        start_time=TS,
        end_time=TS + 1,
        data=b"Subject: hi\r\n\r\nbody\r\n.\r\n",
        complete=True,
        truncated=False,
        gap=False,
        decoded=mime(),
        preprocess_status=PreprocessStatus.VALID,
        processing_action=ProcessingAction.FORWARD,
        reason=[],
        issues=[Issue("decoder", "invalid_base64", "bad pad", {"part": 0})],
    )


def flow_record() -> FlowRecord:
    return FlowRecord(
        flow_id="0123456789abcdef",
        protocol="TCP",
        application_protocol="HTTP",
        endpoint_a=Endpoint("10.0.0.1", 51234),
        endpoint_b=Endpoint("10.0.0.2", 80),
        start_time=TS,
        last_seen=TS + 2.5,
        duration=2.5,
        packet_count=5,
        byte_count=400,
        payload_byte_count=120,
        forward=DirectionStats(3, 250, 100),
        backward=DirectionStats(2, 150, 20),
        tcp=TcpFlowStats(
            state=TcpState.CLOSED,
            syn_count=2,
            ack_count=4,
            fin_count=2,
            rst_count=0,
            handshake_complete=True,
            midstream=False,
        ),
        end_reason=EndReason.CLOSED,
        first_packet_id=1,
        last_packet_id=5,
    )
```

Create `tests/test_codec.py`:

```python
from __future__ import annotations

import base64
import json
from dataclasses import fields

import pytest
from codec_samples import TS, flow_record, message_event, rich_dns_event, rich_http_event

from ids.codec import SCHEMA_VERSION, encode, encode_line, iso_timestamp, to_jsonable
from ids.issues import Issue
from ids.model import (
    DecodedMime,
    Detection,
    DnsQuestion,
    FlowRecord,
    Ipv4Info,
    MessageEvent,
    MimeHeaders,
    PacketEvent,
    Payload,
    TcpInfo,
)

PACKET_KEYS = [
    "schema_version",
    "record_type",
    "packet_id",
    "timestamp",
    "timestamp_iso",
    "event_type",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "application_protocol",
    "preprocess_status",
    "processing_action",
    "reason",
    "flow",
    "capture",
    "link",
    "network",
    "transport",
    "application",
    "payload",
    "decoded",
    "normalized",
    "issues",
]


def test_schema_version_is_two():
    assert SCHEMA_VERSION == 2


def test_packet_record_key_order():
    assert list(encode(rich_http_event())) == PACKET_KEYS


def test_empty_packet_record_has_every_key_with_empty_values():
    assert encode(PacketEvent()) == {
        "schema_version": 2,
        "record_type": "packet",
        "packet_id": None,
        "timestamp": None,
        "timestamp_iso": None,
        "event_type": "unparsed",
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "protocol": None,
        "application_protocol": "UNKNOWN",
        "preprocess_status": None,
        "processing_action": None,
        "reason": [],
        "flow": None,
        "capture": None,
        "link": None,
        "network": None,
        "transport": None,
        "application": None,
        "payload": None,
        "decoded": None,
        "normalized": None,
        "issues": [],
    }


def test_derived_top_level_fields_come_from_the_nested_blocks():
    record = encode(rich_http_event())
    assert record["timestamp"] == TS
    assert record["timestamp_iso"] == "2025-09-27T19:06:40.100000Z"
    assert record["event_type"] == "http_request"
    assert (record["src_ip"], record["dst_ip"], record["src_port"], record["dst_port"]) == (
        "10.0.0.1",
        "10.0.0.2",
        51234,
        80,
    )
    assert record["protocol"] == "TCP"
    assert record["application_protocol"] == "HTTP"


def test_nested_dataclass_writes_every_declared_field_in_order():
    network = encode(PacketEvent(network=Ipv4Info(src_ip="10.0.0.1")))["network"]
    assert list(network) == [f.name for f in fields(Ipv4Info)]
    assert network["src_ip"] == "10.0.0.1"
    assert network["flags"] is None
    assert network["options"] == []


def test_json_aliases_replace_python_field_names():
    assert to_jsonable(DnsQuestion(name="a", type=1, class_=1)) == {
        "name": "a",
        "type": 1,
        "type_name": None,
        "class": 1,
        "class_name": None,
    }
    headers = to_jsonable(MimeHeaders(from_="a@example.com"))
    assert "from_" not in headers
    assert headers["from"] == "a@example.com"


def test_bytes_fields_are_written_as_base64_under_b64_keys():
    data = b"\x00\xffGET"
    encoded = to_jsonable(Payload(length=5, data=data))
    assert "data" not in encoded
    assert encoded["data_b64"] == base64.b64encode(data).decode("ascii")
    assert base64.b64decode(encoded["data_b64"]) == data


def test_missing_bytes_are_written_as_null_b64():
    assert to_jsonable(Payload())["data_b64"] is None


def test_enums_are_written_as_their_values():
    record = encode(rich_http_event())
    assert record["preprocess_status"] == "partial"
    assert record["processing_action"] == "mark"
    assert record["flow"] == {
        "flow_id": "0123456789abcdef",
        "direction": "forward",
        "state": "ESTABLISHED",
        "flow_packet_index": 4,
    }
    assert record["decoded"]["status"] == "decoded"
    assert record["decoded"]["kind"] == "http"


def test_issues_are_written_as_objects():
    assert encode(rich_http_event())["issues"] == [
        {
            "stage": "transport",
            "code": "truncated_packet",
            "message": "short segment",
            "context": {"needed": 20, "have": 12},
        }
    ]


def test_dns_record_alias_object_value_and_nested_issue():
    answers = encode(rich_dns_event())["application"]["message"]["answers"]
    assert answers[0]["class"] == 1
    assert answers[0]["value"] == "93.184.216.34"
    assert answers[1]["value"] == ["v=spf1", "-all"]
    opt = encode(rich_dns_event())["application"]["message"]["additionals"][0]
    assert opt["value"] == {"flags": 0, "note": "x"}
    assert opt["rdata_error"] == {
        "stage": "application",
        "code": "decode_error",
        "message": "bad",
        "context": {"offset": 3},
    }


def test_message_record_starts_with_schema_and_type_then_declared_fields():
    record = encode(message_event())
    expected = ["schema_version", "record_type"]
    expected += ["data_b64" if f.name == "data" else f.name for f in fields(MessageEvent)]
    assert list(record) == expected
    assert record["record_type"] == "message"
    assert base64.b64decode(record["data_b64"]) == message_event().data
    assert record["decoded"]["headers"]["from"] == "a@example.com"


def test_flow_record_starts_with_schema_and_type_then_declared_fields():
    record = encode(flow_record())
    assert list(record) == ["schema_version", "record_type"] + [f.name for f in fields(FlowRecord)]
    assert record["record_type"] == "flow"
    assert record["forward"] == {"packet_count": 3, "byte_count": 250, "payload_byte_count": 100}
    assert record["tcp"]["state"] == "CLOSED"
    assert record["end_reason"] == "closed"


def test_empty_flow_record_keeps_zero_counters():
    record = encode(FlowRecord())
    assert record["packet_count"] == 0
    assert record["forward"] == {"packet_count": 0, "byte_count": 0, "payload_byte_count": 0}
    assert record["tcp"] is None
    assert record["end_reason"] is None


@pytest.mark.parametrize(
    "record",
    [
        PacketEvent(reason=[b"raw"]),
        PacketEvent(issues=[Issue("load", "x", "y", {"value": {1, 2}})]),
        PacketEvent(issues=[Issue("load", "x", "y", {1: "int key"})]),
    ],
)
def test_non_json_values_raise_type_error(record):
    with pytest.raises(TypeError):
        encode(record)


def test_non_json_value_inside_a_nested_block_raises_type_error():
    with pytest.raises(TypeError):
        to_jsonable(Detection(scores={"HTTP": object()}))


def test_encode_rejects_objects_that_are_not_records():
    with pytest.raises(TypeError):
        encode(TcpInfo())


def test_encode_line_is_compact_and_keeps_unicode():
    line = encode_line(PacketEvent(decoded=DecodedMime(headers=MimeHeaders(subject="Chào"))))
    assert line.startswith('{"schema_version":2,"record_type":"packet","packet_id":null,')
    assert "Chào" in line
    assert json.loads(line)["decoded"]["headers"]["subject"] == "Chào"


def test_encode_line_rejects_nan():
    with pytest.raises(ValueError):
        encode_line(PacketEvent(packet_id=1, timestamp=float("nan")))


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, None),
        (0, "1970-01-01T00:00:00.000000Z"),
        (1759000000, "2025-09-27T19:06:40.000000Z"),
        (TS, "2025-09-27T19:06:40.100000Z"),
        (1e20, None),
        (float("nan"), None),
    ],
)
def test_iso_timestamp(value, expected):
    assert iso_timestamp(value) == expected


def test_out_of_range_timestamp_encodes_with_null_iso():
    record = encode(PacketEvent(packet_id=1, timestamp=1e20))
    assert record["timestamp"] == 1e20
    assert record["timestamp_iso"] is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_codec.py -q`
Expected: collection error `ModuleNotFoundError: No module named 'ids.codec'`.

- [ ] **Step 3: Write the implementation**

Create `ids/codec.py`:

```python
from __future__ import annotations

import base64
import dataclasses
import json
import typing
from datetime import datetime, timezone
from enum import Enum
from functools import cache

from .model.event import MessageEvent, PacketEvent
from .model.flow import FlowRecord

SCHEMA_VERSION = 2


@dataclasses.dataclass(frozen=True, slots=True)
class _Field:
    name: str
    key: str
    is_bytes: bool


def iso_timestamp(value: float | None) -> str | None:
    if value is None:
        return None
    try:
        moment = datetime.fromtimestamp(value, timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None
    return moment.isoformat(timespec="microseconds").replace("+00:00", "Z")


def to_jsonable(obj: object) -> object:
    kind = type(obj)
    if obj is None or kind is str or kind is int or kind is float or kind is bool:
        return obj
    if isinstance(obj, Enum):
        return obj.value
    if dataclasses.is_dataclass(kind):
        return _dump_fields(obj, {})
    if kind is list or kind is tuple:
        return [to_jsonable(item) for item in obj]
    if kind is dict:
        out: dict[str, object] = {}
        for key, value in obj.items():
            if type(key) is not str:
                raise TypeError(f"dict key {key!r} is not a str")
            out[key] = to_jsonable(value)
        return out
    raise TypeError(f"{kind.__name__} value {obj!r} is not JSON serialisable")


def _dump_fields(obj: object, out: dict[str, object]) -> dict[str, object]:
    for spec in _fields(type(obj)):
        value = getattr(obj, spec.name)
        if spec.is_bytes:
            out[spec.key] = None if value is None else base64.b64encode(value).decode("ascii")
        else:
            out[spec.key] = to_jsonable(value)
    return out


def encode(record: PacketEvent | MessageEvent | FlowRecord) -> dict[str, object]:
    if isinstance(record, PacketEvent):
        return _encode_packet(record)
    if isinstance(record, (MessageEvent, FlowRecord)):
        head: dict[str, object] = {
            "schema_version": SCHEMA_VERSION,
            "record_type": record.RECORD_TYPE,
        }
        return _dump_fields(record, head)
    raise TypeError(f"cannot encode {type(record).__name__}")


def _encode_packet(event: PacketEvent) -> dict[str, object]:
    return {
        "schema_version": SCHEMA_VERSION,
        "record_type": PacketEvent.RECORD_TYPE,
        "packet_id": to_jsonable(event.packet_id),
        "timestamp": to_jsonable(event.timestamp),
        "timestamp_iso": iso_timestamp(event.timestamp),
        "event_type": event.event_type,
        "src_ip": event.src_ip,
        "dst_ip": event.dst_ip,
        "src_port": event.src_port,
        "dst_port": event.dst_port,
        "protocol": event.protocol,
        "application_protocol": event.application_protocol,
        "preprocess_status": to_jsonable(event.preprocess_status),
        "processing_action": to_jsonable(event.processing_action),
        "reason": to_jsonable(event.reason),
        "flow": to_jsonable(event.flow),
        "capture": to_jsonable(event.capture),
        "link": to_jsonable(event.link),
        "network": to_jsonable(event.network),
        "transport": to_jsonable(event.transport),
        "application": to_jsonable(event.application),
        "payload": to_jsonable(event.payload),
        "decoded": to_jsonable(event.decoded),
        "normalized": to_jsonable(event.normalized),
        "issues": to_jsonable(event.issues),
    }


def encode_line(record: PacketEvent | MessageEvent | FlowRecord) -> str:
    return json.dumps(encode(record), ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def _is_bytes(hint: object) -> bool:
    return hint is bytes or bytes in typing.get_args(hint)


@cache
def _fields(cls: type) -> tuple[_Field, ...]:
    hints = typing.get_type_hints(cls)
    specs = []
    for item in dataclasses.fields(cls):
        key = item.metadata.get("json", item.name)
        is_bytes = _is_bytes(hints[item.name])
        specs.append(_Field(item.name, f"{key}_b64" if is_bytes else key, is_bytes))
    return tuple(specs)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_codec.py -q`
Expected: PASS — 28 tests, exit status 0.

Run: `uv run pytest -q`
Expected: PASS — 271 tests, exit status 0.

Run: `uv run ruff check ids/codec.py tests/codec_samples.py tests/test_codec.py && uv run ruff format --check ids/codec.py tests/codec_samples.py tests/test_codec.py`
Expected: `All checks passed!`, `3 files already formatted`.

- [ ] **Step 5: Commit**

```bash
git add ids/codec.py tests/codec_samples.py tests/test_codec.py
git commit -m "feat: add schema v2 encoder"
```

### Task 6: Tolerant schema v2 decoder

Rules implemented (contract §5 `from_jsonable` / `decode_packet`, spec §6.4):
- Loaders are compiled once per class from `typing.get_type_hints` (cached through `_fields`). Supported hints: `str`, `int`, `float`, `bool`, `bytes` (via `<key>_b64`), `object`/`Any` (JSON-native pass-through), `Enum` subclasses (by value), dataclasses, `X | None`, `list[X]` (incl. `list[list[int]]`, `list[list[str]]`), `dict[str, X]`, and unions of dataclasses that carry a `TAG = (key, value)` (`TcpInfo | UdpInfo | None`, `HttpMessage | DnsMessage | SmtpSession | None`, `DecodedHttp | DecodedMime | None`). Any other hint raises `TypeError` the first time the class is used (programming error, not data).
- Missing key → field default, no issue. Unknown keys (incl. derived `event_type`, `timestamp_iso`, `application_protocol`, `src_ip`, … and v1 extras such as `errors`) → ignored.
- Wrong type → field default (`None`, `[]`, `0`, `DirectionStats()`…) + `Issue("load", "invalid_type", "<path>: expected <expected>, got <type>", {"field": path, "expected": expected, "got": type(value).__name__})`.
- Paths: JSON keys joined by `.`, list indices in brackets, empty string for the record itself: `packet_id`, `network.src_ip`, `transport.src_port`, `network.options[0].type`, `payload.data_b64`, `application.detection.scores.DNS`; flat fallback fields use their top-level key (`src_ip`, `src_port`, `protocol`, `transport_protocol`).
- Scalars: exact type checks, so `bool` is never accepted for `int`; `int` is accepted for `float` and converted with `float()` (ints beyond float range → `invalid_type`); non-finite floats (`NaN`, `Infinity`, which `json.loads` accepts) → `invalid_type`, so a loaded event can always be re-encoded with `allow_nan=False`.
- `object`/`Any` fields accept only JSON-native values (str, int, bool, None, finite float, lists, dicts with str keys), checked iteratively (no recursion limit risk).
- A bad element inside a `list[...]`/`dict[str, ...]` is dropped with its own issue (`reason[1]`, `transport.options[0].blocks[1][1]`); the rest of the container is kept.
- `<key>_b64`: must be a str accepted by `base64.b64decode(value, validate=True)` (alphabet + padding checked, non-ASCII rejected; 3.10-safe) else `invalid_type` with expected `base64 str`.
- Enums: str value of a member; anything else (incl. wrong case `"MARK"`) → `invalid_type` with expected = enum class name.
- Tagged unions: the member whose `TAG` key holds a str equal to the tag value under `casefold()` is loaded (raw text kept, e.g. `protocol == "udp"`); no match / no tag / not an object → `invalid_type` with expected `"TcpInfo | UdpInfo"` etc.
- `PacketEvent.timestamp` additionally accepts an ISO-8601 string (spec §8.2): a trailing `Z`/`z` is replaced by `+00:00` (3.10 `fromisoformat` has no `Z`), surrounding whitespace stripped, naive values are UTC, result = epoch float; unparsable → `invalid_type` with expected `float or ISO-8601 str`. Millisecond scaling stays in the Preprocessor (plan 3).
- `decode_packet(obj)` never raises. Non-dict → `(PacketEvent(), [invalid_type field ""])`. `schema_version` present and not the int `2` (incl. `"2"`, `True`) → `unsupported_schema` with context `{"schema_version": value}`; `record_type` present and not `"packet"` (incl. `null`) → `unsupported_schema` with context `{"record_type": value}`; the record still loads.
- Flat fallback (after the nested load): when `obj.get("network") is None` and at least one of top-level `src_ip`/`dst_ip` loads as a str → `Ipv4Info(protocol="IPv4", src_ip, dst_ip, protocol_name=<top-level "protocol" str or None>)`. When `obj.get("transport") is None` and top-level `protocol` — else `transport_protocol` — casefolds to `tcp`/`udp` → `TcpInfo`/`UdpInfo(src_port, dst_port)` from the top-level ports (tag field keeps its default `"TCP"`/`"UDP"`). An encoded record whose `network`/`transport` is `null` also has null top-level copies, so the fallback never changes a round trip.
- Returned issues are only the load issues; `event.issues` holds just what the JSON `issues` key contained (the events source of plan 1c appends the load issues).
- Python 3.10 note: there `get_type_hints` wraps `x: object = None` as `Optional[object]`; the union branch with a single non-`None` member handles it. Verified while planning on CPython 3.10.20 and 3.14.7 (both `330 passed`).

**Files:**
- Modify: `ids/codec.py` (full replacement; the Task 5 encoder code is unchanged, `_Field` gains `load`)
- Test: `tests/test_codec_decode.py`

**Interfaces:**
- Consumes: Task 5 `ids.codec` encoder + `tests/codec_samples.py`; `ids.issues.Issue`, `ids.issues.Issues` (Task 2); `ids.model` (Task 3).
- Produces:
  - `from_jsonable(cls: type[T], obj: object, issues: Issues, path: str) -> T | None` — `None` (+ `invalid_type` at `path`) when `obj` is not a dict.
  - `decode_packet(obj: object) -> tuple[PacketEvent, list[Issue]]` — issues stage `load`.
  - Invariant: `decode_packet(json.loads(encode_line(e))) == (e, [])` for every `PacketEvent` built from the model; `from_jsonable(MessageEvent | FlowRecord, json.loads(encode_line(r)), issues, "") == r`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_codec_decode.py`:

```python
from __future__ import annotations

import json

import pytest
from codec_samples import (
    TS,
    flow_record,
    message_event,
    rich_dns_event,
    rich_http_event,
    rich_smtp_event,
)

from ids.codec import decode_packet, encode_line, from_jsonable
from ids.issues import Issue, Issues
from ids.model import (
    DecodedMime,
    DecodeStatus,
    Direction,
    DirectionStats,
    DnsMessage,
    DnsRecord,
    FlowRecord,
    Ipv4Info,
    MessageEvent,
    PacketEvent,
    Payload,
    PreprocessStatus,
    TcpFlags,
    TcpInfo,
    TcpOption,
    UdpInfo,
)

FLAT = {
    "packet_id": 3,
    "timestamp": 1759000000.5,
    "src_ip": "10.0.0.1",
    "dst_ip": "10.0.0.2",
    "src_port": 51234,
    "dst_port": 80,
    "protocol": "tcp",
}


def load(record: dict) -> tuple[PacketEvent, list[Issue]]:
    return decode_packet(json.loads(json.dumps(record)))


def invalid_fields(issues: list[Issue]) -> list[str]:
    return [issue.context["field"] for issue in issues if issue.code == "invalid_type"]


@pytest.mark.parametrize("build", [rich_http_event, rich_dns_event, rich_smtp_event, PacketEvent])
def test_packet_round_trip_through_json(build):
    event = build()
    assert decode_packet(json.loads(encode_line(event))) == (event, [])


def test_network_only_packet_round_trip_does_not_invent_a_transport():
    event = PacketEvent(
        packet_id=2, timestamp=TS, network=Ipv4Info(src_ip="1.1.1.1", dst_ip="2.2.2.2")
    )
    assert decode_packet(json.loads(encode_line(event))) == (event, [])


def test_message_and_flow_records_round_trip_through_from_jsonable():
    issues = Issues("load")
    message = json.loads(encode_line(message_event()))
    flow = json.loads(encode_line(flow_record()))
    assert from_jsonable(MessageEvent, message, issues, "") == message_event()
    assert from_jsonable(FlowRecord, flow, issues, "") == flow_record()
    assert issues.records == []


def test_wrong_types_fall_back_to_defaults_with_dotted_paths():
    event, issues = load(
        {
            "packet_id": "7",
            "timestamp": True,
            "network": {
                "src_ip": 5,
                "ttl": True,
                "flags": {"df": "yes"},
                "options": [{"type": "x"}],
            },
            "transport": {"protocol": "TCP", "src_port": 80.0, "flags_list": ["SYN", 2]},
        }
    )
    assert invalid_fields(issues) == [
        "packet_id",
        "timestamp",
        "network.flags.df",
        "network.ttl",
        "network.src_ip",
        "network.options[0].type",
        "transport.src_port",
        "transport.flags_list[1]",
    ]
    assert event.packet_id is None
    assert event.timestamp is None
    assert event.network.src_ip is None
    assert event.network.ttl is None
    assert event.network.flags.df is None
    assert event.network.options[0].type is None
    assert event.transport.src_port is None
    assert event.transport.flags_list == ["SYN"]
    assert all(issue.stage == "load" for issue in issues)


def test_invalid_type_issue_context_names_field_expected_and_got():
    _, issues = load({"packet_id": "7"})
    assert issues == [
        Issue(
            "load",
            "invalid_type",
            "packet_id: expected int, got str",
            {"field": "packet_id", "expected": "int", "got": "str"},
        )
    ]


def test_int_is_accepted_for_float_and_converted():
    event, issues = load({"timestamp": 1759000000})
    assert issues == []
    assert event.timestamp == 1759000000.0
    assert type(event.timestamp) is float


def test_bool_is_rejected_for_int_fields():
    event, issues = load({"packet_id": True})
    assert event.packet_id is None
    assert invalid_fields(issues) == ["packet_id"]


@pytest.mark.parametrize("text", ['{"timestamp": NaN}', '{"timestamp": Infinity}'])
def test_non_finite_floats_are_rejected(text):
    event, issues = decode_packet(json.loads(text))
    assert event.timestamp is None
    assert invalid_fields(issues) == ["timestamp"]
    assert json.loads(encode_line(event))["timestamp"] is None


def test_integer_too_large_for_float_is_rejected():
    event, issues = decode_packet({"timestamp": 10**400})
    assert event.timestamp is None
    assert invalid_fields(issues) == ["timestamp"]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("2025-09-27T19:06:40.100000Z", TS),
        ("2025-09-27T19:06:40.100000+00:00", TS),
        ("2025-09-28T02:06:40.100000+07:00", TS),
        ("2025-09-27T19:06:40", 1759000000.0),
        (" 2025-09-27T19:06:40z ", 1759000000.0),
    ],
)
def test_iso_timestamp_strings_are_converted_to_epoch_seconds(text, expected):
    event, issues = decode_packet({"timestamp": text})
    assert issues == []
    assert event.timestamp == expected


def test_unparsable_timestamp_string_is_invalid():
    event, issues = decode_packet({"timestamp": "yesterday"})
    assert event.timestamp is None
    assert issues[0].context == {
        "field": "timestamp",
        "expected": "float or ISO-8601 str",
        "got": "str",
    }


def test_non_optional_fields_keep_their_default_on_null_or_wrong_type():
    issues = Issues("load")
    flow = from_jsonable(
        FlowRecord,
        {"packet_count": None, "forward": "x", "tcp": {"handshake_complete": 1}},
        issues,
        "",
    )
    assert flow.packet_count == 0
    assert flow.forward == DirectionStats()
    assert flow.tcp.handshake_complete is False
    assert invalid_fields(issues.records) == ["packet_count", "forward", "tcp.handshake_complete"]


@pytest.mark.parametrize("value", ["!!!!", "QQ", "QQ==QQ==", "QUJD\n", "ÀÀÀÀ", 12])
def test_bad_base64_is_invalid(value):
    event, issues = load({"payload": {"length": 3, "data_b64": value}})
    assert event.payload == Payload(length=3)
    assert invalid_fields(issues) == ["payload.data_b64"]


def test_null_base64_loads_as_none_without_issue():
    event, issues = load({"payload": {"data_b64": None}})
    assert event.payload.data is None
    assert issues == []


def test_unknown_enum_values_are_invalid():
    event, issues = load(
        {
            "preprocess_status": "maybe",
            "processing_action": "MARK",
            "flow": {"direction": "forward", "state": "OPEN"},
        }
    )
    assert event.preprocess_status is None
    assert event.processing_action is None
    assert event.flow.direction is Direction.FORWARD
    assert event.flow.state is None
    assert invalid_fields(issues) == ["preprocess_status", "processing_action", "flow.state"]


def test_enum_values_load_as_members():
    event, issues = load(
        {"preprocess_status": "partial", "decoded": {"kind": "mime", "status": "failed"}}
    )
    assert issues == []
    assert event.preprocess_status is PreprocessStatus.PARTIAL
    assert event.decoded == DecodedMime(status=DecodeStatus.FAILED)


def test_union_member_is_chosen_by_tag_case_insensitively():
    event, issues = load(
        {
            "network": {"src_ip": "10.0.0.1"},
            "transport": {"protocol": "udp", "src_port": 53},
            "application": {"protocol": "DNS", "message": {"protocol": "dns", "kind": "query"}},
        }
    )
    assert issues == []
    assert event.transport == UdpInfo(protocol="udp", src_port=53)
    assert event.application.message == DnsMessage(protocol="dns", kind="query")
    assert event.event_type == "dns_query"


@pytest.mark.parametrize(
    ("record", "field", "expected"),
    [
        ({"transport": {"protocol": "SCTP"}}, "transport", "TcpInfo | UdpInfo"),
        ({"transport": {"src_port": 1}}, "transport", "TcpInfo | UdpInfo"),
        ({"transport": [6]}, "transport", "TcpInfo | UdpInfo"),
        (
            {"application": {"message": {"protocol": "FTP"}}},
            "application.message",
            "HttpMessage | DnsMessage | SmtpSession",
        ),
        ({"decoded": {"kind": "html"}}, "decoded", "DecodedHttp | DecodedMime"),
    ],
)
def test_union_without_a_matching_tag_is_invalid(record, field, expected):
    _, issues = load({"network": {"src_ip": "10.0.0.1"}, **record})
    assert [(i.context["field"], i.context["expected"]) for i in issues] == [(field, expected)]


def test_nested_lists_of_ints_and_strings():
    event, issues = load(
        {
            "transport": {
                "protocol": "TCP",
                "options": [{"type": 5, "blocks": [[1, 2], [3, "4"], "x"]}],
            },
            "decoded": {"kind": "http", "uri": {"params": [["a", "1"], ["b", 2]]}},
        }
    )
    assert event.transport.options == [TcpOption(type=5, blocks=[[1, 2], [3]])]
    assert event.decoded.uri.params == [["a", "1"], ["b"]]
    assert invalid_fields(issues) == [
        "transport.options[0].blocks[1][1]",
        "transport.options[0].blocks[2]",
        "decoded.uri.params[1][1]",
    ]


def test_dict_fields_load_values_and_drop_bad_entries():
    event, issues = load(
        {
            "application": {"detection": {"scores": {"HTTP": 1, "DNS": "high"}}},
            "normalized": {"http": {"headers": {"host": ["a"], "x": "b"}}},
        }
    )
    assert event.application.detection.scores == {"HTTP": 1.0}
    assert event.normalized.http.headers == {"host": ["a"]}
    assert invalid_fields(issues) == [
        "application.detection.scores.DNS",
        "normalized.http.headers.x",
    ]


def test_object_fields_pass_json_values_through():
    issues = Issues("load")
    record = from_jsonable(DnsRecord, {"value": {"a": [1, "b", None, 2.5]}}, issues, "r")
    assert record.value == {"a": [1, "b", None, 2.5]}
    assert issues.records == []


def test_object_fields_reject_non_finite_numbers():
    issues = Issues("load")
    record = from_jsonable(DnsRecord, {"value": [1, float("nan")]}, issues, "r")
    assert record.value is None
    assert invalid_fields(issues.records) == ["r.value"]


def test_from_jsonable_on_a_non_object_returns_none():
    issues = Issues("load")
    assert from_jsonable(TcpFlags, [True], issues, "transport.flags") is None
    assert invalid_fields(issues.records) == ["transport.flags"]


@pytest.mark.parametrize("value", [[1, 2], "text", None, 5])
def test_non_object_record_becomes_a_stub(value):
    event, issues = decode_packet(value)
    assert event == PacketEvent()
    assert [(i.stage, i.code, i.context["field"]) for i in issues] == [("load", "invalid_type", "")]


@pytest.mark.parametrize(
    ("header", "context"),
    [
        ({"schema_version": 1}, {"schema_version": 1}),
        ({"schema_version": 9}, {"schema_version": 9}),
        ({"schema_version": "2"}, {"schema_version": "2"}),
        ({"schema_version": True}, {"schema_version": True}),
        ({"record_type": "flow"}, {"record_type": "flow"}),
        ({"record_type": None}, {"record_type": None}),
    ],
)
def test_unsupported_schema_is_reported_but_the_record_still_loads(header, context):
    event, issues = load({**header, **FLAT})
    assert [(i.stage, i.code, i.context) for i in issues] == [
        ("load", "unsupported_schema", context)
    ]
    assert event.packet_id == 3
    assert event.src_port == 51234


def test_absent_schema_version_and_record_type_are_accepted():
    _, issues = load(FLAT)
    assert issues == []


def test_flat_event_builds_network_and_transport():
    event, issues = load(FLAT)
    assert issues == []
    assert event.network == Ipv4Info(
        protocol="IPv4", src_ip="10.0.0.1", dst_ip="10.0.0.2", protocol_name="tcp"
    )
    assert event.transport == TcpInfo(src_port=51234, dst_port=80)
    assert event.event_type == "tcp_segment"


def test_flat_event_uses_transport_protocol_when_protocol_is_not_tcp_or_udp():
    record = {**FLAT, "protocol": "IPv4", "transport_protocol": "Udp"}
    event, issues = load(record)
    assert issues == []
    assert event.transport == UdpInfo(src_port=51234, dst_port=80)


def test_flat_event_without_a_transport_protocol_has_no_transport():
    event, issues = load({**FLAT, "protocol": "ICMP"})
    assert issues == []
    assert event.network.src_ip == "10.0.0.1"
    assert event.transport is None
    assert event.event_type == "network_only"


def test_flat_event_with_one_address_still_builds_network():
    record = {key: value for key, value in FLAT.items() if key != "src_ip"}
    event, _ = load(record)
    assert (event.network.src_ip, event.network.dst_ip) == (None, "10.0.0.2")


def test_flat_fields_with_wrong_types_are_reported_by_their_top_level_key():
    event, issues = load({**FLAT, "src_ip": 10, "src_port": "80", "dst_port": 70000})
    assert invalid_fields(issues) == ["src_ip", "src_port"]
    assert event.network.src_ip is None
    assert event.transport == TcpInfo(src_port=None, dst_port=70000)


def test_nested_blocks_win_over_flat_fields():
    record = {
        **FLAT,
        "network": {"protocol": "IPv4", "src_ip": "192.168.0.1"},
        "transport": {"protocol": "UDP", "src_port": 1},
    }
    event, issues = load(record)
    assert issues == []
    assert event.network == Ipv4Info(protocol="IPv4", src_ip="192.168.0.1")
    assert event.transport == UdpInfo(src_port=1)


def test_derived_and_unknown_top_level_keys_are_ignored():
    record = {
        **FLAT,
        "event_type": 5,
        "timestamp_iso": ["not", "a", "date"],
        "application_protocol": {"x": 1},
        "something_else": "x",
    }
    event, issues = load(record)
    assert issues == []
    assert event.application_protocol == "UNKNOWN"


def test_v1_event_loads_with_unsupported_schema():
    v1 = {
        "schema_version": 1,
        "packet_id": 2,
        "timestamp": 1759000001.107919,
        "timestamp_iso": "2025-09-27T19:06:41.107919+00:00",
        "event_type": "http_request",
        "network_protocol": "IPv4",
        "transport_protocol": "TCP",
        "application_protocol": "HTTP",
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "src_port": 51234,
        "dst_port": 80,
        "network": {"protocol": "IPv4", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "ttl": 64},
        "transport": {
            "protocol": "TCP",
            "src_port": 51234,
            "dst_port": 80,
            "flags": {"psh": True, "ack": True},
            "flags_list": ["PSH", "ACK"],
            "payload_length": 187,
        },
        "application": {
            "protocol": "HTTP",
            "detection": {"method": "port+payload", "confidence": 1.0, "scores": {"HTTP": 1.0}},
            "http": {"method": "GET", "headers": {"host": "example.com"}},
        },
        "payload": {"length": 187, "sha256": "ab" * 32, "preview": "GET / HTTP/1.1"},
        "errors": [],
    }
    event, issues = load(v1)
    assert [(i.code, i.context) for i in issues] == [("unsupported_schema", {"schema_version": 1})]
    assert (event.src_ip, event.dst_ip, event.src_port, event.dst_port) == (
        "10.0.0.1",
        "10.0.0.2",
        51234,
        80,
    )
    assert event.transport.flags == TcpFlags(psh=True, ack=True)
    assert event.application.protocol == "HTTP"
    assert event.application.message is None
    assert event.application.detection.scores == {"HTTP": 1.0}
    assert event.payload == Payload(length=187, sha256="ab" * 32, preview="GET / HTTP/1.1")
    assert event.event_type == "http_unparsed"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_codec_decode.py -q`
Expected: collection error `ImportError: cannot import name 'decode_packet' from 'ids.codec'`.

- [ ] **Step 3: Write the implementation**

Replace the whole of `ids/codec.py` with:

```python
from __future__ import annotations

import base64
import dataclasses
import json
import math
import types
import typing
from collections.abc import Callable
from datetime import datetime, timezone
from enum import Enum
from functools import cache
from typing import Any, TypeVar, Union

from .issues import Issue, Issues
from .model.event import MessageEvent, PacketEvent
from .model.flow import FlowRecord
from .model.packet import Ipv4Info, TcpInfo, UdpInfo

SCHEMA_VERSION = 2

T = TypeVar("T")
Loader = Callable[[object, Issues, str], object]

_INVALID = object()
_NONE_TYPE = type(None)
_TRANSPORTS: dict[str, type[TcpInfo] | type[UdpInfo]] = {"tcp": TcpInfo, "udp": UdpInfo}


@dataclasses.dataclass(frozen=True, slots=True)
class _Field:
    name: str
    key: str
    is_bytes: bool
    load: Loader


def iso_timestamp(value: float | None) -> str | None:
    if value is None:
        return None
    try:
        moment = datetime.fromtimestamp(value, timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None
    return moment.isoformat(timespec="microseconds").replace("+00:00", "Z")


def to_jsonable(obj: object) -> object:
    kind = type(obj)
    if obj is None or kind is str or kind is int or kind is float or kind is bool:
        return obj
    if isinstance(obj, Enum):
        return obj.value
    if dataclasses.is_dataclass(kind):
        return _dump_fields(obj, {})
    if kind is list or kind is tuple:
        return [to_jsonable(item) for item in obj]
    if kind is dict:
        out: dict[str, object] = {}
        for key, value in obj.items():
            if type(key) is not str:
                raise TypeError(f"dict key {key!r} is not a str")
            out[key] = to_jsonable(value)
        return out
    raise TypeError(f"{kind.__name__} value {obj!r} is not JSON serialisable")


def _dump_fields(obj: object, out: dict[str, object]) -> dict[str, object]:
    for spec in _fields(type(obj)):
        value = getattr(obj, spec.name)
        if spec.is_bytes:
            out[spec.key] = None if value is None else base64.b64encode(value).decode("ascii")
        else:
            out[spec.key] = to_jsonable(value)
    return out


def encode(record: PacketEvent | MessageEvent | FlowRecord) -> dict[str, object]:
    if isinstance(record, PacketEvent):
        return _encode_packet(record)
    if isinstance(record, (MessageEvent, FlowRecord)):
        head: dict[str, object] = {
            "schema_version": SCHEMA_VERSION,
            "record_type": record.RECORD_TYPE,
        }
        return _dump_fields(record, head)
    raise TypeError(f"cannot encode {type(record).__name__}")


def _encode_packet(event: PacketEvent) -> dict[str, object]:
    return {
        "schema_version": SCHEMA_VERSION,
        "record_type": PacketEvent.RECORD_TYPE,
        "packet_id": to_jsonable(event.packet_id),
        "timestamp": to_jsonable(event.timestamp),
        "timestamp_iso": iso_timestamp(event.timestamp),
        "event_type": event.event_type,
        "src_ip": event.src_ip,
        "dst_ip": event.dst_ip,
        "src_port": event.src_port,
        "dst_port": event.dst_port,
        "protocol": event.protocol,
        "application_protocol": event.application_protocol,
        "preprocess_status": to_jsonable(event.preprocess_status),
        "processing_action": to_jsonable(event.processing_action),
        "reason": to_jsonable(event.reason),
        "flow": to_jsonable(event.flow),
        "capture": to_jsonable(event.capture),
        "link": to_jsonable(event.link),
        "network": to_jsonable(event.network),
        "transport": to_jsonable(event.transport),
        "application": to_jsonable(event.application),
        "payload": to_jsonable(event.payload),
        "decoded": to_jsonable(event.decoded),
        "normalized": to_jsonable(event.normalized),
        "issues": to_jsonable(event.issues),
    }


def encode_line(record: PacketEvent | MessageEvent | FlowRecord) -> str:
    return json.dumps(encode(record), ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def from_jsonable(cls: type[T], obj: object, issues: Issues, path: str) -> T | None:
    if not isinstance(obj, dict):
        _invalid(issues, path, cls.__name__, obj)
        return None
    return _load_object(cls, obj, issues, path)


def decode_packet(obj: object) -> tuple[PacketEvent, list[Issue]]:
    issues = Issues("load")
    if not isinstance(obj, dict):
        _invalid(issues, "", "object", obj)
        return PacketEvent(), issues.records
    if "schema_version" in obj:
        version = obj["schema_version"]
        if type(version) is not int or version != SCHEMA_VERSION:
            issues.add(
                "unsupported_schema",
                f"schema_version {version!r} is not supported",
                schema_version=version,
            )
    if "record_type" in obj:
        record_type = obj["record_type"]
        if record_type != PacketEvent.RECORD_TYPE:
            issues.add(
                "unsupported_schema",
                f"record_type {record_type!r} is not a packet record",
                record_type=record_type,
            )
    event = _load_object(PacketEvent, obj, issues, "")
    if obj.get("network") is None or obj.get("transport") is None:
        _flat_fallback(event, obj, issues)
    return event, issues.records


def _flat_fallback(event: PacketEvent, obj: dict[str, object], issues: Issues) -> None:
    protocol = _flat(obj, "protocol", _load_str, issues)
    if obj.get("network") is None:
        src_ip = _flat(obj, "src_ip", _load_str, issues)
        dst_ip = _flat(obj, "dst_ip", _load_str, issues)
        if src_ip is not None or dst_ip is not None:
            event.network = Ipv4Info(
                protocol="IPv4", src_ip=src_ip, dst_ip=dst_ip, protocol_name=protocol
            )
    if obj.get("transport") is None:
        info = _TRANSPORTS.get(protocol.casefold()) if protocol is not None else None
        if info is None:
            name = _flat(obj, "transport_protocol", _load_str, issues)
            info = _TRANSPORTS.get(name.casefold()) if name is not None else None
        if info is not None:
            event.transport = info(
                src_port=_flat(obj, "src_port", _load_int, issues),
                dst_port=_flat(obj, "dst_port", _load_int, issues),
            )


def _flat(obj: dict[str, object], key: str, load: Loader, issues: Issues) -> Any:
    value = obj.get(key)
    if value is None:
        return None
    loaded = load(value, issues, key)
    return None if loaded is _INVALID else loaded


def _load_object(cls: type[T], obj: dict[str, object], issues: Issues, path: str) -> T:
    prefix = f"{path}." if path else ""
    kwargs: dict[str, object] = {}
    for spec in _fields(cls):
        if spec.key in obj:
            loaded = spec.load(obj[spec.key], issues, prefix + spec.key)
            if loaded is not _INVALID:
                kwargs[spec.name] = loaded
    return cls(**kwargs)


def _invalid(issues: Issues, path: str, expected: str, value: object) -> object:
    got = type(value).__name__
    issues.add(
        "invalid_type",
        f"{path or 'record'}: expected {expected}, got {got}",
        field=path,
        expected=expected,
        got=got,
    )
    return _INVALID


def _load_str(value: object, issues: Issues, path: str) -> object:
    return value if type(value) is str else _invalid(issues, path, "str", value)


def _load_int(value: object, issues: Issues, path: str) -> object:
    return value if type(value) is int else _invalid(issues, path, "int", value)


def _load_bool(value: object, issues: Issues, path: str) -> object:
    return value if type(value) is bool else _invalid(issues, path, "bool", value)


def _load_float(value: object, issues: Issues, path: str) -> object:
    if type(value) is float:
        if math.isfinite(value):
            return value
    elif type(value) is int:
        try:
            return float(value)
        except OverflowError:
            pass
    return _invalid(issues, path, "float", value)


def _load_b64(value: object, issues: Issues, path: str) -> object:
    if type(value) is str:
        try:
            return base64.b64decode(value, validate=True)
        except ValueError:
            pass
    return _invalid(issues, path, "base64 str", value)


def _load_timestamp(value: object, issues: Issues, path: str) -> object:
    if type(value) is not str:
        return _load_float(value, issues, path)
    text = value.strip()
    if text[-1:] in ("Z", "z"):
        text = text[:-1] + "+00:00"
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return _invalid(issues, path, "float or ISO-8601 str", value)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.timestamp()


def _load_any(value: object, issues: Issues, path: str) -> object:
    return value if _is_json(value) else _invalid(issues, path, "JSON value", value)


def _is_json(value: object) -> bool:
    stack = [value]
    while stack:
        item = stack.pop()
        kind = type(item)
        if kind is float:
            if not math.isfinite(item):
                return False
        elif kind is list:
            stack.extend(item)
        elif kind is dict:
            for key, child in item.items():
                if type(key) is not str:
                    return False
                stack.append(child)
        elif not (item is None or kind is str or kind is int or kind is bool):
            return False
    return True


def _optional(inner: Loader) -> Loader:
    def load(value: object, issues: Issues, path: str) -> object:
        return None if value is None else inner(value, issues, path)

    return load


def _list_of(item: Loader) -> Loader:
    def load(value: object, issues: Issues, path: str) -> object:
        if type(value) is not list:
            return _invalid(issues, path, "list", value)
        out = []
        for index, element in enumerate(value):
            loaded = item(element, issues, f"{path}[{index}]")
            if loaded is not _INVALID:
                out.append(loaded)
        return out

    return load


def _dict_of(item: Loader) -> Loader:
    def load(value: object, issues: Issues, path: str) -> object:
        if type(value) is not dict:
            return _invalid(issues, path, "object", value)
        out = {}
        for key, element in value.items():
            if type(key) is not str:
                _invalid(issues, path, "str key", key)
                continue
            loaded = item(element, issues, f"{path}.{key}")
            if loaded is not _INVALID:
                out[key] = loaded
        return out

    return load


def _enum_of(cls: type[Enum]) -> Loader:
    def load(value: object, issues: Issues, path: str) -> object:
        if type(value) is str:
            try:
                return cls(value)
            except ValueError:
                pass
        return _invalid(issues, path, cls.__name__, value)

    return load


def _dataclass_of(cls: type) -> Loader:
    def load(value: object, issues: Issues, path: str) -> object:
        if type(value) is not dict:
            return _invalid(issues, path, cls.__name__, value)
        return _load_object(cls, value, issues, path)

    return load


def _tagged_union_of(members: tuple[type, ...]) -> Loader:
    tags = [(cls.TAG[0], cls.TAG[1].casefold(), cls) for cls in members]
    expected = " | ".join(cls.__name__ for cls in members)

    def load(value: object, issues: Issues, path: str) -> object:
        if type(value) is dict:
            for key, tag, cls in tags:
                found = value.get(key)
                if type(found) is str and found.casefold() == tag:
                    return _load_object(cls, value, issues, path)
        return _invalid(issues, path, expected, value)

    return load


_SCALARS: dict[object, Loader] = {
    str: _load_str,
    int: _load_int,
    float: _load_float,
    bool: _load_bool,
    bytes: _load_b64,
}

_FIELD_LOADERS: dict[tuple[type, str], Loader] = {
    (PacketEvent, "timestamp"): _optional(_load_timestamp),
}


def _loader(hint: object) -> Loader:
    if hint is object or hint is Any:
        return _load_any
    origin = typing.get_origin(hint)
    if origin is Union or origin is types.UnionType:
        args = typing.get_args(hint)
        members = tuple(arg for arg in args if arg is not _NONE_TYPE)
        if len(members) == 1:
            inner = _loader(members[0])
        elif all(dataclasses.is_dataclass(member) for member in members):
            inner = _tagged_union_of(members)
        else:
            raise TypeError(f"unsupported union {hint!r}")
        return _optional(inner) if len(members) < len(args) else inner
    if origin is list:
        return _list_of(_loader(typing.get_args(hint)[0]))
    if origin is dict:
        key, item = typing.get_args(hint)
        if key is not str:
            raise TypeError(f"unsupported dict key type {key!r}")
        return _dict_of(_loader(item))
    if hint in _SCALARS:
        return _SCALARS[hint]
    if isinstance(hint, type) and issubclass(hint, Enum):
        return _enum_of(hint)
    if isinstance(hint, type) and dataclasses.is_dataclass(hint):
        return _dataclass_of(hint)
    raise TypeError(f"unsupported field type {hint!r}")


def _is_bytes(hint: object) -> bool:
    return hint is bytes or bytes in typing.get_args(hint)


@cache
def _fields(cls: type) -> tuple[_Field, ...]:
    hints = typing.get_type_hints(cls)
    specs = []
    for item in dataclasses.fields(cls):
        hint = hints[item.name]
        key = item.metadata.get("json", item.name)
        is_bytes = _is_bytes(hint)
        if is_bytes:
            key = f"{key}_b64"
        load = _FIELD_LOADERS.get((cls, item.name)) or _loader(hint)
        specs.append(_Field(item.name, key, is_bytes, load))
    return tuple(specs)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_codec_decode.py -q`
Expected: PASS — 59 tests, exit status 0.

Run: `uv run pytest -q`
Expected: PASS — 330 tests, exit status 0.

Run (Python 3.10 floor; uses a throwaway environment and leaves `.venv` alone — uv downloads CPython 3.10 if it is not installed): `uv run --isolated --python 3.10 --with pytest python -m pytest -q tests/test_issues.py tests/test_model.py tests/test_payload.py tests/test_codec.py tests/test_codec_decode.py`
Expected: PASS — 151 tests, exit status 0.

Run: `uv run ruff check ids/codec.py tests/test_codec_decode.py && uv run ruff format --check ids/codec.py tests/test_codec_decode.py`
Expected: `All checks passed!`, `2 files already formatted`.

- [ ] **Step 5: Commit**

```bash
git add ids/codec.py tests/test_codec_decode.py
git commit -m "feat: add tolerant schema v2 decoder"
```

## Self-review (done while writing)

- **Spec coverage (slice 1a):** spec §2/§13.1 rename + console script → Task 1; §6.1 single `Issue` type, `ParseError`, scoped collector → Task 2; §6.2 records and derived properties (`event_type`, 5-tuple, `protocol`, `is_tcp`), case-insensitive `header()` → Task 3; §4 "payload bytes dropped" fix (`Payload.data` up to `max_payload_bytes`) → Task 4; §6.3 schema v2 JSON (key set never varies, `*_b64`, top-level derived fields, `TypeError` on non-JSON) → Task 5; §6.4 tolerant decode (defaults, `invalid_type`, `unsupported_schema`, never raises, round trip) + §8.2 ISO timestamps on load → Task 6; §14 Python 3.10 risk → manual base64 validation via `validate=True`, `Z` handling, 3.10 test run in Task 6. Contract §0 green rule: every task ends with the full suite green (179 → 187 → 225 → 243 → 271 → 330 tests).
- **Placeholder scan:** every code step carries the complete file; no "similar to", TBD or unstated helpers. The only non-code instructions are one-line substitutions with the resulting line shown.
- **Type consistency:** names and signatures match `docs/plans/2026-10-10-interfaces.md` §2–§5 verbatim (`jsonable`, `Issue`, `ParseError`, `Issues.add/scoped/capture`, every §3 class/field, `sha256_hex`, `looks_binary`, `make_payload(data, *, max_bytes=65535, preview_limit=256)`, `SCHEMA_VERSION`, `to_jsonable`, `encode`, `encode_line`, `from_jsonable(cls, obj, issues, path)`, `decode_packet(obj)`). Additions live only in plan-1a modules: `ids.codec.iso_timestamp`, private codec helpers, private `ids.payload._render`, test helper `tests/codec_samples.py`.

## Contract refinements decided in this plan

These fill gaps the contract leaves open; plans 1c and 3 rely on them.

| Topic | Decision |
|---|---|
| `invalid_type` context | `{"field": <path>, "expected": <str>, "got": <Python type name of the JSON value>}`; raw value not stored |
| ISO-8601 `timestamp` in loaded events | converted to epoch float by `decode_packet` (no issue); unparsable → `invalid_type` |
| `timestamp_iso` format | `ids.codec.iso_timestamp`: microseconds, `Z` suffix (e.g. `2025-09-27T19:06:40.100000Z`); plan 3 reuses it for `normalized.timestamp_iso` |
| Union tag match | case-insensitive (`casefold`), raw text kept in the tag field |
| Fallback trigger | `obj.get("network") is None` / `obj.get("transport") is None` (absent or `null`); network needs ≥1 non-null top-level IP; transport checks `protocol` then `transport_protocol` |
| Bad container elements | dropped individually, each with its own issue |
| Non-finite floats / huge ints | rejected as `invalid_type` on load |
| `schema_version` | must be the int `2`; `"2"`, `2.0`, `true` → `unsupported_schema` |
| Load issues | returned only; not appended to `event.issues` by the codec |
| `describe` | kept for legacy callers; preview now uses the full-data binary decision; `render` removed |
| `pyproject.toml` version | bumped to `0.2.0` together with `ids.__version__` |
