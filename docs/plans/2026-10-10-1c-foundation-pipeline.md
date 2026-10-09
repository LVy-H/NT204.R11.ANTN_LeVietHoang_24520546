# Foundation 1c: Packet Parser, Sources, Runner, Sink, Stats, CLI — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the legacy dict pipeline (`ids/pipeline.py`, `ids/event.py`, `ids/errors.py`, `ids/logger.py`, `ids/stats.py`, `ids/cli.py`, `ids/capture/*`) with the typed `PacketParser`, capture/events sources, stage `Runner`, `JsonlSink`, `Stats` and CLI from the shared contract, then move the capture-parser cases to `TEST/capture-parser/`.

**Architecture:** Sources yield `RawPacket | PacketEvent | Tick`. `PacketParser.parse` turns a `RawPacket` into a `PacketEvent` and never raises. The `Runner` sends every record through an ordered list of stages (empty in this plan; plans 2–4 add stages), applies drop / unknown-policy outcomes and writes through `JsonlSink` (one `codec.encode_line` per record). `Stats` counts every outcome. `ids/cli.py` wires source → parser → runner → sink.

**Tech Stack:** Python ≥ 3.10 stdlib (`argparse`, `json`, `struct`, `dataclasses`, `collections`), scapy (live capture only), pytest, ruff, uv.

**Spec:** `docs/specs/2026-10-10-decoder-preprocessor-flow-tracker.md` (§4, §5, §6.1, §10, §11.2) and `docs/plans/2026-10-10-interfaces.md` (§0 green rule, §2, §3, §4, §5, §6, §7, §8, §9). Read both before starting.

## Global Constraints

- `requires-python = ">=3.10"`: no 3.11+ APIs (`tomllib`, `datetime.UTC`, `typing.Self`, `binascii` `strict_mode`).
- Every module, including test helpers, starts with `from __future__ import annotations`.
- No new runtime dependency. Scapy is imported lazily, only by `ids/capture/live.py`.
- Names, types and signatures from interfaces §6 (`ParserConfig`, `PacketParser`), §7 (`CaptureSource`, `PcapSource`, `LiveSource`, `EventsSource`, `list_interfaces`), §8 (`Emit`, `Stage`, `UNKNOWN_POLICIES`, `Runner`, `JsonlSink`, `Stats`) and §9 (`build_parser`, `build_stages`, `main`, `non_negative_int`, `positive_int`, `non_negative_float`) are used verbatim. Helpers this plan adds stay private to their module or are extra names that do not change a contract item.
- `LiveSource` in this plan has no `tick` parameter; plan 4 adds it together with `Tick` emission.
- Exit codes: 0 ok, 1 runtime error, 2 usage (argparse), 130 interrupted.
- Lint: `uv run ruff check <paths> && uv run ruff format --check <paths>` (line-length 100; rules E, F, W, I, UP, B, C4, SIM, RUF; ignored SIM108, SIM115, BLE001).
- One task = one commit; messages lower-case conventional (`feat: …`, `refactor: …`, `test: …`, `docs: …`).
- Repo user-facing docs (`README.md`, `TEST/**/README.md`) are Vietnamese, short, plain.
- **Green rule.** On entry (after plan 1b) `tests/test_pipeline.py` and `tests/test_cli.py` fail because the legacy pipeline calls parsers whose types changed. Tasks 1–5 run only the test files they own (plus the already-green suites they touch). **The Task 6 commit (`feat: wire the cli onto the typed runner`) restores a fully green `uv run pytest -q`**; Tasks 7 and 8 keep it green and run the full suite.

## Review Focus

1. **pcapng interface block shorter than 8 bytes** — today `_interface` calls `struct.unpack_from` on it and the run dies with `struct.error`. Expected: a warning, the block is skipped, reading continues. Test: Task 1 `test_pcapng_short_interface_block_warns_instead_of_crashing`.
2. **`--output` in a directory that does not exist** — the legacy CLI opened the writer outside its `try` and crashed with a traceback. Expected: `error: …` on stderr, exit 1. Test: Task 6 `test_cli_reports_an_unwritable_output_path`.
3. **`NaN` / `Infinity` in an events line** — `json.loads` accepts them by default, and then `encode_line(..., allow_nan=False)` raises inside the sink and kills the run. Expected: that line becomes an `invalid_json` stub and the run continues. Tests: Task 7 `test_nan_and_infinity_are_invalid_json` and `test_cli_events_with_nan_line_completes`.
4. **Events file with invalid UTF-8 bytes or a UTF-8 BOM** — text-mode reading would raise `UnicodeDecodeError` partway through the file. Expected: the BOM line loads, the bad line becomes an `invalid_json` stub, later lines still load. Test: Task 7 `test_invalid_utf8_line_is_a_stub_and_bom_is_accepted`.
5. **A stage that raises in `tick` or `flush`** (e.g. a flow tracker bug at end of input) — there is no record to attach the issue to. Expected: the other stages still tick/flush, their output is still written, and the failure is counted in `stats.stage_errors`. Test: Task 4 `test_tick_and_flush_failures_are_isolated_and_counted`.

## Decisions this plan fixes (contract ambiguities)

- **Emission timing.** `Runner` collects what a stage emits during one `process`/`tick`/`flush` call and dispatches it as soon as that call returns: `FlowRecord` (and any non-message record) → written, `MessageEvent` → through every stage from index 0, then written. This happens before the next stage runs and before the triggering packet is written, so the output order is the one contract §8 describes. Two things follow: a stage is never re-entered by its own emission, and a sink `OSError` is never mistaken for a stage failure.
- **Stage failures outside `process`.** `tick`/`flush` exceptions are counted with `Stats.stage_error(stage, "tick" | "flush")` → `to_dict()["stage_errors"]`.
- **Transport is parsed only for IP protocols 6 and 17**, as the legacy pipeline did. ICMP and other protocols stay `network_only` with no issue; the Preprocessor reports them as unsupported.
- **Fallback event** (exception outside the guarded steps): `PacketEvent(packet_id, timestamp, capture=CaptureInfo(...), issues=[Issue("pipeline", "internal_error", ...)])` with `payload = None`. No fake hash.
- **`EventsSource` clears stage outputs on load.** It resets `decoded`, `normalized`, `preprocess_status`, `processing_action`, `reason`, `flow`, and drops issues whose stage is `decoder`, `preprocess` or `flow`. Those stages run again, so a re-run never doubles issues or inherits a verdict (a loaded `"processing_action": "drop"` is not dropped before the Preprocessor).
- **`EventsSource` line numbering.** `packet_id` of an `invalid_json` stub = 1-based physical line number, blank lines included. One warning per skipped flow/message line: `line <n>: skipped record_type '<type>'`.
- **CLI stderr layout.** `source: <source> <origin>` (suppressed by `-q`); up to 3 `warning: …` lines plus `warning: N more warnings not shown`; `wrote <records> records from <packets> packets (<d> dropped, <s> skipped, <i> with issues)` (suppressed by `-q`); with `--stats`, `json.dumps(stats.to_dict() + {"source": source.describe()}, indent=2)`. The legacy 10 000-packet progress line is dropped: the runner has no per-item hook, and `--stats` already gives the totals.
- **`--count` uses `positive_int`** (0 is rejected). `--capture-idle-timeout 0` means "never stop", as with the legacy flag.
- **`Stats.to_dict()` key order:** `packets_seen, records_written{packet,message,flow}, dropped, skipped, packets_with_issues, first_timestamp, last_timestamp, event_types, protocols, application_protocols, detection_methods, issue_codes, preprocess_status, processing_action, flow_end_reasons, messages{complete,incomplete}, stage_errors`, then `Stats.extra` merged at top level.

## File Structure

| Path | Task | Responsibility |
|---|---|---|
| `ids/capture/base.py` | 1 (rewrite) | `CaptureSource` protocol, `DLT_*` constants, `LINKTYPE_NAMES`, `linktype_name` |
| `ids/capture/pcap.py` | 1 (rewrite) | `PcapSource`: pcap/pcapng reader yielding `RawPacket`; file format errors → `ParseError("malformed_header")` |
| `ids/capture/live.py` | 1 (rewrite) | `LiveSource`, `list_interfaces`, `scapy_module`, per-packet linktype |
| `ids/capture/__init__.py` | 1 (rewrite), 7 | exports; `EventsSource` added in 7 |
| `ids/capture/events.py` | 7 (create) | `EventsSource`: schema v2 JSONL (`-` = stdin) |
| `ids/parsers/__init__.py` | 2 (rewrite) | `ParserConfig`, `PacketParser` |
| `ids/stats.py` | 3 (rewrite) | `Stats` |
| `ids/pipeline.py` | 2 (delete legacy), 4 (create) | `Emit`, `Stage`, `Sink`, `UNKNOWN_POLICIES`, `Runner` |
| `ids/sink.py` | 5 (create) | `JsonlSink` |
| `ids/cli.py` | 6 (rewrite), 7 | flags, numeric helpers, `build_stages`, `main` |
| `ids/event.py`, `ids/errors.py`, `ids/payload.py:describe` | 2 (delete) | legacy, last caller removed in 2 |
| `ids/logger.py` | 6 (delete) | legacy, last caller removed in 6 |
| `tests/fake_scapy.py` | 1 (create) | fake `scapy.all` used by `test_live.py` and `test_cli.py` |
| `tests/test_capture.py`, `tests/test_live.py` | 1 (migrate) | source tests |
| `tests/test_pipeline.py` | 2 (migrate), 8 | end-to-end `PcapSource` + `PacketParser` over the fixtures |
| `tests/test_stats.py` | 3 (create) | |
| `tests/test_runner.py` | 4 (create), 8 | |
| `tests/test_sink.py` | 5 (create) | |
| `tests/test_cli.py` | 6 (migrate), 7, 8 | |
| `tests/test_events_source.py` | 7 (create), 8 | |
| `README.md` | 6, 7, 8 | flag table rows, `--events` example, TEST paths |
| `TEST/capture-parser/**`, `TEST/README.md`, `TEST/run_cases.sh` | 8 | move + index + runner script |

`main.py` keeps `from ids.cli import main` (set by plan 1a) and is not edited.

---

### Task 1: Typed pcap and live capture sources

**Files:**
- Modify (full rewrite): `ids/capture/base.py`, `ids/capture/pcap.py`, `ids/capture/live.py`, `ids/capture/__init__.py`
- Create: `tests/fake_scapy.py`
- Test (full rewrite): `tests/test_capture.py`, `tests/test_live.py`

**Interfaces:**
- Consumes: `ids.model.RawPacket`, `ids.model.PacketEvent`, `ids.model.Tick` (plan 1a, contract §3.1/§3.6); `ids.issues.ParseError` (contract §2).
- Produces:
  - `ids.capture.base`: `DLT_NULL=0, DLT_EN10MB=1, DLT_RAW_BSD=12, DLT_RAW=101, DLT_IEEE802_11=105, DLT_LOOP=108, DLT_LINUX_SLL=113, DLT_IPV4=228, DLT_IPV6=229, DLT_LINUX_SLL2=276`, `LINKTYPE_NAMES: dict[int, str]`, `linktype_name(linktype: int | None) -> str | None`, `class CaptureSource(Protocol)` with `source: str`, `origin: str`, `warnings: list[str]`, `items() -> Iterator[RawPacket | PacketEvent | Tick]`, `describe() -> dict[str, object]`, `close() -> None`. (`ids/parsers/link.py` and `tests/test_link.py` from plan 1b import the `DLT_*` constants from here.)
  - `ids.capture.pcap.PcapSource(path: str | Path, *, count: int | None = None)`; attributes `source="pcap"`, `origin: str`, `format: str | None`, `linktype: int | None`, `snaplen: int | None`, `warnings: list[str]`; `items() -> Iterator[RawPacket]` raises `ParseError("malformed_header", ...)` for an empty file, unknown magic or truncated global header, and `OSError` for an unreadable path.
  - `ids.capture.live.LiveSource(interface: str, *, bpf_filter: str | None = None, count: int | None = None, promiscuous: bool = True, capture_idle_timeout: float | None = None, poll_interval: float = 1.0)`; `items() -> Iterator[RawPacket]` raises `RuntimeError` for unknown interface / missing permission / missing scapy. `PERMISSION_HINT: str`, `scapy_module() -> Any`, `list_interfaces() -> list[dict[str, object]]` (keys `name`, `description`, `mac`, `ips`).
  - `ids.capture` exports `CaptureSource`, `LiveSource`, `PcapSource`, `linktype_name`, `list_interfaces`.
  - `tests/fake_scapy.py`: `FakePacket(raw: bytes, timestamp: object)`, `FakeSocket`, `FakeInterface`, `FakeScapy(packets=(), interfaces=("lo", "eth0"), denied=False, reject_filter=False, layer2num=None)` with `.opened`, `.attempts`, `.sockets`, `.conf.l2types.layer2num`.

- [ ] **Step 1: Write the failing tests**

`tests/fake_scapy.py`:

```python
"""Stand-in for the parts of `scapy.all` that ids.capture.live uses."""

from __future__ import annotations

import time
from types import SimpleNamespace


class FakePacket:
    def __init__(self, raw: bytes, timestamp: object) -> None:
        self.raw = raw
        self.time = timestamp

    def __bytes__(self) -> bytes:
        return self.raw


class FakeSocket:
    def __init__(self, packets: list[FakePacket]) -> None:
        self.packets = list(packets)
        self.closed = False

    def select(self, sockets: list[FakeSocket], timeout: float) -> list[FakeSocket]:
        time.sleep(0.01)
        return [self] if self.packets else []

    def recv(self) -> FakePacket | None:
        return self.packets.pop(0) if self.packets else None

    def close(self) -> None:
        self.closed = True


class FakeInterface:
    def __init__(self, description: str, mac: str, ips: dict[int, list[str]]) -> None:
        self.description = description
        self.mac = mac
        self.ips = ips


class FakeScapy:
    def __init__(
        self,
        packets: tuple[FakePacket, ...] | list[FakePacket] = (),
        interfaces: tuple[str, ...] = ("lo", "eth0"),
        denied: bool = False,
        reject_filter: bool = False,
        layer2num: dict[type, int] | None = None,
    ) -> None:
        self.packets = list(packets)
        self.interfaces = list(interfaces)
        self.denied = denied
        self.reject_filter = reject_filter
        self.opened: list[dict[str, object]] = []
        self.attempts: list[str | None] = []
        self.sockets: list[FakeSocket] = []
        self.conf = SimpleNamespace(
            L2listen=self.listen,
            ifaces={
                "lo": FakeInterface("loopback", "00:00:00:00:00:00", {4: ["127.0.0.1"], 6: ["::1"]})
            },
            l2types=SimpleNamespace(layer2num=dict(layer2num or {})),
        )

    def listen(
        self, iface: str | None = None, filter: str | None = None, promisc: bool | None = None
    ) -> FakeSocket:
        self.attempts.append(filter)
        if self.denied:
            raise PermissionError(1, "Operation not permitted")
        if iface not in self.interfaces:
            raise OSError(f"no such interface {iface}")
        if filter and self.reject_filter and "badfilter" in filter:
            raise RuntimeError("filter compile failed")
        self.opened.append({"iface": iface, "filter": filter, "promisc": promisc})
        socket = FakeSocket(self.packets)
        self.sockets.append(socket)
        return socket

    def get_if_list(self) -> list[str]:
        return list(self.interfaces)
```

`tests/test_capture.py` (replaces the file):

```python
from __future__ import annotations

import struct

import pytest

from ids.capture.base import linktype_name
from ids.capture.pcap import PcapSource
from ids.issues import ParseError
from ids.model import RawPacket

TS = 1759000000
FRAME_A = bytes.fromhex("0200000000020200000000010800") + bytes.fromhex(
    "4500001c00010000400600000a0000010a000002"
)
FRAME_B = bytes.fromhex("0200000000020200000000010800") + bytes.fromhex(
    "4500001c00010000400600000a0000010a000003"
)


def classic(records, *, endian="<", divisor=1_000_000, linktype=1, snaplen=262144):
    magic = {
        ("<", 1_000_000): b"\xd4\xc3\xb2\xa1",
        (">", 1_000_000): b"\xa1\xb2\xc3\xd4",
        ("<", 1_000_000_000): b"\x4d\x3c\xb2\xa1",
        (">", 1_000_000_000): b"\xa1\xb2\x3c\x4d",
    }[(endian, divisor)]
    out = magic + struct.pack(endian + "HHiIII", 2, 4, 0, 0, snaplen, linktype)
    for seconds, fraction, data, captured in records:
        out += struct.pack(endian + "IIII", seconds, fraction, captured, len(data)) + data
    return out


def block(block_type, body, endian="<"):
    total = 12 + len(body)
    return struct.pack(endian + "II", block_type, total) + body + struct.pack(endian + "I", total)


def section_header(endian="<"):
    bom = b"\x1a\x2b\x3c\x4d" if endian == ">" else b"\x4d\x3c\x2b\x1a"
    return block(0x0A0D0D0A, bom + struct.pack(endian + "HHq", 1, 0, -1), endian)


def interface_description(linktype=1, snaplen=262144, tsresol=None, endian="<"):
    body = struct.pack(endian + "HHI", linktype, 0, snaplen)
    if tsresol is not None:
        body += struct.pack(endian + "HH", 9, 1) + bytes([tsresol]) + b"\x00" * 3
    return block(1, body, endian)


def enhanced_packet(data, timestamp, iface=0, endian="<"):
    body = struct.pack(
        endian + "IIIII", iface, timestamp >> 32, timestamp & 0xFFFFFFFF, len(data), len(data)
    )
    body += data + b"\x00" * (-len(data) % 4)
    return block(6, body, endian)


def write(tmp_path, raw, name="capture.pcap"):
    path = tmp_path / name
    path.write_bytes(raw)
    return path


def test_classic_little_endian(tmp_path):
    raw = classic([(TS, 250000, FRAME_A, len(FRAME_A)), (TS + 1, 500000, FRAME_B, len(FRAME_B))])
    source = PcapSource(write(tmp_path, raw))
    packets = list(source.items())
    assert source.format == "pcap"
    assert source.linktype == 1
    assert source.snaplen == 262144
    assert source.warnings == []
    assert [packet.packet_id for packet in packets] == [1, 2]
    assert packets[0].timestamp == pytest.approx(TS + 0.25)
    assert packets[1].timestamp == pytest.approx(TS + 1.5)
    assert packets[0].data == FRAME_A
    assert packets[0].original_length == len(FRAME_A)
    assert packets[0].truncated is False
    assert packets[0].source == "pcap"
    assert packets[0].origin == str(tmp_path / "capture.pcap")


def test_classic_big_endian(tmp_path):
    raw = classic([(TS, 250000, FRAME_A, len(FRAME_A))], endian=">")
    packets = list(PcapSource(write(tmp_path, raw)).items())
    assert packets[0].timestamp == pytest.approx(TS + 0.25)
    assert packets[0].data == FRAME_A


def test_classic_nanosecond_magic(tmp_path):
    raw = classic([(TS, 123456789, FRAME_A, len(FRAME_A))], divisor=1_000_000_000)
    packets = list(PcapSource(write(tmp_path, raw)).items())
    assert packets[0].timestamp == pytest.approx(TS + 0.123456789)


def test_truncated_record_stops_reading_and_warns(tmp_path):
    raw = classic([(TS, 0, FRAME_A, len(FRAME_A)), (TS + 1, 0, FRAME_B, 400)])
    source = PcapSource(write(tmp_path, raw))
    packets = list(source.items())
    assert len(packets) == 2
    assert packets[1].declared_capture_length == 400
    assert packets[1].truncated is True
    assert len(packets[1].data) == len(FRAME_B)
    assert any("declares 400 captured bytes" in warning for warning in source.warnings)


def test_classic_count_limit(tmp_path):
    raw = classic([(TS, 0, FRAME_A, len(FRAME_A))] * 5)
    assert len(list(PcapSource(write(tmp_path, raw), count=2).items())) == 2


def test_unknown_magic_is_a_malformed_header(tmp_path):
    with pytest.raises(ParseError) as caught:
        list(PcapSource(write(tmp_path, b"NOPE" + b"\x00" * 40)).items())
    assert caught.value.code == "malformed_header"
    assert caught.value.message == "unrecognised capture file format"
    assert caught.value.context == {"magic": "4e4f5045"}


def test_empty_file_is_a_malformed_header(tmp_path):
    with pytest.raises(ParseError) as caught:
        list(PcapSource(write(tmp_path, b"")).items())
    assert caught.value.code == "malformed_header"
    assert caught.value.message == "capture file is empty"


def test_truncated_global_header_is_a_malformed_header(tmp_path):
    with pytest.raises(ParseError) as caught:
        list(PcapSource(write(tmp_path, b"\xd4\xc3\xb2\xa1" + b"\x00" * 10)).items())
    assert caught.value.code == "malformed_header"
    assert caught.value.message == "truncated pcap global header"


def test_missing_file_raises_oserror(tmp_path):
    with pytest.raises(OSError):
        list(PcapSource(tmp_path / "missing.pcap").items())


def test_pcapng_little_endian(tmp_path):
    raw = (
        section_header()
        + interface_description()
        + enhanced_packet(FRAME_A, TS * 1_000_000 + 250000)
    )
    source = PcapSource(write(tmp_path, raw, "capture.pcapng"))
    packets = list(source.items())
    assert source.format == "pcapng"
    assert source.linktype == 1
    assert packets[0].timestamp == pytest.approx(TS + 0.25)
    assert packets[0].data == FRAME_A


def test_pcapng_big_endian(tmp_path):
    raw = (
        section_header(">")
        + interface_description(endian=">")
        + enhanced_packet(FRAME_A, TS * 1_000_000 + 250000, endian=">")
    )
    packets = list(PcapSource(write(tmp_path, raw, "capture.pcapng")).items())
    assert packets[0].timestamp == pytest.approx(TS + 0.25)
    assert packets[0].data == FRAME_A


def test_pcapng_custom_timestamp_resolution(tmp_path):
    raw = (
        section_header()
        + interface_description(tsresol=9)
        + enhanced_packet(FRAME_A, TS * 1_000_000_000 + 500000000)
    )
    packets = list(PcapSource(write(tmp_path, raw, "capture.pcapng")).items())
    assert packets[0].timestamp == pytest.approx(TS + 0.5)


def test_pcapng_binary_timestamp_resolution(tmp_path):
    raw = (
        section_header()
        + interface_description(tsresol=0x80 | 10)
        + enhanced_packet(FRAME_A, TS * 1024)
    )
    packets = list(PcapSource(write(tmp_path, raw, "capture.pcapng")).items())
    assert packets[0].timestamp == pytest.approx(TS)


def test_pcapng_simple_packet_block_has_no_timestamp(tmp_path):
    body = struct.pack("<I", len(FRAME_A)) + FRAME_A + b"\x00" * (-len(FRAME_A) % 4)
    raw = section_header() + interface_description() + block(3, body)
    packets = list(PcapSource(write(tmp_path, raw, "capture.pcapng")).items())
    assert packets[0].timestamp == 0.0
    assert packets[0].data == FRAME_A


def test_pcapng_packet_without_interface_is_skipped(tmp_path):
    raw = section_header() + enhanced_packet(FRAME_A, TS * 1_000_000)
    source = PcapSource(write(tmp_path, raw, "capture.pcapng"))
    assert list(source.items()) == []
    assert any("undefined interface" in warning for warning in source.warnings)


def test_pcapng_bad_block_length_warns(tmp_path):
    raw = section_header() + struct.pack("<II", 1, 3)
    source = PcapSource(write(tmp_path, raw, "capture.pcapng"))
    assert list(source.items()) == []
    assert any("invalid pcapng block length" in warning for warning in source.warnings)


def test_pcapng_short_interface_block_warns_instead_of_crashing(tmp_path):
    raw = (
        section_header()
        + block(1, b"\x01\x00\x00\x00")
        + interface_description()
        + enhanced_packet(FRAME_A, TS * 1_000_000)
    )
    source = PcapSource(write(tmp_path, raw, "capture.pcapng"))
    packets = list(source.items())
    assert source.warnings == ["truncated pcapng interface description block"]
    assert [packet.data for packet in packets] == [FRAME_A]


def test_describe_and_linktype_name():
    assert linktype_name(1) == "EN10MB"
    assert linktype_name(None) is None
    assert linktype_name(4242) == "UNKNOWN(4242)"
    described = PcapSource("missing.pcap", count=3).describe()
    assert described["source"] == "pcap"
    assert described["origin"].endswith("missing.pcap")
    assert described["count_limit"] == 3
    assert described["format"] is None


def test_rawpacket_helpers():
    packet = RawPacket(
        packet_id=7,
        timestamp=1.5,
        data=b"abc",
        linktype=1,
        source="pcap",
        origin="x.pcap",
        original_length=9,
        declared_capture_length=9,
    )
    assert packet.captured_length == 3
    assert packet.truncated is True
```

`tests/test_live.py` (replaces the file):

```python
from __future__ import annotations

import builtins

import pytest
from fake_scapy import FakePacket, FakeScapy

from ids.capture import live
from ids.capture.live import PERMISSION_HINT, LiveSource, list_interfaces

FRAME_A = bytes.fromhex("0200000000020200000000010800") + b"\x45" + b"\x00" * 41
FRAME_B = bytes.fromhex("0200000000020200000000010800") + b"\x45" + b"\x01" * 41


class FakeCookedPacket(FakePacket):
    """Stands in for a scapy layer class registered under another DLT."""


@pytest.fixture
def fake(monkeypatch):
    def install(**kwargs):
        module = FakeScapy(**kwargs)
        monkeypatch.setattr(live, "scapy_module", lambda: module)
        return module

    return install


def test_packets_are_converted_to_raw_packets(fake):
    module = fake(packets=[FakePacket(FRAME_A, 1759000000.5), FakePacket(FRAME_B, 1759000001.25)])
    packets = list(LiveSource("eth0", count=2).items())
    assert module.opened == [{"iface": "eth0", "filter": None, "promisc": True}]
    assert [packet.packet_id for packet in packets] == [1, 2]
    assert packets[0].timestamp == pytest.approx(1759000000.5)
    assert packets[0].data == FRAME_A
    assert packets[0].source == "live"
    assert packets[0].origin == "eth0"
    assert packets[0].linktype == 1
    assert packets[0].truncated is False
    assert module.sockets[0].closed is True


def test_linktype_comes_from_the_scapy_layer_class(fake):
    fake(
        packets=[FakeCookedPacket(FRAME_A, 1.0), FakePacket(FRAME_B, 2.0)],
        layer2num={FakeCookedPacket: 113},
    )
    packets = list(LiveSource("eth0", count=2).items())
    assert [packet.linktype for packet in packets] == [113, 1]


def test_count_limit_stops_the_loop(fake):
    fake(packets=[FakePacket(FRAME_A, 1.0), FakePacket(FRAME_B, 2.0), FakePacket(FRAME_A, 3.0)])
    assert len(list(LiveSource("eth0", count=2).items())) == 2


def test_unparseable_timestamp_falls_back_to_wall_clock(fake):
    fake(packets=[FakePacket(FRAME_A, None)])
    packet = next(LiveSource("eth0").items())
    assert packet.timestamp > 1759000000


def test_unknown_interface_is_rejected_before_opening(fake):
    module = fake(packets=[], interfaces=("lo", "eth0"))
    with pytest.raises(RuntimeError) as caught:
        list(LiveSource("wlan9").items())
    assert "wlan9" in str(caught.value)
    assert "lo, eth0" in str(caught.value)
    assert module.opened == []


def test_permission_error_is_explained(fake):
    fake(denied=True)
    with pytest.raises(RuntimeError) as caught:
        list(LiveSource("eth0").items())
    assert str(caught.value) == PERMISSION_HINT


def test_rejected_bpf_filter_falls_back_to_no_filter(fake):
    module = fake(packets=[FakePacket(FRAME_A, 1.0)], reject_filter=True)
    source = LiveSource("eth0", bpf_filter="badfilter", count=1)
    list(source.items())
    assert module.attempts == ["badfilter", None]
    assert [entry["filter"] for entry in module.opened] == [None]
    assert any("without a filter" in warning for warning in source.warnings)


def test_filter_and_promiscuity_are_forwarded(fake):
    module = fake(packets=[FakePacket(FRAME_A, 1.0)])
    list(LiveSource("eth0", bpf_filter="tcp port 80", promiscuous=False, count=1).items())
    assert module.opened == [{"iface": "eth0", "filter": "tcp port 80", "promisc": False}]


def test_capture_idle_timeout_stops_the_capture(fake):
    fake(packets=[])
    source = LiveSource("eth0", capture_idle_timeout=0.05, poll_interval=0.01)
    assert list(source.items()) == []
    assert any("without traffic" in warning for warning in source.warnings)


def test_describe_contains_the_interface(fake):
    fake(packets=[])
    described = LiveSource("eth0", bpf_filter="udp", count=5, capture_idle_timeout=2.0).describe()
    assert described["interface"] == "eth0"
    assert described["bpf_filter"] == "udp"
    assert described["count_limit"] == 5
    assert described["capture_idle_timeout"] == 2.0
    assert described["source"] == "live"


def test_list_interfaces_reports_addresses(fake):
    fake(interfaces=("lo",))
    assert list_interfaces() == [
        {
            "name": "lo",
            "description": "loopback",
            "mac": "00:00:00:00:00:00",
            "ips": ["127.0.0.1", "::1"],
        }
    ]


def test_scapy_module_reports_a_missing_dependency(monkeypatch):
    real_import = builtins.__import__

    def blocked(name, *args, **kwargs):
        if name.startswith("scapy"):
            raise ImportError("no scapy")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", blocked)
    with pytest.raises(RuntimeError) as caught:
        live.scapy_module()
    assert "scapy is required" in str(caught.value)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_capture.py tests/test_live.py -q`
Expected: FAIL — collection errors `ImportError: cannot import name 'PcapSource' from 'ids.capture.pcap'` and `ImportError: cannot import name 'LiveSource' from 'ids.capture.live'`.

- [ ] **Step 3: Implement the sources**

`ids/capture/base.py`:

```python
from __future__ import annotations

from collections.abc import Iterator
from typing import Protocol

from ..model import PacketEvent, RawPacket, Tick

DLT_NULL = 0
DLT_EN10MB = 1
DLT_RAW_BSD = 12
DLT_RAW = 101
DLT_IEEE802_11 = 105
DLT_LOOP = 108
DLT_LINUX_SLL = 113
DLT_IPV4 = 228
DLT_IPV6 = 229
DLT_LINUX_SLL2 = 276

LINKTYPE_NAMES = {
    DLT_NULL: "NULL",
    DLT_EN10MB: "EN10MB",
    DLT_RAW_BSD: "RAW",
    DLT_RAW: "RAW",
    DLT_IEEE802_11: "IEEE802_11",
    DLT_LOOP: "LOOP",
    DLT_LINUX_SLL: "LINUX_SLL",
    DLT_IPV4: "IPV4",
    DLT_IPV6: "IPV6",
    DLT_LINUX_SLL2: "LINUX_SLL2",
}


def linktype_name(linktype: int | None) -> str | None:
    if linktype is None:
        return None
    return LINKTYPE_NAMES.get(linktype, f"UNKNOWN({linktype})")


class CaptureSource(Protocol):
    source: str
    origin: str
    warnings: list[str]

    def items(self) -> Iterator[RawPacket | PacketEvent | Tick]: ...

    def describe(self) -> dict[str, object]: ...

    def close(self) -> None: ...
```

`ids/capture/pcap.py`:

```python
from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from ..issues import ParseError
from ..model import RawPacket
from .base import linktype_name

MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}

NG_SHB = b"\x0a\x0d\x0d\x0a"
NG_BOM_BE = b"\x1a\x2b\x3c\x4d"
NG_BOM_LE = b"\x4d\x3c\x2b\x1a"
NG_IDB = 1
NG_SPB = 3
NG_EPB = 6
NG_TSRESOL = 9
NG_IDB_MIN_BODY = 8


@dataclass(frozen=True, slots=True)
class _Record:
    timestamp: float
    linktype: int
    data: bytes
    original_length: int
    declared_capture_length: int


@dataclass(frozen=True, slots=True)
class _Interface:
    linktype: int
    snaplen: int
    divisor: int


def _options(data: bytes, endian: str) -> Iterator[tuple[int, bytes]]:
    offset = 0
    while offset + 4 <= len(data):
        code, length = struct.unpack_from(endian + "HH", data, offset)
        if code == 0:
            return
        yield code, data[offset + 4 : offset + 4 + length]
        offset += 4 + length + (-length % 4)


def _interface(body: bytes, endian: str) -> _Interface:
    linktype, _, snaplen = struct.unpack_from(endian + "HHI", body, 0)
    divisor = 1_000_000
    for code, value in _options(body[NG_IDB_MIN_BODY:], endian):
        if code == NG_TSRESOL and value:
            exponent = value[0] & 0x7F
            divisor = 2**exponent if value[0] & 0x80 else 10**exponent
    return _Interface(linktype, snaplen, divisor)


class PcapSource:
    source = "pcap"

    def __init__(self, path: str | Path, *, count: int | None = None) -> None:
        self.path = Path(path)
        self.origin = str(self.path)
        self.count = count
        self.linktype: int | None = None
        self.snaplen: int | None = None
        self.format: str | None = None
        self.warnings: list[str] = []

    def close(self) -> None:
        """The file handle lives inside items(); nothing else is held open."""

    def describe(self) -> dict[str, object]:
        return {
            "source": self.source,
            "origin": self.origin,
            "format": self.format,
            "linktype": self.linktype,
            "linktype_name": linktype_name(self.linktype),
            "snaplen": self.snaplen,
            "count_limit": self.count,
        }

    def items(self) -> Iterator[RawPacket]:
        with self.path.open("rb") as handle:
            magic = handle.read(4)
            if len(magic) < 4:
                raise ParseError("malformed_header", "capture file is empty", path=self.origin)
            if magic == NG_SHB:
                records = self._pcapng(handle, magic)
            elif magic in MAGIC:
                records = self._classic(handle, magic)
            else:
                raise ParseError(
                    "malformed_header", "unrecognised capture file format", magic=magic.hex()
                )
            for index, record in enumerate(records, start=1):
                if self.count is not None and index > self.count:
                    return
                if self.linktype is None:
                    self.linktype = record.linktype
                yield RawPacket(
                    packet_id=index,
                    timestamp=record.timestamp,
                    data=record.data,
                    linktype=record.linktype,
                    source=self.source,
                    origin=self.origin,
                    original_length=record.original_length,
                    declared_capture_length=record.declared_capture_length,
                )

    def _classic(self, handle: BinaryIO, magic: bytes) -> Iterator[_Record]:
        endian, divisor = MAGIC[magic]
        header = handle.read(20)
        if len(header) < 20:
            raise ParseError("malformed_header", "truncated pcap global header", path=self.origin)
        _, _, _, _, snaplen, network = struct.unpack(endian + "HHiIII", header)
        linktype = network & 0xFFFF
        self.format = "pcap"
        self.linktype = linktype
        self.snaplen = snaplen
        while True:
            raw = handle.read(16)
            if not raw:
                return
            if len(raw) < 16:
                self.warnings.append("truncated pcap record header at end of file")
                return
            ts_sec, ts_frac, cap_len, orig_len = struct.unpack(endian + "IIII", raw)
            data = handle.read(cap_len)
            short = len(data) < cap_len
            if short:
                self.warnings.append(
                    f"record {ts_sec}.{ts_frac} declares {cap_len} captured bytes, "
                    f"{len(data)} present"
                )
            yield _Record(ts_sec + ts_frac / divisor, linktype, data, orig_len, cap_len)
            if short:
                self.warnings.append(
                    "stopping at the truncated record, the file position is unreliable"
                )
                return

    def _pcapng(self, handle: BinaryIO, first_block_type: bytes) -> Iterator[_Record]:
        self.format = "pcapng"
        endian = "<"
        interfaces: list[_Interface] = []
        pending: bytes | None = first_block_type
        while True:
            if pending is not None:
                block_type_raw, pending = pending, None
            else:
                block_type_raw = handle.read(4)
                if not block_type_raw:
                    return
                if len(block_type_raw) < 4:
                    self.warnings.append("truncated pcapng block type")
                    return
            if block_type_raw == NG_SHB:
                rest = handle.read(8)
                if len(rest) < 8:
                    self.warnings.append("truncated pcapng section header")
                    return
                if rest[4:] == NG_BOM_LE:
                    endian = "<"
                elif rest[4:] == NG_BOM_BE:
                    endian = ">"
                else:
                    self.warnings.append("pcapng section header without byte-order magic")
                    return
                total_len = struct.unpack(endian + "I", rest[:4])[0]
                if total_len < 28:
                    self.warnings.append(f"invalid pcapng section length {total_len}")
                    return
                body = handle.read(total_len - 16)
                if len(body) < total_len - 16 or len(handle.read(4)) < 4:
                    self.warnings.append("truncated pcapng section header")
                    return
                interfaces = []
                continue
            length_raw = handle.read(4)
            if len(length_raw) < 4:
                self.warnings.append("truncated pcapng block length")
                return
            block_type = struct.unpack(endian + "I", block_type_raw)[0]
            total_len = struct.unpack(endian + "I", length_raw)[0]
            if total_len < 12 or total_len % 4:
                self.warnings.append(f"invalid pcapng block length {total_len}")
                return
            body = handle.read(total_len - 12)
            if len(body) < total_len - 12 or len(handle.read(4)) < 4:
                self.warnings.append("truncated pcapng block body")
                return
            if block_type == NG_IDB:
                if len(body) < NG_IDB_MIN_BODY:
                    self.warnings.append("truncated pcapng interface description block")
                    continue
                interfaces.append(_interface(body, endian))
                if self.linktype is None:
                    self.linktype = interfaces[-1].linktype
            elif block_type == NG_EPB:
                record = self._enhanced(body, endian, interfaces)
                if record is not None:
                    yield record
            elif block_type == NG_SPB:
                record = self._simple(body, endian, interfaces)
                if record is not None:
                    yield record

    def _enhanced(self, body: bytes, endian: str, interfaces: list[_Interface]) -> _Record | None:
        if len(body) < 20:
            self.warnings.append("truncated pcapng enhanced packet block")
            return None
        iface_id, ts_high, ts_low, cap_len, orig_len = struct.unpack_from(endian + "IIIII", body, 0)
        if iface_id >= len(interfaces):
            self.warnings.append(f"pcapng packet references undefined interface {iface_id}")
            return None
        interface = interfaces[iface_id]
        data = body[20 : 20 + cap_len]
        if len(data) < cap_len:
            self.warnings.append(f"pcapng packet declares {cap_len} bytes, {len(data)} present")
        timestamp = ((ts_high << 32) | ts_low) / interface.divisor
        return _Record(timestamp, interface.linktype, data, orig_len, cap_len)

    def _simple(self, body: bytes, endian: str, interfaces: list[_Interface]) -> _Record | None:
        if len(body) < 4 or not interfaces:
            self.warnings.append("pcapng simple packet block without a usable interface")
            return None
        interface = interfaces[0]
        orig_len = struct.unpack_from(endian + "I", body, 0)[0]
        captured = min(orig_len, interface.snaplen, len(body) - 4)
        return _Record(0.0, interface.linktype, body[4 : 4 + captured], orig_len, captured)
```

`ids/capture/live.py`:

```python
from __future__ import annotations

import time
from collections.abc import Iterator
from typing import Any

from ..model import RawPacket
from .base import DLT_EN10MB

PERMISSION_HINT = (
    "live capture requires CAP_NET_RAW (Linux) or administrator rights; "
    "run with sudo or grant the capability, or use --pcap instead"
)


def scapy_module() -> Any:
    try:
        import scapy.all as scapy_all
    except ImportError as exc:
        raise RuntimeError(
            "scapy is required for live capture; install it with `uv sync` or use --pcap"
        ) from exc
    return scapy_all


def list_interfaces() -> list[dict[str, object]]:
    scapy_all = scapy_module()
    interfaces: list[dict[str, object]] = []
    for name in scapy_all.get_if_list():
        entry = scapy_all.conf.ifaces.get(name)
        ips: list[str] = []
        if entry is not None:
            for family in (4, 6):
                ips.extend(entry.ips.get(family, []))
        interfaces.append(
            {
                "name": name,
                "description": getattr(entry, "description", "") or "",
                "mac": str(getattr(entry, "mac", "") or ""),
                "ips": ips,
            }
        )
    return interfaces


class LiveSource:
    source = "live"

    def __init__(
        self,
        interface: str,
        *,
        bpf_filter: str | None = None,
        count: int | None = None,
        promiscuous: bool = True,
        capture_idle_timeout: float | None = None,
        poll_interval: float = 1.0,
    ) -> None:
        self.interface = interface
        self.origin = interface
        self.bpf_filter = bpf_filter
        self.count = count
        self.promiscuous = promiscuous
        self.capture_idle_timeout = capture_idle_timeout
        self.poll_interval = poll_interval
        self.warnings: list[str] = []

    def close(self) -> None:
        """The socket is opened and closed inside items(); nothing else is held."""

    def describe(self) -> dict[str, object]:
        return {
            "source": self.source,
            "origin": self.origin,
            "interface": self.interface,
            "bpf_filter": self.bpf_filter,
            "promiscuous": self.promiscuous,
            "count_limit": self.count,
            "capture_idle_timeout": self.capture_idle_timeout,
        }

    def _open_socket(self, scapy_all: Any) -> Any:
        available = scapy_all.get_if_list()
        if self.interface not in available:
            raise RuntimeError(
                f"interface {self.interface!r} not found; available: {', '.join(available)}"
            )
        try:
            try:
                return scapy_all.conf.L2listen(
                    iface=self.interface,
                    filter=self.bpf_filter,
                    promisc=self.promiscuous,
                )
            except PermissionError as exc:
                raise RuntimeError(PERMISSION_HINT) from exc
            except Exception as exc:
                if not self.bpf_filter:
                    raise
                self.warnings.append(f"BPF filter rejected ({exc}); capturing without a filter")
                return scapy_all.conf.L2listen(iface=self.interface, promisc=self.promiscuous)
        except PermissionError as exc:
            raise RuntimeError(PERMISSION_HINT) from exc

    def items(self) -> Iterator[RawPacket]:
        scapy_all = scapy_module()
        socket = self._open_socket(scapy_all)
        layer2num = scapy_all.conf.l2types.layer2num
        index = 0
        last_packet = time.monotonic()
        try:
            while self.count is None or index < self.count:
                if not socket.select([socket], self.poll_interval):
                    if (
                        self.capture_idle_timeout
                        and time.monotonic() - last_packet >= self.capture_idle_timeout
                    ):
                        self.warnings.append(
                            f"live capture stopped after {self.capture_idle_timeout}s"
                            " without traffic"
                        )
                        return
                    continue
                packet = socket.recv()
                if packet is None:
                    continue
                last_packet = time.monotonic()
                index += 1
                yield self._raw_packet(index, packet, layer2num.get(type(packet), DLT_EN10MB))
        finally:
            socket.close()

    def _raw_packet(self, index: int, packet: Any, linktype: int) -> RawPacket:
        try:
            timestamp = float(packet.time)
        except (TypeError, ValueError):
            timestamp = time.time()
        data = bytes(packet)
        return RawPacket(
            packet_id=index,
            timestamp=timestamp,
            data=data,
            linktype=linktype,
            source=self.source,
            origin=self.origin,
            original_length=len(data),
            declared_capture_length=len(data),
        )
```

`ids/capture/__init__.py`:

```python
from __future__ import annotations

from .base import CaptureSource, linktype_name
from .live import LiveSource, list_interfaces
from .pcap import PcapSource

__all__ = [
    "CaptureSource",
    "LiveSource",
    "PcapSource",
    "linktype_name",
    "list_interfaces",
]
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/test_capture.py tests/test_live.py tests/test_link.py -q`
Expected: PASS (`tests/test_link.py` from plan 1b still imports the `DLT_*` constants from `ids.capture.base`).

Run: `uv run ruff check ids/capture tests/fake_scapy.py tests/test_capture.py tests/test_live.py && uv run ruff format --check ids/capture tests/fake_scapy.py tests/test_capture.py tests/test_live.py`
Expected: `All checks passed!` and `7 files already formatted`.

- [ ] **Step 5: Commit**

```bash
git add ids/capture/base.py ids/capture/pcap.py ids/capture/live.py ids/capture/__init__.py tests/fake_scapy.py tests/test_capture.py tests/test_live.py
git commit -m "feat: port pcap and live capture onto typed sources"
```

---
### Task 2: Packet parser over the typed parsers

**Files:**
- Modify (full rewrite): `ids/parsers/__init__.py`
- Modify: `ids/payload.py` (delete the legacy `describe` function)
- Delete: `ids/pipeline.py` (legacy `Pipeline`), `ids/event.py`, `ids/errors.py`
- Test (full rewrite): `tests/test_pipeline.py`

**Interfaces:**
- Consumes: `parse_link(data: bytes, linktype: int) -> LinkResult` (`.info`, `.payload`, `.network_protocol`); `parse_ipv4(data: bytes, issues: Issues) -> NetworkResult` (`.info: Ipv4Info`, `.payload`; adds its own `truncated_packet` issue); `IPPROTO_TCP`, `IPPROTO_UDP`; `parse_transport(protocol_number, data, *, src_ip, dst_ip, declared_length=None, fragment_offset=0) -> TransportResult`; `detect(payload, *, src_port, dst_port, tcp) -> Detection`; `registry.by_name(name) -> AppProtocol | None` whose `.parse(payload, *, tcp, issues)` returns `HttpMessage | DnsMessage | SmtpSession` (plan 1b, contract §6). `make_payload(data, *, max_bytes, preview_limit) -> Payload`, `sha256_hex` (plan 1a, §4). `Issues`, `Issue` (§2). `linktype_name` (Task 1). `PcapSource` (Task 1, tests only). `ids.codec.encode_line` (plan 1a, tests only).
- Produces: `ids.parsers.ParserConfig(max_payload_bytes: int = 65535, preview_limit: int = 256)`; `ids.parsers.PacketParser(config: ParserConfig | None = None)` with `.config` and `.parse(raw: RawPacket) -> PacketEvent` (never raises). Module-level names `parse_link`, `parse_ipv4`, `parse_transport`, `detect`, `by_name`, `make_payload` are looked up at call time (tests monkeypatch them on `ids.parsers`).

`PacketParser.parse` behaviour:

1. `capture = CaptureInfo(...)` from the `RawPacket`; `raw.truncated` → issue `capture/truncated_packet` (`declared`, `captured`).
2. Each step runs inside `_guarded(issues.scoped(<stage>), function, ...)`: a `ParseError` becomes its own code at that stage, any other exception becomes `<stage>/internal_error` (`Issues.capture`), and the step result is `None`.
3. `link` → (only if `network_protocol == "IPv4"`) `network` → (only if IP protocol is 6 or 17) `transport` → `detect` → `application` (only if the detected protocol is not `UNKNOWN` and the L7 payload is non-empty).
4. Whenever a transport was parsed, `event.application = ApplicationInfo(protocol, detection, message)` with `protocol = UNKNOWN` when detection failed or matched nothing; otherwise `event.application = None`.
5. `event.payload = make_payload(<deepest bytes reached>, max_bytes=config.max_payload_bytes, preview_limit=config.preview_limit)`.
6. Any exception outside the guarded steps → `PacketEvent(packet_id, timestamp, capture, issues=[pipeline/internal_error])`, `payload = None`.

- [ ] **Step 1: Write the failing test**

`tests/test_pipeline.py` (replaces the file):

```python
from __future__ import annotations

import json
import random
from pathlib import Path

from ids.capture import PcapSource
from ids.codec import encode_line
from ids.issues import Issue
from ids.model import UNKNOWN, ApplicationInfo, RawPacket
from ids.parsers import PacketParser, ParserConfig
from ids.payload import sha256_hex

FIXTURES = Path(__file__).resolve().parents[1] / "TEST" / "fixtures"


def raw_packets(fixture):
    return list(PcapSource(FIXTURES / fixture).items())


def events(fixture, config=None):
    parser = PacketParser(config)
    return [parser.parse(raw) for raw in raw_packets(fixture)]


def boom(*args, **kwargs):
    raise RuntimeError("parser bug")


def test_tcp_handshake_sequence():
    results = events("01-tcp-handshake.pcap")
    assert [event.transport.flags_string for event in results] == ["S", "SA", "A"]
    assert [event.event_type for event in results] == ["tcp_segment"] * 3
    assert results[0].transport.flags.syn is True
    assert results[1].transport.flags.ack is True
    assert results[0].network.header_checksum_valid is True
    assert all(event.issues == [] for event in results)


def test_tcp_data_payload_is_kept():
    results = events("02-tcp-data.pcap")
    assert [event.transport.payload_length for event in results] == [29, 32]
    assert results[0].payload.preview.startswith("PAYLOAD-01")
    assert results[0].payload.data.startswith(b"PAYLOAD-01")
    assert results[0].payload.length == len(results[0].payload.data) == 29
    assert results[1].payload.binary is True
    assert len(results[1].payload.sha256) == 64


def test_payload_bytes_are_capped_but_hashed_in_full():
    full = events("02-tcp-data.pcap")[0].payload
    capped = events("02-tcp-data.pcap", ParserConfig(max_payload_bytes=10))[0].payload
    assert full.data_truncated is False
    assert capped.data == b"PAYLOAD-01"
    assert capped.data_truncated is True
    assert capped.length == 29
    assert capped.sha256 == full.sha256 == sha256_hex(full.data)


def test_udp_packets():
    results = events("03-udp.pcap")
    assert all(event.protocol == "UDP" for event in results)
    assert [event.transport.payload_length for event in results] == [15, 64, 0]
    assert results[0].application_protocol == UNKNOWN
    assert results[0].application.detection.method == "none"


def test_http_get_application_block():
    event = events("04-http-get.pcap")[1]
    assert event.event_type == "http_request"
    assert event.application_protocol == "HTTP"
    message = event.application.message
    assert message.method == "GET"
    assert message.uri == "/index.html?q=ids&page=1"
    assert message.header("host") == "example.com"
    assert [header.name for header in message.headers] == [
        "Host",
        "User-Agent",
        "Accept",
        "Cookie",
        "Connection",
    ]
    assert event.application.detection.method == "port+payload"
    assert event.src_ip == "10.0.0.1"
    assert event.dst_port == 80


def test_http_post_body_is_located_in_the_payload():
    event = events("05-http-post.pcap")[0]
    message = event.application.message
    assert message.method == "POST"
    assert message.body.length == 42
    assert message.body.declared_length == 42
    start = message.body.offset
    assert event.payload.data[start : start + 42] == b"username=alice&password=s3cr3t&remember=on"
    assert event.issues == []


def test_http_responses_report_status_codes():
    results = events("06-http-response.pcap")
    messages = [event.application.message for event in results]
    assert [message.status_code for message in messages] == [200, 404]
    assert [message.reason for message in messages] == ["OK", "Not Found"]
    assert messages[0].header("server") == "nginx/1.24.0"
    assert results[0].event_type == "http_response"


def test_dns_queries_report_name_and_type():
    results = events("07-dns-query.pcap")
    assert [event.event_type for event in results] == ["dns_query"] * 3
    questions = [event.application.message.questions[0] for event in results]
    assert [(question.name, question.type_name) for question in questions] == [
        ("example.com", "A"),
        ("mail.example.com", "MX"),
        ("1.1.168.192.in-addr.arpa", "PTR"),
    ]


def test_dns_response_has_answers():
    results = events("08-dns-response.pcap")
    first = results[0].application.message
    assert first.kind == "response"
    assert first.rcode_name == "NOERROR"
    assert [answer.type_name for answer in first.answers] == ["CNAME", "A"]
    assert first.answers[1].value == "93.184.216.34"
    assert results[1].application.message.rcode_name == "NXDOMAIN"


def test_smtp_commands():
    results = events("09-smtp-command.pcap")
    sessions = [event.application.message for event in results]
    assert [session.command for session in sessions] == ["EHLO", "MAIL", "RCPT", "DATA"]
    assert sessions[1].mail_from == "alice@example.test"
    assert sessions[2].rcpt_to == ["bob@example.test"]
    assert all(event.event_type == "smtp_command" for event in results)


def test_smtp_status_codes():
    results = events("10-smtp-response.pcap")
    sessions = [event.application.message for event in results]
    assert [session.status_code for session in sessions] == [220, 250, 354, 550]
    assert len(sessions[1].replies) == 1
    assert all(event.event_type == "smtp_response" for event in results)


def test_unknown_protocols_do_not_crash():
    results = events("11-unknown-protocol.pcap")
    assert len(results) == 6
    assert all(event.application_protocol == UNKNOWN for event in results)
    assert {event.event_type for event in results} == {
        "unknown_payload",
        "network_only",
        "unparsed",
    }
    assert results[3].network.protocol == "IPv4"
    assert results[3].transport is None
    assert results[3].application is None
    assert results[3].issues == []


def test_malformed_packets_do_not_crash():
    results = events("12-malformed.pcap")
    assert len(results) == 14
    assert all(event.issues for event in results)
    found = {(issue.stage, issue.code) for event in results for issue in event.issues}
    assert ("link", "truncated_packet") in found
    assert ("network", "malformed_header") in found
    assert ("network", "truncated_packet") in found
    assert ("network", "unsupported_protocol") in found
    assert ("transport", "malformed_header") in found
    assert ("transport", "truncated_packet") in found
    assert ("application", "decode_error") in found
    assert ("application", "truncated_body") in found
    assert ("capture", "truncated_packet") in found
    assert [(issue.stage, issue.code) for issue in results[13].issues] == [
        ("capture", "truncated_packet"),
        ("network", "truncated_packet"),
        ("transport", "truncated_packet"),
    ]


def test_pcapng_fixture_parses_like_pcap():
    results = events("13-mixed.pcapng")
    assert len(results) == 12
    assert all(event.capture.source == "pcap" for event in results)
    assert all(event.capture.linktype_name == "EN10MB" for event in results)
    assert {event.event_type for event in results} == {
        "tcp_segment",
        "http_request",
        "dns_query",
        "smtp_command",
    }


def test_preview_limit_is_respected():
    event = events("02-tcp-data.pcap", ParserConfig(preview_limit=4))[0]
    assert event.payload.preview == "PAYL"
    assert event.payload.preview_truncated is True
    assert event.payload.length == 29


def test_random_bytes_never_escape_the_parser():
    rng = random.Random(20260928)
    parser = PacketParser()
    for index in range(3000):
        data = bytes(rng.getrandbits(8) for _ in range(rng.randrange(0, 96)))
        packet = RawPacket(
            packet_id=index + 1,
            timestamp=1759000000.0 + index,
            data=data,
            linktype=rng.choice([0, 1, 101, 113, 228, 276, 999]),
            source="pcap",
            origin="fuzz",
            original_length=len(data),
            declared_capture_length=len(data),
        )
        event = parser.parse(packet)
        assert event.application_protocol in {"HTTP", "DNS", "SMTP", UNKNOWN}
        assert json.loads(encode_line(event))["packet_id"] == index + 1


def test_link_crash_is_contained_in_one_event(monkeypatch):
    monkeypatch.setattr("ids.parsers.parse_link", boom)
    event = PacketParser().parse(RawPacket(1, 0.0, b"\x00" * 60, 1, "pcap", "fuzz", 60, 60))
    assert event.issues == [
        Issue("link", "internal_error", "parser bug", {"exception": "RuntimeError"})
    ]
    assert event.event_type == "unparsed"
    assert event.network is None
    assert event.payload.length == 60


def test_detector_crash_leaves_the_packet_unknown(monkeypatch):
    monkeypatch.setattr("ids.parsers.detect", boom)
    event = PacketParser().parse(raw_packets("04-http-get.pcap")[1])
    assert event.issues == [
        Issue("detect", "internal_error", "parser bug", {"exception": "RuntimeError"})
    ]
    assert event.application == ApplicationInfo(protocol=UNKNOWN, detection=None, message=None)
    assert event.transport is not None
    assert event.payload.length == 187


def test_missing_application_parser_is_reported_at_application_stage(monkeypatch):
    monkeypatch.setattr("ids.parsers.by_name", lambda name: None)
    event = PacketParser().parse(raw_packets("04-http-get.pcap")[1])
    assert [(issue.stage, issue.code, issue.message) for issue in event.issues] == [
        ("application", "internal_error", "no application parser registered for HTTP")
    ]
    assert event.application.protocol == "HTTP"
    assert event.application.message is None
    assert event.event_type == "http_unparsed"


def test_failure_outside_the_steps_falls_back_to_a_minimal_event(monkeypatch):
    def broken_payload(*args, **kwargs):
        raise RuntimeError("payload bug")

    monkeypatch.setattr("ids.parsers.make_payload", broken_payload)
    event = PacketParser().parse(RawPacket(9, 12.5, b"\x00" * 60, 1, "pcap", "fuzz", 60, 60))
    assert event.packet_id == 9
    assert event.timestamp == 12.5
    assert event.event_type == "unparsed"
    assert event.payload is None
    assert event.capture.captured_length == 60
    assert event.capture.linktype_name == "EN10MB"
    assert event.issues == [
        Issue("pipeline", "internal_error", "payload bug", {"exception": "RuntimeError"})
    ]
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/test_pipeline.py -q`
Expected: FAIL — collection error `ImportError: cannot import name 'PacketParser' from 'ids.parsers'`.

- [ ] **Step 3: Implement `PacketParser`**

`ids/parsers/__init__.py` (replaces the file):

```python
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, TypeVar

from ..capture.base import linktype_name
from ..issues import Issues
from ..model import (
    UNKNOWN,
    ApplicationInfo,
    CaptureInfo,
    DnsMessage,
    HttpMessage,
    PacketEvent,
    RawPacket,
    SmtpSession,
    TcpInfo,
)
from ..payload import make_payload
from .detector import detect
from .link import parse_link
from .network import IPPROTO_TCP, IPPROTO_UDP, parse_ipv4
from .registry import by_name
from .transport import parse_transport

__all__ = ["PacketParser", "ParserConfig"]

TRANSPORT_PROTOCOLS = frozenset((IPPROTO_TCP, IPPROTO_UDP))

T = TypeVar("T")


@dataclass(slots=True)
class ParserConfig:
    max_payload_bytes: int = 65535
    preview_limit: int = 256


def _guarded(issues: Issues, function: Callable[..., T], /, *args: Any, **kwargs: Any) -> T | None:
    try:
        return function(*args, **kwargs)
    except Exception as error:
        issues.capture(error)
        return None


def _capture_info(raw: RawPacket) -> CaptureInfo:
    return CaptureInfo(
        source=raw.source,
        origin=raw.origin,
        linktype=raw.linktype,
        linktype_name=linktype_name(raw.linktype),
        captured_length=raw.captured_length,
        original_length=raw.original_length,
        declared_capture_length=raw.declared_capture_length,
        truncated_by_capture=raw.truncated,
    )


def _parse_application(
    protocol: str, payload: bytes, tcp: bool, issues: Issues
) -> HttpMessage | DnsMessage | SmtpSession:
    application = by_name(protocol)
    if application is None:
        raise LookupError(f"no application parser registered for {protocol}")
    return application.parse(payload, tcp=tcp, issues=issues)


def _layers(raw: RawPacket, event: PacketEvent, issues: Issues) -> bytes:
    """Parse as deep as possible into `event`; return the deepest bytes reached."""
    link = _guarded(issues.scoped("link"), parse_link, raw.data, raw.linktype)
    if link is None:
        return raw.data
    event.link = link.info
    if link.network_protocol != "IPv4":
        return link.payload

    network_issues = issues.scoped("network")
    network = _guarded(network_issues, parse_ipv4, link.payload, network_issues)
    if network is None:
        return link.payload
    ip = network.info
    event.network = ip
    if ip.protocol_number not in TRANSPORT_PROTOCOLS:
        return network.payload

    transport = _guarded(
        issues.scoped("transport"),
        parse_transport,
        ip.protocol_number,
        network.payload,
        src_ip=ip.src_ip,
        dst_ip=ip.dst_ip,
        declared_length=ip.declared_payload_length,
        fragment_offset=ip.fragment_offset or 0,
    )
    if transport is None:
        return network.payload
    segment = transport.info
    event.transport = segment
    payload = transport.payload
    tcp = isinstance(segment, TcpInfo)

    detection = _guarded(
        issues.scoped("detect"),
        detect,
        payload,
        src_port=segment.src_port,
        dst_port=segment.dst_port,
        tcp=tcp,
    )
    protocol = detection.protocol if detection is not None and detection.protocol else UNKNOWN
    message = None
    if protocol != UNKNOWN and payload:
        application_issues = issues.scoped("application")
        message = _guarded(
            application_issues, _parse_application, protocol, payload, tcp, application_issues
        )
    event.application = ApplicationInfo(protocol=protocol, detection=detection, message=message)
    return payload


class PacketParser:
    __slots__ = ("config",)

    def __init__(self, config: ParserConfig | None = None) -> None:
        self.config = config if config is not None else ParserConfig()

    def parse(self, raw: RawPacket) -> PacketEvent:
        try:
            return self._parse(raw)
        except Exception as error:
            issues = Issues("pipeline")
            issues.capture(error)
            return PacketEvent(
                packet_id=raw.packet_id,
                timestamp=raw.timestamp,
                capture=_capture_info(raw),
                issues=issues.records,
            )

    def _parse(self, raw: RawPacket) -> PacketEvent:
        issues = Issues("capture")
        if raw.truncated:
            issues.add(
                "truncated_packet",
                "the capture file holds fewer bytes than the record declares",
                declared=raw.declared_capture_length,
                captured=raw.captured_length,
            )
        event = PacketEvent(
            packet_id=raw.packet_id,
            timestamp=raw.timestamp,
            capture=_capture_info(raw),
            issues=issues.records,
        )
        deepest = _layers(raw, event, issues)
        config = self.config
        event.payload = make_payload(
            deepest, max_bytes=config.max_payload_bytes, preview_limit=config.preview_limit
        )
        return event
```

Delete the legacy modules whose last caller was the legacy pipeline:

```bash
git rm -q ids/pipeline.py ids/event.py ids/errors.py
```

In `ids/payload.py`, delete the whole `def describe(...)` function (the legacy dict summary; plan 1a left it in place for the legacy pipeline). Keep `make_payload`, `sha256_hex`, `looks_binary` and every private helper `make_payload` uses. Then check whether `HEX_LIMIT` / `PREVIEW_LIMIT` lost their last user:

Run: `git grep -n -w -e HEX_LIMIT -e PREVIEW_LIMIT -e printable_ratio -- ids tests`
Expected: each listed name still appears at least once outside its own definition line. Delete any constant or helper whose only remaining hit is its definition.

Confirm no caller of the deleted code is left (plan 1b moved the parsers to `ids.issues`; the legacy CLI is rewritten in Task 6 and is allowed to be broken until then):

Run: `git grep -n -E "from (\.\.?|ids\.)(errors|event) import|import describe|describe\(data" -- ids tests ':!ids/model' ':!ids/cli.py'`
Expected: no output.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/test_pipeline.py tests/test_capture.py tests/test_live.py -q`
Expected: PASS.

Run: `uv run ruff check ids/parsers/__init__.py ids/payload.py tests/test_pipeline.py && uv run ruff format --check ids/parsers/__init__.py ids/payload.py tests/test_pipeline.py`
Expected: `All checks passed!` and `3 files already formatted`.

- [ ] **Step 5: Commit**

```bash
git add ids/parsers/__init__.py ids/payload.py tests/test_pipeline.py
git commit -m "feat: add packet parser over the typed parsers"
```

(`git rm` in Step 3 already staged the three deletions.)

---

### Task 3: Typed run statistics

**Files:**
- Modify (full rewrite): `ids/stats.py`
- Create: `tests/test_stats.py`

**Interfaces:**
- Consumes: `PacketEvent`, `MessageEvent`, `FlowRecord`, `ApplicationInfo`, `Detection`, `HttpMessage`, `Ipv4Info`, `TcpInfo`, `Payload`, `EndReason`, `PreprocessStatus`, `ProcessingAction` (plan 1a, §3); `Issue` (§2).
- Produces: `ids.stats.Stats()` with
  - `observe(record: PacketEvent | MessageEvent | FlowRecord) -> None` (written records),
  - `dropped(record: PacketEvent | MessageEvent) -> None`, `skipped(record: PacketEvent) -> None`,
  - `stage_error(stage: str, operation: str) -> None` (`operation` is `"tick"` or `"flush"`),
  - `to_dict() -> dict[str, object]`, `extra: dict[str, object]`,
  - attributes `packets_seen`, `dropped_count`, `skipped_count`, `packets_with_issues: int`, `records_written: Counter[str]`, `first_timestamp`, `last_timestamp: float | None`, property `written -> int` (sum of `records_written`).

Counting rules: `packets_seen` counts every `PacketEvent` that reaches an outcome (written, dropped or skipped), and so do `first_timestamp`/`last_timestamp` (first and last non-`None`, in arrival order). `preprocess_status` / `processing_action` count packet and message records at every outcome. `event_types`, `protocols` (`"none"` when no transport), `application_protocols`, `detection_methods`, `packets_with_issues` count written packets. `issue_codes` (`"stage/code"`) count written packets and messages. `messages` counts written messages by `complete`. `flow_end_reasons` counts written flows.

- [ ] **Step 1: Write the failing test**

`tests/test_stats.py`:

```python
from __future__ import annotations

from ids.issues import Issue
from ids.model import (
    ApplicationInfo,
    Detection,
    EndReason,
    FlowRecord,
    HttpMessage,
    Ipv4Info,
    MessageEvent,
    PacketEvent,
    Payload,
    PreprocessStatus,
    ProcessingAction,
    TcpInfo,
)
from ids.stats import Stats


def http_packet(packet_id, **fields):
    return PacketEvent(
        packet_id=packet_id,
        timestamp=float(packet_id),
        network=Ipv4Info(protocol="IPv4"),
        transport=TcpInfo(),
        application=ApplicationInfo(
            protocol="HTTP",
            detection=Detection(protocol="HTTP", method="port+payload"),
            message=HttpMessage(kind="request"),
        ),
        payload=Payload(length=10),
        **fields,
    )


def test_written_packets_fill_the_breakdowns():
    stats = Stats()
    stats.observe(http_packet(1))
    stats.observe(
        PacketEvent(packet_id=2, timestamp=2.0, issues=[Issue("link", "truncated_packet", "short")])
    )
    summary = stats.to_dict()
    assert stats.written == 2
    assert summary["packets_seen"] == 2
    assert summary["records_written"] == {"packet": 2, "message": 0, "flow": 0}
    assert summary["event_types"] == {"http_request": 1, "unparsed": 1}
    assert summary["protocols"] == {"TCP": 1, "none": 1}
    assert summary["application_protocols"] == {"HTTP": 1, "UNKNOWN": 1}
    assert summary["detection_methods"] == {"port+payload": 1}
    assert summary["issue_codes"] == {"link/truncated_packet": 1}
    assert summary["packets_with_issues"] == 1
    assert (summary["first_timestamp"], summary["last_timestamp"]) == (1.0, 2.0)


def test_dropped_and_skipped_packets_are_seen_but_not_written():
    stats = Stats()
    stats.dropped(
        http_packet(
            1,
            preprocess_status=PreprocessStatus.INVALID,
            processing_action=ProcessingAction.DROP,
        )
    )
    stats.skipped(PacketEvent(packet_id=2, timestamp=3.0))
    summary = stats.to_dict()
    assert summary["packets_seen"] == 2
    assert summary["dropped"] == 1
    assert summary["skipped"] == 1
    assert summary["records_written"] == {"packet": 0, "message": 0, "flow": 0}
    assert summary["preprocess_status"] == {"invalid": 1}
    assert summary["processing_action"] == {"drop": 1}
    assert summary["event_types"] == {}
    assert summary["last_timestamp"] == 3.0


def test_messages_and_flows_are_counted_by_outcome():
    stats = Stats()
    stats.observe(MessageEvent(message_id="f-1", complete=True))
    stats.observe(
        MessageEvent(
            message_id="f-2",
            complete=False,
            preprocess_status=PreprocessStatus.PARTIAL,
            issues=[Issue("decoder", "invalid_base64", "bad")],
        )
    )
    stats.observe(FlowRecord(flow_id="a", end_reason=EndReason.CLOSED))
    stats.observe(FlowRecord(flow_id="b", end_reason=EndReason.IDLE_TIMEOUT))
    summary = stats.to_dict()
    assert summary["records_written"] == {"packet": 0, "message": 2, "flow": 2}
    assert summary["messages"] == {"complete": 1, "incomplete": 1}
    assert summary["flow_end_reasons"] == {"closed": 1, "idle_timeout": 1}
    assert summary["issue_codes"] == {"decoder/invalid_base64": 1}
    assert summary["preprocess_status"] == {"partial": 1}
    assert summary["packets_seen"] == 0


def test_timestamps_skip_missing_values():
    stats = Stats()
    stats.observe(PacketEvent(packet_id=1))
    stats.observe(PacketEvent(packet_id=2, timestamp=5.0))
    stats.observe(PacketEvent(packet_id=3))
    summary = stats.to_dict()
    assert (summary["first_timestamp"], summary["last_timestamp"]) == (5.0, 5.0)


def test_stage_errors_and_extra_are_reported_last():
    stats = Stats()
    stats.stage_error("flow", "flush")
    stats.stage_error("flow", "flush")
    stats.extra["active_flows"] = 3
    summary = stats.to_dict()
    assert summary["stage_errors"] == {"flow/flush": 2}
    assert summary["active_flows"] == 3
    assert list(summary)[-2:] == ["stage_errors", "active_flows"]
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/test_stats.py -q`
Expected: FAIL — the legacy `Stats.observe` subscripts its argument: `TypeError: 'PacketEvent' object is not subscriptable` (and `AttributeError` for `dropped`/`stage_error`).

- [ ] **Step 3: Implement `Stats`**

`ids/stats.py` (replaces the file):

```python
from __future__ import annotations

from collections import Counter

from .issues import Issue
from .model import FlowRecord, MessageEvent, PacketEvent

RECORD_TYPES = (PacketEvent.RECORD_TYPE, MessageEvent.RECORD_TYPE, FlowRecord.RECORD_TYPE)


class Stats:
    def __init__(self) -> None:
        self.packets_seen = 0
        self.records_written: Counter[str] = Counter()
        self.dropped_count = 0
        self.skipped_count = 0
        self.packets_with_issues = 0
        self.first_timestamp: float | None = None
        self.last_timestamp: float | None = None
        self.event_types: Counter[str] = Counter()
        self.protocols: Counter[str] = Counter()
        self.application_protocols: Counter[str] = Counter()
        self.detection_methods: Counter[str] = Counter()
        self.issue_codes: Counter[str] = Counter()
        self.preprocess_status: Counter[str] = Counter()
        self.processing_action: Counter[str] = Counter()
        self.flow_end_reasons: Counter[str] = Counter()
        self.messages: Counter[str] = Counter()
        self.stage_errors: Counter[str] = Counter()
        self.extra: dict[str, object] = {}

    @property
    def written(self) -> int:
        return sum(self.records_written.values())

    def observe(self, record: PacketEvent | MessageEvent | FlowRecord) -> None:
        self.records_written[record.RECORD_TYPE] += 1
        if isinstance(record, FlowRecord):
            if record.end_reason is not None:
                self.flow_end_reasons[record.end_reason.value] += 1
            return
        self._outcome(record)
        self._issues(record.issues)
        if isinstance(record, MessageEvent):
            self.messages["complete" if record.complete else "incomplete"] += 1
            return
        self.event_types[record.event_type] += 1
        self.protocols[record.protocol or "none"] += 1
        self.application_protocols[record.application_protocol] += 1
        application = record.application
        if application is not None and application.detection is not None:
            method = application.detection.method
            if method:
                self.detection_methods[method] += 1
        if record.issues:
            self.packets_with_issues += 1

    def dropped(self, record: PacketEvent | MessageEvent) -> None:
        self.dropped_count += 1
        self._outcome(record)

    def skipped(self, record: PacketEvent) -> None:
        self.skipped_count += 1
        self._outcome(record)

    def stage_error(self, stage: str, operation: str) -> None:
        self.stage_errors[f"{stage}/{operation}"] += 1

    def _outcome(self, record: PacketEvent | MessageEvent) -> None:
        if record.preprocess_status is not None:
            self.preprocess_status[record.preprocess_status.value] += 1
        if record.processing_action is not None:
            self.processing_action[record.processing_action.value] += 1
        if isinstance(record, PacketEvent):
            self.packets_seen += 1
            timestamp = record.timestamp
            if timestamp is not None:
                if self.first_timestamp is None:
                    self.first_timestamp = timestamp
                self.last_timestamp = timestamp

    def _issues(self, issues: list[Issue]) -> None:
        for issue in issues:
            self.issue_codes[f"{issue.stage}/{issue.code}"] += 1

    def to_dict(self) -> dict[str, object]:
        summary: dict[str, object] = {
            "packets_seen": self.packets_seen,
            "records_written": {key: self.records_written[key] for key in RECORD_TYPES},
            "dropped": self.dropped_count,
            "skipped": self.skipped_count,
            "packets_with_issues": self.packets_with_issues,
            "first_timestamp": self.first_timestamp,
            "last_timestamp": self.last_timestamp,
            "event_types": dict(self.event_types.most_common()),
            "protocols": dict(self.protocols.most_common()),
            "application_protocols": dict(self.application_protocols.most_common()),
            "detection_methods": dict(self.detection_methods.most_common()),
            "issue_codes": dict(self.issue_codes.most_common()),
            "preprocess_status": dict(self.preprocess_status.most_common()),
            "processing_action": dict(self.processing_action.most_common()),
            "flow_end_reasons": dict(self.flow_end_reasons.most_common()),
            "messages": {
                "complete": self.messages["complete"],
                "incomplete": self.messages["incomplete"],
            },
            "stage_errors": dict(self.stage_errors.most_common()),
        }
        summary.update(self.extra)
        return summary
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/test_stats.py -q`
Expected: PASS.

Run: `uv run ruff check ids/stats.py tests/test_stats.py && uv run ruff format --check ids/stats.py tests/test_stats.py`
Expected: `All checks passed!` and `2 files already formatted`.

- [ ] **Step 5: Commit**

```bash
git add ids/stats.py tests/test_stats.py
git commit -m "feat: add typed run statistics"
```

---
### Task 4: Stage runner

**Files:**
- Create: `ids/pipeline.py`
- Create: `tests/test_runner.py`

**Interfaces:**
- Consumes: `PacketParser` (Task 2); `Stats` incl. `observe`, `dropped`, `skipped`, `stage_error`, `dropped_count`, `skipped_count`, `packets_seen`, `to_dict` (Task 3); `PcapSource` (Task 1, tests only); `UNKNOWN`, `PacketEvent`, `MessageEvent`, `FlowRecord`, `ProcessingAction`, `RawPacket`, `Tick`, `ApplicationInfo` (plan 1a); `Issue` (§2).
- Produces (`ids.pipeline`):
  - `Emit = Callable[[PacketEvent | MessageEvent | FlowRecord], None]`
  - `class Stage(Protocol)`: `name: str`; `process(record: PacketEvent | MessageEvent, emit: Emit) -> None`; `tick(now: float, emit: Emit) -> None`; `flush(emit: Emit) -> None`. Stages ignore record types they do not handle.
  - `class Sink(Protocol)`: `write(record: PacketEvent | MessageEvent | FlowRecord) -> None` (`JsonlSink` in Task 5 satisfies it; tests use a list sink).
  - `UNKNOWN_POLICIES = ("emit", "skip")`
  - `Runner(parser: PacketParser, stages: Sequence[Stage], sink: Sink, stats: Stats, *, unknown_policy: str = "emit")` (`ValueError` for an unknown policy); `run(source: Iterable[RawPacket | PacketEvent | Tick]) -> None`.

`Runner` semantics (contract §8 plus the emission-timing decision at the top of this plan):

- `RawPacket` → `parser.parse`; `PacketEvent` → used as is; `Tick` → `stage.tick(now, emit)` for every stage in order.
- Before each stage and after the last: `processing_action is ProcessingAction.DROP` → `stats.dropped(record)`, stop.
- `stage.process` raising → `record.issues.append(Issue(stage.name, "internal_error", str(exc) or type name, {"exception": type name}))`, next stage runs.
- Records a stage emits during one call are dispatched when that call returns: `MessageEvent` → `_process` from stage 0, then written; anything else → written. So an emitted flow/message is in the output before the packet that triggered it.
- After the stages: `PacketEvent` with `application_protocol == "UNKNOWN"` and policy `skip` → `stats.skipped`; otherwise `sink.write` then `stats.observe`.
- End of input, and on `KeyboardInterrupt` before re-raising: `stage.flush(emit)` for every stage in order. `tick`/`flush` exceptions → `stats.stage_error(stage.name, "tick" | "flush")`, next stage runs. Sink exceptions propagate.

- [ ] **Step 1: Write the failing test**

`tests/test_runner.py`:

```python
from __future__ import annotations

from pathlib import Path

import pytest

from ids.capture import PcapSource
from ids.issues import Issue
from ids.model import (
    ApplicationInfo,
    FlowRecord,
    MessageEvent,
    PacketEvent,
    ProcessingAction,
    RawPacket,
    Tick,
)
from ids.parsers import PacketParser
from ids.pipeline import UNKNOWN_POLICIES, Runner
from ids.stats import Stats

FIXTURES = Path(__file__).resolve().parents[1] / "TEST" / "fixtures"


class ListSink:
    def __init__(self):
        self.records = []

    def write(self, record):
        self.records.append(record)


class FailingSink:
    def write(self, record):
        raise OSError("disk full")


def label(record):
    if isinstance(record, FlowRecord):
        return ("flow", record.flow_id)
    if isinstance(record, MessageEvent):
        return ("message", record.message_id)
    return ("packet", record.packet_id)


def labels(sink):
    return [label(record) for record in sink.records]


class Recorder:
    """Stage that logs every call into a shared journal."""

    def __init__(self, name, journal):
        self.name = name
        self.journal = journal

    def process(self, record, emit):
        self.journal.append((self.name, "process", label(record)[1]))

    def tick(self, now, emit):
        self.journal.append((self.name, "tick", now))

    def flush(self, emit):
        self.journal.append((self.name, "flush", None))


class Exploding(Recorder):
    def process(self, record, emit):
        raise RuntimeError("stage bug")


class Dropper(Recorder):
    def process(self, record, emit):
        super().process(record, emit)
        record.processing_action = ProcessingAction.DROP


class Emitter(Recorder):
    """Emits a flow and a message while processing packet 2; notes any re-entry."""

    def __init__(self, name, journal):
        super().__init__(name, journal)
        self.active = False
        self.reentered = False

    def process(self, record, emit):
        if self.active:
            self.reentered = True
        self.active = True
        super().process(record, emit)
        if isinstance(record, PacketEvent) and record.packet_id == 2:
            emit(FlowRecord(flow_id="f1"))
            emit(MessageEvent(message_id="m1"))
        self.active = False


class Flusher(Recorder):
    def flush(self, emit):
        super().flush(emit)
        emit(FlowRecord(flow_id="end"))


class BrokenClock(Recorder):
    def tick(self, now, emit):
        raise RuntimeError("tick bug")

    def flush(self, emit):
        raise RuntimeError("flush bug")


def packet(packet_id, protocol="HTTP", **fields):
    return PacketEvent(
        packet_id=packet_id,
        timestamp=float(packet_id),
        application=ApplicationInfo(protocol=protocol),
        **fields,
    )


def run(stages, items, sink=None, **options):
    sink = sink if sink is not None else ListSink()
    stats = Stats()
    Runner(PacketParser(), stages, sink, stats, **options).run(items)
    return sink, stats


def test_records_pass_every_stage_in_order_then_reach_the_sink():
    journal = []
    sink, stats = run([Recorder("a", journal), Recorder("b", journal)], [packet(1), packet(2)])
    assert journal == [
        ("a", "process", 1),
        ("b", "process", 1),
        ("a", "process", 2),
        ("b", "process", 2),
        ("a", "flush", None),
        ("b", "flush", None),
    ]
    assert labels(sink) == [("packet", 1), ("packet", 2)]
    assert stats.to_dict()["records_written"]["packet"] == 2


def test_raw_packets_are_parsed_before_the_stages():
    sink, _ = run([], [RawPacket(1, 1.0, b"\x00" * 6, 1, "pcap", "test", 6, 6)])
    (event,) = sink.records
    assert [(issue.stage, issue.code) for issue in event.issues] == [("link", "truncated_packet")]
    assert event.capture.origin == "test"


def test_a_failing_stage_records_an_issue_and_the_next_stage_still_runs():
    journal = []
    sink, _ = run([Exploding("boom", journal), Recorder("after", journal)], [packet(1)])
    assert ("after", "process", 1) in journal
    assert sink.records[0].issues == [
        Issue("boom", "internal_error", "stage bug", {"exception": "RuntimeError"})
    ]


def test_a_drop_stops_the_record_before_the_next_stage():
    journal = []
    sink, stats = run([Dropper("drop", journal), Recorder("after", journal)], [packet(1)])
    assert ("after", "process", 1) not in journal
    assert sink.records == []
    assert (stats.dropped_count, stats.packets_seen) == (1, 1)


def test_a_record_dropped_by_the_last_stage_is_not_written():
    journal = []
    sink, stats = run([Recorder("first", journal), Dropper("last", journal)], [packet(1)])
    assert sink.records == []
    assert stats.dropped_count == 1


def test_a_record_already_marked_drop_never_reaches_a_stage():
    journal = []
    sink, stats = run(
        [Recorder("a", journal)], [packet(1, processing_action=ProcessingAction.DROP)]
    )
    assert journal == [("a", "flush", None)]
    assert sink.records == []
    assert stats.dropped_count == 1


def test_emitted_records_are_written_before_the_triggering_packet():
    journal = []
    emitter = Emitter("emitter", journal)
    sink, stats = run(
        [Recorder("first", journal), emitter, Recorder("last", journal)],
        [packet(1), packet(2)],
    )
    assert labels(sink) == [("packet", 1), ("flow", "f1"), ("message", "m1"), ("packet", 2)]
    assert journal[3:9] == [
        ("first", "process", 2),
        ("emitter", "process", 2),
        ("first", "process", "m1"),
        ("emitter", "process", "m1"),
        ("last", "process", "m1"),
        ("last", "process", 2),
    ]
    assert emitter.reentered is False
    assert stats.to_dict()["records_written"] == {"packet": 2, "message": 1, "flow": 1}


def test_ticks_reach_every_stage_between_records():
    journal = []
    sink, _ = run(
        [Recorder("a", journal), Recorder("b", journal)], [packet(1), Tick(5.0), packet(2)]
    )
    assert journal == [
        ("a", "process", 1),
        ("b", "process", 1),
        ("a", "tick", 5.0),
        ("b", "tick", 5.0),
        ("a", "process", 2),
        ("b", "process", 2),
        ("a", "flush", None),
        ("b", "flush", None),
    ]
    assert labels(sink) == [("packet", 1), ("packet", 2)]


def test_flush_output_is_written_at_end_of_input():
    sink, _ = run([Flusher("flow", [])], [packet(1)])
    assert labels(sink) == [("packet", 1), ("flow", "end")]


def test_tick_and_flush_failures_are_isolated_and_counted():
    journal = []
    sink, stats = run([BrokenClock("clock", journal), Flusher("after", journal)], [Tick(1.0)])
    assert journal == [("after", "tick", 1.0), ("after", "flush", None)]
    assert labels(sink) == [("flow", "end")]
    assert stats.to_dict()["stage_errors"] == {"clock/tick": 1, "clock/flush": 1}


def test_sink_failures_are_not_swallowed():
    with pytest.raises(OSError, match="disk full"):
        run([Recorder("a", [])], [packet(1)], sink=FailingSink())


def test_unknown_policy_skip_suppresses_only_unknown_packets():
    sink, stats = run(
        [Emitter("emitter", [])],
        [packet(1, "UNKNOWN"), packet(2), PacketEvent(packet_id=3)],
        unknown_policy="skip",
    )
    assert labels(sink) == [("flow", "f1"), ("message", "m1"), ("packet", 2)]
    assert (stats.skipped_count, stats.packets_seen) == (2, 3)


def test_unknown_policy_must_be_known():
    assert UNKNOWN_POLICIES == ("emit", "skip")
    with pytest.raises(ValueError):
        Runner(PacketParser(), [], ListSink(), Stats(), unknown_policy="explode")


def test_keyboard_interrupt_flushes_the_stages_then_propagates():
    def items():
        yield packet(1)
        raise KeyboardInterrupt

    sink = ListSink()
    with pytest.raises(KeyboardInterrupt):
        Runner(PacketParser(), [Flusher("flow", [])], sink, Stats()).run(items())
    assert labels(sink) == [("packet", 1), ("flow", "end")]


def test_unknown_policy_skip_on_capture_fixtures():
    sink, stats = run([], PcapSource(FIXTURES / "04-http-get.pcap").items(), unknown_policy="skip")
    assert [event.event_type for event in sink.records] == ["http_request"]
    assert stats.skipped_count == 1
    sink, stats = run(
        [], PcapSource(FIXTURES / "11-unknown-protocol.pcap").items(), unknown_policy="skip"
    )
    assert sink.records == []
    assert (stats.skipped_count, stats.packets_seen) == (6, 6)
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/test_runner.py -q`
Expected: FAIL — collection error `ModuleNotFoundError: No module named 'ids.pipeline'` (the legacy module was deleted in Task 2).

- [ ] **Step 3: Implement the runner**

`ids/pipeline.py`:

```python
from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from typing import Protocol

from .issues import Issue
from .model import (
    UNKNOWN,
    FlowRecord,
    MessageEvent,
    PacketEvent,
    ProcessingAction,
    RawPacket,
    Tick,
)
from .parsers import PacketParser
from .stats import Stats

Emit = Callable[[PacketEvent | MessageEvent | FlowRecord], None]

UNKNOWN_POLICIES = ("emit", "skip")


class Stage(Protocol):
    name: str

    def process(self, record: PacketEvent | MessageEvent, emit: Emit) -> None: ...

    def tick(self, now: float, emit: Emit) -> None: ...

    def flush(self, emit: Emit) -> None: ...


class Sink(Protocol):
    def write(self, record: PacketEvent | MessageEvent | FlowRecord) -> None: ...


def _internal_error(stage: str, error: Exception) -> Issue:
    name = type(error).__name__
    return Issue(stage, "internal_error", str(error) or name, {"exception": name})


class Runner:
    def __init__(
        self,
        parser: PacketParser,
        stages: Sequence[Stage],
        sink: Sink,
        stats: Stats,
        *,
        unknown_policy: str = "emit",
    ) -> None:
        if unknown_policy not in UNKNOWN_POLICIES:
            raise ValueError(
                f"unknown_policy must be one of {UNKNOWN_POLICIES}, got {unknown_policy!r}"
            )
        self.parser = parser
        self.stages = tuple(stages)
        self.sink = sink
        self.stats = stats
        self.skip_unknown = unknown_policy == "skip"

    def run(self, source: Iterable[RawPacket | PacketEvent | Tick]) -> None:
        try:
            for item in source:
                if isinstance(item, Tick):
                    self._tick(item.now)
                elif isinstance(item, PacketEvent):
                    self._process(item)
                else:
                    self._process(self.parser.parse(item))
        except KeyboardInterrupt:
            self._flush()
            raise
        self._flush()

    def _process(self, record: PacketEvent | MessageEvent) -> None:
        for stage in self.stages:
            if record.processing_action is ProcessingAction.DROP:
                self.stats.dropped(record)
                return
            emitted: list[PacketEvent | MessageEvent | FlowRecord] = []
            try:
                stage.process(record, emitted.append)
            except Exception as error:
                record.issues.append(_internal_error(stage.name, error))
            self._dispatch(emitted)
        if record.processing_action is ProcessingAction.DROP:
            self.stats.dropped(record)
        elif (
            self.skip_unknown
            and isinstance(record, PacketEvent)
            and record.application_protocol == UNKNOWN
        ):
            self.stats.skipped(record)
        else:
            self._write(record)

    def _tick(self, now: float) -> None:
        for stage in self.stages:
            emitted: list[PacketEvent | MessageEvent | FlowRecord] = []
            try:
                stage.tick(now, emitted.append)
            except Exception:
                self.stats.stage_error(stage.name, "tick")
            self._dispatch(emitted)

    def _flush(self) -> None:
        for stage in self.stages:
            emitted: list[PacketEvent | MessageEvent | FlowRecord] = []
            try:
                stage.flush(emitted.append)
            except Exception:
                self.stats.stage_error(stage.name, "flush")
            self._dispatch(emitted)

    def _dispatch(self, emitted: list[PacketEvent | MessageEvent | FlowRecord]) -> None:
        for record in emitted:
            if isinstance(record, MessageEvent):
                self._process(record)
            else:
                self._write(record)

    def _write(self, record: PacketEvent | MessageEvent | FlowRecord) -> None:
        self.sink.write(record)
        self.stats.observe(record)
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/test_runner.py tests/test_stats.py -q`
Expected: PASS.

Run: `uv run ruff check ids/pipeline.py tests/test_runner.py && uv run ruff format --check ids/pipeline.py tests/test_runner.py`
Expected: `All checks passed!` and `2 files already formatted`.

- [ ] **Step 5: Commit**

```bash
git add ids/pipeline.py tests/test_runner.py
git commit -m "feat: add stage runner with isolated stages and emit ordering"
```

---

### Task 5: JSON Lines sink

**Files:**
- Create: `ids/sink.py`
- Create: `tests/test_sink.py`

**Interfaces:**
- Consumes: `ids.codec.encode_line(record) -> str` (plan 1a, §5); `PacketEvent`, `MessageEvent`, `FlowRecord`, `EndReason` (plan 1a).
- Produces: `ids.sink.JsonlSink(path: str | None = "-", *, flows_path: str | None = None, flush_every: int = 100)` with `write(record: PacketEvent | MessageEvent | FlowRecord) -> None`, `close() -> None` (idempotent), context manager. `None`/`"-"` = stdout, flushed after every record and never closed. A file path is opened `"w"`, UTF-8, flushed every `flush_every` records (minimum 1) and at close. With `flows_path`, `FlowRecord`s go there and everything else goes to `path`. Opening a bad path raises `OSError` from the constructor.

- [ ] **Step 1: Write the failing test**

`tests/test_sink.py`:

```python
from __future__ import annotations

import json
import sys

import pytest

from ids.codec import encode_line
from ids.model import EndReason, FlowRecord, MessageEvent, PacketEvent
from ids.sink import JsonlSink

PACKET = PacketEvent(packet_id=1, timestamp=1.0)
FLOW = FlowRecord(flow_id="f1", end_reason=EndReason.CLOSED)
MESSAGE = MessageEvent(message_id="f1-1", flow_id="f1", data=b"hi")


def lines(path):
    return path.read_text(encoding="utf-8").splitlines()


def test_records_are_written_as_codec_lines_in_order(tmp_path):
    path = tmp_path / "out.jsonl"
    with JsonlSink(str(path)) as sink:
        sink.write(PACKET)
        sink.write(FLOW)
        sink.write(MESSAGE)
    assert lines(path) == [encode_line(PACKET), encode_line(FLOW), encode_line(MESSAGE)]
    assert [json.loads(line)["record_type"] for line in lines(path)] == [
        "packet",
        "flow",
        "message",
    ]


def test_flow_records_go_to_the_flows_path(tmp_path):
    out = tmp_path / "out.jsonl"
    flows = tmp_path / "flows.jsonl"
    with JsonlSink(str(out), flows_path=str(flows)) as sink:
        sink.write(PACKET)
        sink.write(FLOW)
        sink.write(MESSAGE)
    assert lines(out) == [encode_line(PACKET), encode_line(MESSAGE)]
    assert lines(flows) == [encode_line(FLOW)]


def test_stdout_is_the_default_and_stays_open(capsys):
    sink = JsonlSink()
    sink.write(PACKET)
    sink.close()
    assert not sys.stdout.closed
    print("after")
    assert capsys.readouterr().out == encode_line(PACKET) + "\nafter\n"


def test_file_output_is_flushed_every_n_records(tmp_path):
    path = tmp_path / "out.jsonl"
    sink = JsonlSink(str(path), flush_every=2)
    sink.write(PACKET)
    assert path.read_text(encoding="utf-8") == ""
    sink.write(PACKET)
    assert len(lines(path)) == 2
    sink.write(PACKET)
    sink.close()
    assert len(lines(path)) == 3


def test_unwritable_path_raises_oserror(tmp_path):
    with pytest.raises(OSError):
        JsonlSink(str(tmp_path / "missing" / "out.jsonl"))


def test_unwritable_flows_path_raises_and_closes_the_main_output(tmp_path):
    out = tmp_path / "out.jsonl"
    with pytest.raises(OSError):
        JsonlSink(str(out), flows_path=str(tmp_path / "missing" / "flows.jsonl"))
    assert out.read_text(encoding="utf-8") == ""
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/test_sink.py -q`
Expected: FAIL — collection error `ModuleNotFoundError: No module named 'ids.sink'`.

- [ ] **Step 3: Implement the sink**

`ids/sink.py`:

```python
from __future__ import annotations

import sys
from types import TracebackType
from typing import TextIO

from .codec import encode_line
from .model import FlowRecord, MessageEvent, PacketEvent


class _Output:
    __slots__ = ("flush_every", "owned", "pending", "stream")

    def __init__(self, path: str | None, flush_every: int) -> None:
        self.stream: TextIO
        if path is None or path == "-":
            self.stream = sys.stdout
            self.owned = False
            self.flush_every = 1
        else:
            self.stream = open(path, "w", encoding="utf-8")
            self.owned = True
            self.flush_every = max(1, flush_every)
        self.pending = 0

    def write(self, line: str) -> None:
        self.stream.write(line)
        self.stream.write("\n")
        self.pending += 1
        if self.pending >= self.flush_every:
            self.stream.flush()
            self.pending = 0

    def close(self) -> None:
        self.stream.flush()
        if self.owned:
            self.stream.close()


class JsonlSink:
    def __init__(
        self, path: str | None = "-", *, flows_path: str | None = None, flush_every: int = 100
    ) -> None:
        self._main = _Output(path, flush_every)
        try:
            self._flows = _Output(flows_path, flush_every) if flows_path is not None else None
        except OSError:
            self._main.close()
            raise
        self._closed = False

    def write(self, record: PacketEvent | MessageEvent | FlowRecord) -> None:
        if self._flows is not None and isinstance(record, FlowRecord):
            self._flows.write(encode_line(record))
        else:
            self._main.write(encode_line(record))

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._main.close()
        finally:
            if self._flows is not None:
                self._flows.close()

    def __enter__(self) -> JsonlSink:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/test_sink.py -q`
Expected: PASS.

Run: `uv run ruff check ids/sink.py tests/test_sink.py && uv run ruff format --check ids/sink.py tests/test_sink.py`
Expected: `All checks passed!` and `2 files already formatted`.

- [ ] **Step 5: Commit**

```bash
git add ids/sink.py tests/test_sink.py
git commit -m "feat: add jsonl sink with optional flows output"
```

---
### Task 6: CLI on the typed runner (restores the green suite)

**Files:**
- Modify (full rewrite): `ids/cli.py`
- Delete: `ids/logger.py`
- Test (full rewrite): `tests/test_cli.py`
- Modify: `README.md` (flag table rows only)

**Interfaces:**
- Consumes: `PcapSource`, `LiveSource`, `list_interfaces`, `ids.capture.live` module with `scapy_module` (Task 1); `PacketParser`, `ParserConfig` (Task 2); `Stats` incl. `written`, `packets_seen`, `dropped_count`, `skipped_count`, `packets_with_issues`, `to_dict` (Task 3); `Runner`, `Stage`, `UNKNOWN_POLICIES` (Task 4); `JsonlSink` (Task 5); `ParseError` (§2); `ids.__version__` (plan 1a, `"0.2.0"`); `tests/fake_scapy.FakeScapy` (Task 1).
- Produces (`ids.cli`, contract §9):
  - `non_negative_int(text: str) -> int`, `positive_int(text: str) -> int`, `non_negative_float(text: str) -> float` (argparse `type=` helpers; bad values raise `argparse.ArgumentTypeError` → exit 2; the float helper also rejects `nan`/`inf`).
  - `build_parser() -> argparse.ArgumentParser` (`prog="ids"`); flags owned by plan 1c except `-e/--events` (Task 7): `-i/--interface`, `-r/--pcap`, `-L/--list-interfaces` (required mutually exclusive group), `-o/--output` (`"-"`), `-c/--count` (`positive_int`, `None`), `--filter` (`dest="bpf_filter"`), `--capture-idle-timeout` (`non_negative_float`, `None`), `--max-payload-bytes` (`non_negative_int`, 65535), `--preview-limit` (`non_negative_int`, 256), `--unknown-policy` (`UNKNOWN_POLICIES`, `"emit"`), `--stats`, `-q/--quiet`, `--version`.
  - `build_stages(args: argparse.Namespace) -> list[Stage]` returning `[]` (plans 2–4 append their stages).
  - `main(argv: Sequence[str] | None = None) -> int`: exit 0 ok, 1 runtime error (`ParseError`, `OSError`, `RuntimeError`, printed as `error: <message>`), 2 usage (argparse), 130 interrupted (output flushed, stages flushed by the runner).
  - Order inside `main` that plans 2–4 rely on: `source = _open_source(args)` → `stats = Stats()` → `stages = build_stages(args)` → `packet_parser = PacketParser(ParserConfig(...))` → `with JsonlSink(args.output) as sink:` → `Runner(packet_parser, stages, sink, stats, unknown_policy=args.unknown_policy).run(source.items())`. Plan 4 changes the call to `build_stages(args, stats)` and passes `flows_path=args.flows_output` to `JsonlSink`.

- [ ] **Step 1: Write the failing test**

`tests/test_cli.py` (replaces the file):

```python
from __future__ import annotations

import base64
import itertools
import json
from pathlib import Path

import pytest
from fake_scapy import FakeScapy

from ids import __version__
from ids.capture import PcapSource, live
from ids.cli import main

FIXTURES = Path(__file__).resolve().parents[1] / "TEST" / "fixtures"
HANDSHAKE = str(FIXTURES / "01-tcp-handshake.pcap")
TCP_DATA = str(FIXTURES / "02-tcp-data.pcap")
HTTP_GET = str(FIXTURES / "04-http-get.pcap")
UNKNOWN = str(FIXTURES / "11-unknown-protocol.pcap")
MALFORMED = str(FIXTURES / "12-malformed.pcap")


def records(text):
    return [json.loads(line) for line in text.splitlines()]


def packet_records(text):
    """Later plans add flow and message records to the same stream; keep packets only."""
    return [record for record in records(text) if record["record_type"] == "packet"]


def packets(path):
    return packet_records(Path(path).read_text(encoding="utf-8"))


def summary_of(err):
    return json.loads(err[err.index("{\n") :])


def test_cli_writes_jsonl_to_a_file(tmp_path, capsys):
    output = tmp_path / "out.jsonl"
    assert main(["--pcap", HANDSHAKE, "--output", str(output)]) == 0
    events = packets(output)
    assert [event["packet_id"] for event in events] == [1, 2, 3]
    assert events[0]["event_type"] == "tcp_segment"
    assert events[0]["schema_version"] == 2
    assert capsys.readouterr().out == ""


def test_cli_defaults_to_stdout(capsys):
    assert main(["--pcap", HANDSHAKE]) == 0
    events = packet_records(capsys.readouterr().out)
    assert len(events) == 3
    assert events[0]["capture"]["source"] == "pcap"


def test_cli_stats_go_to_stderr(tmp_path, capsys):
    assert main(["-r", HANDSHAKE, "-o", str(tmp_path / "out.jsonl"), "--stats"]) == 0
    err = capsys.readouterr().err
    assert err.startswith(f"source: pcap {HANDSHAKE}\n")
    assert "from 3 packets (0 dropped, 0 skipped, 0 with issues)" in err
    summary = summary_of(err)
    assert summary["records_written"]["packet"] == 3
    assert summary["packets_seen"] == 3
    assert summary["event_types"] == {"tcp_segment": 3}
    assert summary["source"]["format"] == "pcap"


def test_cli_quiet_with_stats_prints_only_the_summary(tmp_path, capsys):
    assert main(["-r", HANDSHAKE, "-o", str(tmp_path / "o.jsonl"), "-q", "--stats"]) == 0
    assert json.loads(capsys.readouterr().err)["packets_seen"] == 3


def test_cli_quiet_suppresses_status_lines(tmp_path, capsys):
    assert main(["-r", HANDSHAKE, "-o", str(tmp_path / "o.jsonl"), "-q"]) == 0
    assert capsys.readouterr().err == ""


def test_cli_count_limits_packets(tmp_path):
    output = tmp_path / "out.jsonl"
    assert main(["-r", HANDSHAKE, "-c", "2", "-o", str(output)]) == 0
    assert len(packets(output)) == 2


def test_cli_unknown_policy_skip(tmp_path):
    output = tmp_path / "out.jsonl"
    assert main(["-r", HTTP_GET, "-o", str(output), "--unknown-policy", "skip"]) == 0
    assert [event["event_type"] for event in packets(output)] == ["http_request"]


def test_cli_skip_policy_on_the_unknown_fixture(tmp_path):
    output = tmp_path / "unknown.jsonl"
    assert main(["-r", UNKNOWN, "-o", str(output), "--unknown-policy", "skip"]) == 0
    assert packets(output) == []


def test_cli_limits_payload_bytes_and_preview(tmp_path):
    output = tmp_path / "out.jsonl"
    argv = ["-r", TCP_DATA, "-o", str(output), "--max-payload-bytes", "4", "--preview-limit", "2"]
    assert main(argv) == 0
    payload = packets(output)[0]["payload"]
    assert base64.b64decode(payload["data_b64"]) == b"PAYL"
    assert payload["data_truncated"] is True
    assert payload["preview"] == "PA"
    assert payload["length"] == 29


def test_cli_malformed_fixture_exits_cleanly(tmp_path, capsys):
    output = tmp_path / "malformed.jsonl"
    assert main(["-r", MALFORMED, "-o", str(output)]) == 0
    assert len(packets(output)) == 14
    assert "warning:" in capsys.readouterr().err


def test_cli_reports_a_missing_capture_file(capsys):
    assert main(["--pcap", "/nonexistent/nope.pcap"]) == 1
    assert "error:" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("content", "message"),
    [
        (b"", "capture file is empty"),
        (b"NOPE" + b"\x00" * 40, "unrecognised capture file format"),
    ],
)
def test_cli_reports_a_broken_capture_file(tmp_path, capsys, content, message):
    capture = tmp_path / "broken.pcap"
    capture.write_bytes(content)
    output = tmp_path / "out.jsonl"
    assert main(["-r", str(capture), "-o", str(output)]) == 1
    err = capsys.readouterr().err
    assert f"error: {message}\n" in err
    assert "Traceback" not in err
    assert output.read_text(encoding="utf-8") == ""


def test_cli_reports_an_unwritable_output_path(tmp_path, capsys):
    assert main(["-r", HANDSHAKE, "-o", str(tmp_path / "missing" / "out.jsonl")]) == 1
    err = capsys.readouterr().err
    assert "error:" in err
    assert "Traceback" not in err


def test_cli_reports_an_unknown_interface(capsys):
    assert main(["--interface", "definitely-not-an-interface"]) == 1
    assert "not found" in capsys.readouterr().err


def test_cli_capture_idle_timeout_stops_live_capture(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(live, "scapy_module", lambda: FakeScapy())
    output = tmp_path / "live.jsonl"
    assert main(["-i", "eth0", "--capture-idle-timeout", "0.05", "-o", str(output)]) == 0
    assert "without traffic" in capsys.readouterr().err
    assert packets(output) == []


def test_cli_interrupt_flushes_and_exits_130(tmp_path, monkeypatch, capsys):
    original = PcapSource.items

    def interrupted(self):
        yield from itertools.islice(original(self), 1)
        raise KeyboardInterrupt

    monkeypatch.setattr(PcapSource, "items", interrupted)
    output = tmp_path / "out.jsonl"
    assert main(["-r", HANDSHAKE, "-o", str(output)]) == 130
    assert [event["packet_id"] for event in packets(output)] == [1]
    assert "interrupted" in capsys.readouterr().err


def test_cli_list_interfaces(capsys):
    assert main(["--list-interfaces"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines
    assert any(line.startswith("lo") for line in lines)


def test_cli_requires_exactly_one_source():
    with pytest.raises(SystemExit) as caught:
        main([])
    assert caught.value.code == 2
    with pytest.raises(SystemExit) as caught:
        main(["--pcap", HANDSHAKE, "--interface", "lo"])
    assert caught.value.code == 2


def test_cli_rejects_an_unknown_policy():
    with pytest.raises(SystemExit) as caught:
        main(["--pcap", HANDSHAKE, "--unknown-policy", "nope"])
    assert caught.value.code == 2


@pytest.mark.parametrize(
    "argv",
    [
        ["--count", "0"],
        ["--count", "-1"],
        ["--count", "many"],
        ["--max-payload-bytes", "-5"],
        ["--preview-limit", "-1"],
        ["--capture-idle-timeout", "-0.5"],
        ["--capture-idle-timeout", "nan"],
        ["--capture-idle-timeout", "inf"],
    ],
)
def test_cli_rejects_bad_numbers(argv, capsys):
    with pytest.raises(SystemExit) as caught:
        main(["--pcap", HANDSHAKE, *argv])
    assert caught.value.code == 2
    assert argv[0] in capsys.readouterr().err


def test_cli_version(capsys):
    with pytest.raises(SystemExit) as caught:
        main(["--version"])
    assert caught.value.code == 0
    assert capsys.readouterr().out.strip() == f"ids {__version__}"
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/test_cli.py -q`
Expected: FAIL — collection error raised by the legacy `ids/cli.py`: `ImportError: cannot import name 'open_capture' from 'ids.capture'` (the legacy CLI imports names removed in Tasks 1–2).

- [ ] **Step 3: Implement the CLI**

`ids/cli.py` (replaces the file):

```python
from __future__ import annotations

import argparse
import json
import math
import sys
from collections.abc import Sequence

from . import __version__
from .capture import LiveSource, PcapSource, list_interfaces
from .issues import ParseError
from .parsers import PacketParser, ParserConfig
from .pipeline import UNKNOWN_POLICIES, Runner, Stage
from .sink import JsonlSink
from .stats import Stats

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_INTERRUPTED = 130
WARNING_PREVIEW = 3


def _parse_int(text: str) -> int:
    try:
        return int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not an integer: {text!r}") from None


def non_negative_int(text: str) -> int:
    value = _parse_int(text)
    if value < 0:
        raise argparse.ArgumentTypeError(f"must be >= 0, got {value}")
    return value


def positive_int(text: str) -> int:
    value = _parse_int(text)
    if value < 1:
        raise argparse.ArgumentTypeError(f"must be > 0, got {value}")
    return value


def non_negative_float(text: str) -> float:
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a number: {text!r}") from None
    if not math.isfinite(value) or value < 0:
        raise argparse.ArgumentTypeError(f"must be a finite number >= 0, got {text}")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ids",
        description="IDS pipeline: packet capture and parsing, then the analysis stages",
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--interface", "-i", metavar="NAME", help="capture live traffic from a network interface"
    )
    source.add_argument(
        "--pcap", "-r", metavar="FILE", help="read packets from a pcap or pcapng file"
    )
    source.add_argument(
        "--list-interfaces", "-L", action="store_true", help="list usable interfaces and exit"
    )
    parser.add_argument(
        "--output",
        "-o",
        metavar="FILE",
        default="-",
        help="JSON Lines output file (default: stdout)",
    )
    parser.add_argument(
        "--count",
        "-c",
        type=positive_int,
        default=None,
        metavar="N",
        help="stop after N input records",
    )
    parser.add_argument(
        "--filter",
        dest="bpf_filter",
        metavar="EXPR",
        default=None,
        help="BPF filter applied by the capture library (live capture only)",
    )
    parser.add_argument(
        "--capture-idle-timeout",
        type=non_negative_float,
        default=None,
        metavar="SECONDS",
        help="stop live capture after SECONDS without traffic (0: never)",
    )
    parser.add_argument(
        "--max-payload-bytes",
        type=non_negative_int,
        default=65535,
        metavar="BYTES",
        help="payload bytes kept in payload.data_b64 (default: 65535)",
    )
    parser.add_argument(
        "--preview-limit",
        type=non_negative_int,
        default=256,
        metavar="BYTES",
        help="payload bytes rendered in payload.preview (default: 256)",
    )
    parser.add_argument(
        "--unknown-policy",
        choices=UNKNOWN_POLICIES,
        default="emit",
        help="emit packets whose application protocol is UNKNOWN, or skip them",
    )
    parser.add_argument("--stats", action="store_true", help="print a JSON run summary to stderr")
    parser.add_argument(
        "--quiet", "-q", action="store_true", help="suppress status messages on stderr"
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def build_stages(args: argparse.Namespace) -> list[Stage]:
    return []


def _note(quiet: bool, message: str) -> None:
    if not quiet:
        print(message, file=sys.stderr, flush=True)


def _print_interfaces() -> int:
    try:
        interfaces = list_interfaces()
    except RuntimeError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_ERROR
    if not interfaces:
        print("no interfaces found", file=sys.stderr)
        return EXIT_ERROR
    width = max(len(entry["name"]) for entry in interfaces)
    for entry in interfaces:
        addresses = ", ".join(entry["ips"]) or "-"
        print(f"{entry['name']:<{width}}  {entry['mac'] or '-':<17}  {addresses}")
    return EXIT_OK


def _open_source(args: argparse.Namespace) -> PcapSource | LiveSource:
    if args.interface is not None:
        return LiveSource(
            args.interface,
            bpf_filter=args.bpf_filter,
            count=args.count,
            capture_idle_timeout=args.capture_idle_timeout,
        )
    return PcapSource(args.pcap, count=args.count)


def _report(args: argparse.Namespace, source: PcapSource | LiveSource, stats: Stats) -> None:
    warnings = source.warnings
    for warning in warnings[:WARNING_PREVIEW]:
        print(f"warning: {warning}", file=sys.stderr)
    hidden = len(warnings) - WARNING_PREVIEW
    if hidden > 0:
        print(f"warning: {hidden} more warnings not shown", file=sys.stderr)
    _note(
        args.quiet,
        f"wrote {stats.written} records from {stats.packets_seen} packets"
        f" ({stats.dropped_count} dropped, {stats.skipped_count} skipped,"
        f" {stats.packets_with_issues} with issues)",
    )
    if args.stats:
        summary = stats.to_dict()
        summary["source"] = source.describe()
        print(json.dumps(summary, indent=2), file=sys.stderr)


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.list_interfaces:
        return _print_interfaces()

    source = _open_source(args)
    stats = Stats()
    stages = build_stages(args)
    packet_parser = PacketParser(
        ParserConfig(max_payload_bytes=args.max_payload_bytes, preview_limit=args.preview_limit)
    )
    interrupted = False

    _note(args.quiet, f"source: {source.source} {source.origin}")
    try:
        with JsonlSink(args.output) as sink:
            runner = Runner(packet_parser, stages, sink, stats, unknown_policy=args.unknown_policy)
            try:
                runner.run(source.items())
            except KeyboardInterrupt:
                interrupted = True
                _note(args.quiet, "interrupted, flushing what has been processed so far")
    except (ParseError, OSError, RuntimeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_ERROR
    finally:
        source.close()

    _report(args, source, stats)
    return EXIT_INTERRUPTED if interrupted else EXIT_OK
```

Delete the legacy writer (its only caller was the legacy CLI):

```bash
git rm -q ids/logger.py
```

`README.md`, table "Tham số" — replace these rows (match by text; leave every other line as it is):

| Old row | New row |
|---|---|
| ``| `--idle-timeout` | Dừng live capture sau N giây không có traffic |`` | ``| `--capture-idle-timeout` | Dừng live capture sau N giây không có traffic (`0` = không dừng) |`` |
| ``| `--quiet`, `-q` | Tắt thông báo tiến độ |`` | ``| `--quiet`, `-q` | Tắt các dòng trạng thái trên stderr |`` |

and insert this row directly after the `--preview-limit` row:

```markdown
| `--max-payload-bytes` | Số byte payload tối đa giữ trong `payload.data_b64` (mặc định 65535) |
```

- [ ] **Step 4: Run the tests to verify they pass — full suite green from here on**

Run: `uv run pytest tests/test_cli.py -q`
Expected: PASS.

Run: `uv run pytest -q`
Expected: PASS, 0 failures, 0 errors. **This commit restores the green suite** (green-rule checkpoint for plan 1c).

Run: `uv run python main.py --version`
Expected: `ids 0.2.0`.

Run: `git grep -n -E -e "logger|JsonlWriter|open_capture|PcapFileCapture|LiveCapture" -e "--idle-timeout" -e "[^_]idle_timeout" -- ids tests README.md`
Expected: no output.

Run: `uv run ruff check . && uv run ruff format --check .`
Expected: `All checks passed!` and `… files already formatted`.

- [ ] **Step 5: Commit**

```bash
git add ids/cli.py tests/test_cli.py README.md
git commit -m "feat: wire the cli onto the typed runner"
```

(`git rm` in Step 3 already staged `ids/logger.py`.)

---
### Task 7: JSON Lines events source and `--events`

**Files:**
- Create: `ids/capture/events.py`
- Modify: `ids/capture/__init__.py` (export `EventsSource`)
- Modify: `ids/cli.py` (import, `-e/--events`, `_open_source`, `_report` annotation)
- Create: `tests/test_events_source.py`
- Modify: `tests/test_cli.py` (append events tests)
- Modify: `README.md` (usage line + flag row)

**Interfaces:**
- Consumes: `ids.codec.decode_packet(obj: object) -> tuple[PacketEvent, list[Issue]]` and `encode_line` (plan 1a, §5); `PacketEvent`, `Issue`; `PcapSource`, `PacketParser` (tests); `ids.cli` internals from Task 6.
- Produces: `ids.capture.events.EventsSource(path: str | Path, *, count: int | None = None)` (also exported from `ids.capture`): `source = "events"`, `origin` (`"stdin"` for `"-"`, else the path), `warnings: list[str]`, `events_loaded: int`, `skipped_records: int`, `items() -> Iterator[PacketEvent]`, `describe() -> dict[str, object]` (`source`, `origin`, `count_limit`, `events_loaded`, `skipped_records`), `close() -> None`. CLI flag `-e/--events FILE` in the source group.

`EventsSource.items()` rules:

- Reads bytes (`"-"` → `sys.stdin.buffer`, never closed; a path → opened `"rb"` inside `items()`, missing file → `OSError`). Physical lines are numbered from 1; blank lines are skipped but counted.
- `json.loads(line, parse_constant=...)`: any `ValueError` (bad JSON, invalid UTF-8, `NaN`/`Infinity`/`-Infinity`) → `PacketEvent(packet_id=<line number>, issues=[Issue("load", "invalid_json", str(error), {"line": n})])`. A UTF-8 BOM is accepted (`json.loads` on bytes handles it).
- A `str` `record_type` of `"flow"` or `"message"` → skipped, `skipped_records += 1`, warning `line <n>: skipped record_type '<type>'`.
- Everything else → `decode_packet(obj)`; stage outputs are cleared (`decoded`, `normalized`, `preprocess_status`, `processing_action`, `reason`, `flow`, and issues with stage `decoder`/`preprocess`/`flow`), then the load issues are appended to `event.issues`.
- `count` limits yielded events; the source stops right after the `count`-th event without reading another line (matters for stdin).

- [ ] **Step 1: Write the failing tests**

`tests/test_events_source.py`:

```python
from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from ids.capture import EventsSource, PcapSource
from ids.codec import encode_line
from ids.parsers import PacketParser

FIXTURES = Path(__file__).resolve().parents[1] / "TEST" / "fixtures"


def write_lines(tmp_path, *lines):
    path = tmp_path / "events.jsonl"
    encoded = [line if isinstance(line, bytes) else line.encode("utf-8") for line in lines]
    path.write_bytes(b"\n".join(encoded) + b"\n")
    return path


def load(path, **options):
    source = EventsSource(path, **options)
    return source, list(source.items())


def codes(event):
    return [(issue.stage, issue.code) for issue in event.issues]


def test_parsed_events_round_trip(tmp_path):
    parser = PacketParser()
    originals = [parser.parse(raw) for raw in PcapSource(FIXTURES / "04-http-get.pcap").items()]
    source, loaded = load(write_lines(tmp_path, *(encode_line(event) for event in originals)))
    assert loaded == originals
    assert source.describe()["events_loaded"] == 2


def test_blank_lines_count_and_non_json_becomes_a_stub(tmp_path):
    path = write_lines(tmp_path, "", '{"packet_id": 7, "timestamp": 1.5}', "   ", "not json")
    _, events = load(path)
    assert [(event.packet_id, event.timestamp) for event in events] == [(7, 1.5), (4, None)]
    assert events[0].issues == []
    (issue,) = events[1].issues
    assert (issue.stage, issue.code, issue.context) == ("load", "invalid_json", {"line": 4})


def test_flow_and_message_lines_are_skipped_with_a_warning(tmp_path):
    path = write_lines(
        tmp_path,
        '{"record_type": "flow", "flow_id": "x"}',
        '{"record_type": "packet", "packet_id": 2}',
        '{"record_type": "message"}',
    )
    source, events = load(path)
    assert [event.packet_id for event in events] == [2]
    assert source.warnings == [
        "line 1: skipped record_type 'flow'",
        "line 3: skipped record_type 'message'",
    ]
    assert source.describe()["skipped_records"] == 2


def test_unhashable_record_type_is_loaded_as_unsupported_schema(tmp_path):
    _, events = load(write_lines(tmp_path, '{"record_type": ["flow"], "packet_id": 1}'))
    assert [event.packet_id for event in events] == [1]
    assert ("load", "unsupported_schema") in codes(events[0])


def test_other_schema_versions_still_load(tmp_path):
    _, (event,) = load(write_lines(tmp_path, '{"schema_version": 9, "packet_id": 1}'))
    assert event.packet_id == 1
    assert ("load", "unsupported_schema") in codes(event)


def test_load_issues_follow_the_carried_issues(tmp_path):
    line = json.dumps(
        {
            "packet_id": 1,
            "timestamp": "late",
            "issues": [
                {"stage": "network", "code": "truncated_packet", "message": "short", "context": {}}
            ],
        }
    )
    _, (event,) = load(write_lines(tmp_path, line))
    assert event.timestamp is None
    assert codes(event) == [("network", "truncated_packet"), ("load", "invalid_type")]


def test_stage_outputs_are_cleared_on_load(tmp_path):
    line = json.dumps(
        {
            "packet_id": 1,
            "preprocess_status": "invalid",
            "processing_action": "drop",
            "reason": ["invalid_timestamp"],
            "flow": {"flow_id": "abc"},
            "normalized": {"protocol": "TCP"},
            "decoded": {"kind": "http", "status": "decoded"},
            "issues": [
                {"stage": "preprocess", "code": "x", "message": "old verdict", "context": {}},
                {"stage": "network", "code": "truncated_packet", "message": "short", "context": {}},
            ],
        }
    )
    _, (event,) = load(write_lines(tmp_path, line))
    assert event.preprocess_status is None
    assert event.processing_action is None
    assert event.reason == []
    assert event.flow is None
    assert event.normalized is None
    assert event.decoded is None
    assert codes(event) == [("network", "truncated_packet")]


def test_count_limit(tmp_path):
    path = write_lines(tmp_path, '{"packet_id": 1}', '{"packet_id": 2}', '{"packet_id": 3}')
    _, events = load(path, count=2)
    assert [event.packet_id for event in events] == [1, 2]


def test_dash_reads_stdin(monkeypatch):
    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(b'{"packet_id": 1}\n')))
    source, events = load("-")
    assert [event.packet_id for event in events] == [1]
    assert source.origin == "stdin"


def test_invalid_utf8_line_is_a_stub_and_bom_is_accepted(tmp_path):
    path = write_lines(
        tmp_path,
        b'\xef\xbb\xbf{"packet_id": 1}',
        b'{"packet_id": "\xff"}',
        b'{"packet_id": 3}',
    )
    _, events = load(path)
    assert [event.packet_id for event in events] == [1, 2, 3]
    assert [codes(event) for event in events] == [[], [("load", "invalid_json")], []]


def test_nan_and_infinity_are_invalid_json(tmp_path):
    path = write_lines(
        tmp_path,
        '{"packet_id": 5, "timestamp": NaN}',
        '{"packet_id": 6, "timestamp": -Infinity}',
    )
    _, events = load(path)
    assert [(event.packet_id, event.timestamp) for event in events] == [(1, None), (2, None)]
    assert [codes(event) for event in events] == [[("load", "invalid_json")]] * 2
    assert [json.loads(encode_line(event))["packet_id"] for event in events] == [1, 2]


def test_missing_file_raises_oserror(tmp_path):
    with pytest.raises(OSError):
        list(EventsSource(tmp_path / "missing.jsonl").items())
```

Append to `tests/test_cli.py` (add `import io` to the stdlib import block, between `import base64` and `import itertools`):

```python
def test_cli_events_round_trip_keeps_parser_fields(tmp_path):
    first = tmp_path / "first.jsonl"
    second = tmp_path / "second.jsonl"
    assert main(["-r", HTTP_GET, "-o", str(first)]) == 0
    assert main(["-e", str(first), "-o", str(second)]) == 0
    keys = (
        "packet_id",
        "timestamp",
        "capture",
        "link",
        "network",
        "transport",
        "application",
        "payload",
    )
    expected = [{key: record[key] for key in keys} for record in packets(first)]
    assert [{key: record[key] for key in keys} for record in packets(second)] == expected
    assert len(expected) == 2


def test_cli_reads_events_from_stdin(tmp_path, monkeypatch):
    first = tmp_path / "first.jsonl"
    assert main(["-r", HTTP_GET, "-o", str(first)]) == 0
    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(first.read_bytes())))
    second = tmp_path / "second.jsonl"
    assert main(["-e", "-", "-o", str(second)]) == 0
    assert [record["packet_id"] for record in packets(second)] == [1, 2]


def test_cli_events_with_nan_line_completes(tmp_path):
    events = tmp_path / "events.jsonl"
    events.write_text(
        'not json\n{"packet_id": 2, "timestamp": NaN}\n{"packet_id": 3, "timestamp": 1.0}\n',
        encoding="utf-8",
    )
    output = tmp_path / "out.jsonl"
    assert main(["-e", str(events), "-o", str(output)]) == 0
    written = packets(output)
    assert [record["packet_id"] for record in written] == [1, 2, 3]
    assert [[(i["stage"], i["code"]) for i in record["issues"]] for record in written] == [
        [("load", "invalid_json")],
        [("load", "invalid_json")],
        [],
    ]


def test_cli_events_stats_report_skipped_records(tmp_path, capsys):
    events = tmp_path / "events.jsonl"
    events.write_text('{"packet_id": 1}\n{"record_type": "flow"}\n', encoding="utf-8")
    output = tmp_path / "out.jsonl"
    assert main(["-e", str(events), "-o", str(output), "--stats", "-q"]) == 0
    err = capsys.readouterr().err
    assert "warning: line 2: skipped record_type 'flow'\n" in err
    summary = summary_of(err)
    assert summary["packets_seen"] == 1
    assert summary["source"]["source"] == "events"
    assert summary["source"]["skipped_records"] == 1


def test_cli_events_count_limit(tmp_path):
    events = tmp_path / "events.jsonl"
    events.write_text('{"packet_id": 1}\n{"packet_id": 2}\n{"packet_id": 3}\n', encoding="utf-8")
    output = tmp_path / "out.jsonl"
    assert main(["-e", str(events), "-c", "2", "-o", str(output)]) == 0
    assert [record["packet_id"] for record in packets(output)] == [1, 2]


def test_cli_reports_a_missing_events_file(capsys):
    assert main(["--events", "/nonexistent/events.jsonl"]) == 1
    assert "error:" in capsys.readouterr().err


def test_cli_events_excludes_other_sources():
    with pytest.raises(SystemExit) as caught:
        main(["-e", "events.jsonl", "-r", HANDSHAKE])
    assert caught.value.code == 2
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_events_source.py tests/test_cli.py -q`
Expected: FAIL — `tests/test_events_source.py` collection error `ImportError: cannot import name 'EventsSource' from 'ids.capture'`; in `tests/test_cli.py` the new tests exit with `SystemExit: 2` (`unrecognized arguments: -e` / `--events`), the Task 6 tests still pass.

- [ ] **Step 3: Implement the events source and the flag**

`ids/capture/events.py`:

```python
from __future__ import annotations

import json
import sys
from collections.abc import Iterable, Iterator
from pathlib import Path

from ..codec import decode_packet
from ..issues import Issue
from ..model import PacketEvent

SKIPPED_RECORD_TYPES = frozenset(("flow", "message"))
STAGE_OUTPUT_ISSUE_STAGES = frozenset(("decoder", "preprocess", "flow"))


def _reject_constant(name: str) -> object:
    raise ValueError(f"{name} is not valid JSON")


def _clear_stage_outputs(event: PacketEvent) -> None:
    """Drop what the decoder, preprocessor and flow tracker wrote; they run again."""
    event.decoded = None
    event.normalized = None
    event.preprocess_status = None
    event.processing_action = None
    event.reason.clear()
    event.flow = None
    event.issues[:] = [
        issue for issue in event.issues if issue.stage not in STAGE_OUTPUT_ISSUE_STAGES
    ]


class EventsSource:
    """Schema v2 packet events from a JSON Lines file; "-" reads stdin."""

    source = "events"

    def __init__(self, path: str | Path, *, count: int | None = None) -> None:
        self.path = str(path)
        self.origin = "stdin" if self.path == "-" else self.path
        self.count = count
        self.warnings: list[str] = []
        self.events_loaded = 0
        self.skipped_records = 0

    def close(self) -> None:
        """The input file lives inside items(); stdin is never closed."""

    def describe(self) -> dict[str, object]:
        return {
            "source": self.source,
            "origin": self.origin,
            "count_limit": self.count,
            "events_loaded": self.events_loaded,
            "skipped_records": self.skipped_records,
        }

    def items(self) -> Iterator[PacketEvent]:
        if self.count is not None and self.count <= 0:
            return
        if self.path == "-":
            yield from self._read(sys.stdin.buffer)
            return
        with open(self.path, "rb") as handle:
            yield from self._read(handle)

    def _read(self, lines: Iterable[bytes]) -> Iterator[PacketEvent]:
        for line_number, line in enumerate(lines, start=1):
            if not line.strip():
                continue
            event = self._load(line_number, line)
            if event is None:
                continue
            self.events_loaded += 1
            yield event
            if self.count is not None and self.events_loaded >= self.count:
                return

    def _load(self, line_number: int, line: bytes) -> PacketEvent | None:
        try:
            obj = json.loads(line, parse_constant=_reject_constant)
        except ValueError as error:
            issue = Issue("load", "invalid_json", str(error), {"line": line_number})
            return PacketEvent(packet_id=line_number, issues=[issue])
        record_type = obj.get("record_type") if isinstance(obj, dict) else None
        if isinstance(record_type, str) and record_type in SKIPPED_RECORD_TYPES:
            self.skipped_records += 1
            self.warnings.append(f"line {line_number}: skipped record_type {record_type!r}")
            return None
        event, issues = decode_packet(obj)
        _clear_stage_outputs(event)
        event.issues.extend(issues)
        return event
```

`ids/capture/__init__.py` (replaces the file):

```python
from __future__ import annotations

from .base import CaptureSource, linktype_name
from .events import EventsSource
from .live import LiveSource, list_interfaces
from .pcap import PcapSource

__all__ = [
    "CaptureSource",
    "EventsSource",
    "LiveSource",
    "PcapSource",
    "linktype_name",
    "list_interfaces",
]
```

`ids/cli.py` — four edits:

1. Import line `from .capture import LiveSource, PcapSource, list_interfaces` becomes:

```python
from .capture import EventsSource, LiveSource, PcapSource, list_interfaces
```

2. In `build_parser`, directly after the `source.add_argument("--pcap", "-r", ...)` call, insert:

```python
    source.add_argument(
        "--events",
        "-e",
        metavar="FILE",
        help="read schema v2 packet events from a JSON Lines file ('-' = stdin)",
    )
```

3. Replace `_open_source` with:

```python
def _open_source(args: argparse.Namespace) -> PcapSource | LiveSource | EventsSource:
    if args.interface is not None:
        return LiveSource(
            args.interface,
            bpf_filter=args.bpf_filter,
            count=args.count,
            capture_idle_timeout=args.capture_idle_timeout,
        )
    if args.events is not None:
        return EventsSource(args.events, count=args.count)
    return PcapSource(args.pcap, count=args.count)
```

4. Change the `_report` signature line to:

```python
def _report(
    args: argparse.Namespace, source: PcapSource | LiveSource | EventsSource, stats: Stats
) -> None:
```

`README.md`:

- In the "Chạy" code block, directly after the line `python main.py --pcap test.pcap           # đọc file PCAP / PCAPNG`, insert:

```text
python main.py --events events.jsonl      # đọc event JSONL schema v2 (- = stdin)
```

- In the "Tham số" table, directly after the `--pcap`, `-r` row, insert:

```markdown
| `--events`, `-e` | Đọc event JSONL schema v2 (`-` = stdin); bỏ qua dòng `flow` / `message` |
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/test_events_source.py tests/test_cli.py -q`
Expected: PASS.

Run: `uv run pytest -q`
Expected: PASS (still green).

Run: `uv run ruff check . && uv run ruff format --check .`
Expected: `All checks passed!` and `… files already formatted`.

- [ ] **Step 5: Commit**

```bash
git add ids/capture/events.py ids/capture/__init__.py ids/cli.py tests/test_events_source.py tests/test_cli.py README.md
git commit -m "feat: add jsonl events source and --events flag"
```

---
### Task 8: Move the capture-parser cases to `TEST/capture-parser/`

**Files:**
- Move (`git mv`, no content regeneration — plan 5 regenerates): `TEST/README.md` → `TEST/capture-parser/README.md`, `TEST/generate_fixtures.py` → `TEST/capture-parser/generate_fixtures.py`, `TEST/fixtures/` → `TEST/capture-parser/fixtures/`, `TEST/case-*/` → `TEST/capture-parser/case-*/`
- Modify: `TEST/capture-parser/generate_fixtures.py:9-10`, `TEST/capture-parser/README.md` (paths), `README.md` (TEST paths)
- Create: `TEST/README.md` (group index)
- Modify (full rewrite): `TEST/run_cases.sh`
- Test: `tests/test_pipeline.py`, `tests/test_cli.py`, `tests/test_runner.py`, `tests/test_events_source.py` (fixture path line)

**Interfaces:**
- Consumes: CLI flags `--pcap`, `--events`, `--output`, `--stats` (Tasks 6–7); `--flows-output` is detected at run time (added by plan 4).
- Produces: layout `TEST/<group>/{README.md, generate_fixtures.py, fixtures/, <case dirs>}`; `TEST/run_cases.sh [FIXTURE ...]` — no argument = every `TEST/*/fixtures/*`; each argument is a fixture path relative to the repo root. Per fixture `TEST/<group>/fixtures/<name>.<ext>`: `.pcap`/`.pcapng` → `--pcap`, `.jsonl` → `--events`, other extensions ignored; case dir `TEST/<group>/case-<name>` when `<name>` starts with a digit, else `TEST/<group>/<name>`; writes `command.txt`, `output.jsonl`, `stdout.txt`, `summary.txt` (stderr), and `flows.jsonl` only when `main.py --help` lists `--flows-output`. Plan 5 calls it per fixture to commit one case at a time.

- [ ] **Step 1: Point the tests at the new fixture directory**

In each of `tests/test_pipeline.py`, `tests/test_cli.py`, `tests/test_runner.py`, `tests/test_events_source.py`, replace the line

```python
FIXTURES = Path(__file__).resolve().parents[1] / "TEST" / "fixtures"
```

with

```python
FIXTURES = Path(__file__).resolve().parents[1] / "TEST" / "capture-parser" / "fixtures"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_pipeline.py -q`
Expected: FAIL — `FileNotFoundError: [Errno 2] No such file or directory: '…/TEST/capture-parser/fixtures/01-tcp-handshake.pcap'`.

- [ ] **Step 3: Move the files, fix the generator path, rewrite the runner script and the indexes**

```bash
mkdir -p TEST/capture-parser
git mv TEST/README.md TEST/generate_fixtures.py TEST/fixtures TEST/capture-parser/
git mv TEST/case-* TEST/capture-parser/
```

`TEST/capture-parser/generate_fixtures.py` lines 9–10 become:

```python
ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "TEST" / "capture-parser" / "fixtures"
```

`TEST/run_cases.sh` (replaces the file; it is run with `sh`):

```sh
#!/bin/sh
# Regenerates case results. No argument: every TEST/*/fixtures/* file.
# Arguments: fixture paths relative to the repository root.
set -eu
cd "$(dirname "$0")/.."

PYTHON=${PYTHON:-.venv/bin/python}
if [ ! -x "$PYTHON" ]; then
    PYTHON=python3
fi

flows=no
if "$PYTHON" main.py --help | grep -q -- --flows-output; then
    flows=yes
fi

if [ "$#" -eq 0 ]; then
    set -- TEST/*/fixtures/*
fi

for fixture in "$@"; do
    [ -f "$fixture" ] || continue
    group=$(dirname "$(dirname "$fixture")")
    base=$(basename "$fixture")
    name=${base%.*}
    case "$base" in
        *.pcap | *.pcapng) input="--pcap $fixture" ;;
        *.jsonl) input="--events $fixture" ;;
        *) continue ;;
    esac
    case "$name" in
        [0-9]*) case_dir="$group/case-$name" ;;
        *) case_dir="$group/$name" ;;
    esac
    mkdir -p "$case_dir"
    command="$PYTHON main.py $input --output $case_dir/output.jsonl"
    if [ "$flows" = yes ]; then
        command="$command --flows-output $case_dir/flows.jsonl"
    fi
    command="$command --stats"
    printf '%s\n' "$command" > "$case_dir/command.txt"
    sh -c "$command" > "$case_dir/stdout.txt" 2> "$case_dir/summary.txt"
    records=$(awk 'END{print NR}' "$case_dir/output.jsonl")
    printf '%-40s records=%s\n' "$case_dir" "$records"
done
```

`TEST/README.md` (new root index):

````markdown
# TEST: test case theo module

Mỗi nhóm có README riêng (danh sách case, fixture, kết quả mong đợi), script sinh
fixture `generate_fixtures.py`, thư mục `fixtures/` và một thư mục kết quả cho mỗi case.

| Nhóm | Nội dung |
|---|---|
| [`capture-parser/`](capture-parser/README.md) | 13 case của module Packet Capture & Parser |

## Cách chạy

```bash
sh TEST/run_cases.sh                                            # mọi nhóm
sh TEST/run_cases.sh TEST/capture-parser/fixtures/04-http-get.pcap   # một fixture
```

Fixture `.pcap` / `.pcapng` chạy với `--pcap`, fixture `.jsonl` chạy với `--events`.
Fixture tên bắt đầu bằng số ghi kết quả vào `case-<tên>/`, các fixture khác vào `<tên>/`.
Mỗi thư mục kết quả có `command.txt`, `output.jsonl`, `stdout.txt`, `summary.txt`, và
`flows.jsonl` khi CLI hỗ trợ `--flows-output`.
````

`TEST/capture-parser/README.md` — replace these lines (match by text, leave the rest unchanged; the case outputs are regenerated by plan 5):

| Old line | New line |
|---|---|
| `# TEST: kết quả test case bắt buộc` | `# TEST/capture-parser: test case của Packet Capture & Parser` |
| `uv run python TEST/generate_fixtures.py   # sinh lại toàn bộ fixture (deterministic)` | `uv run python TEST/capture-parser/generate_fixtures.py   # sinh lại fixture (deterministic)` |
| `sh TEST/run_cases.sh                      # chạy lại toàn bộ case, ghi output.jsonl` | `sh TEST/run_cases.sh TEST/capture-parser/fixtures/*      # chạy lại các case của nhóm này` |
| `python main.py --pcap TEST/fixtures/01-tcp-handshake.pcap --output out.jsonl --stats` | `python main.py --pcap TEST/capture-parser/fixtures/01-tcp-handshake.pcap --output out.jsonl --stats` |

and add this row at the end of the `| File | Nội dung |` table (after the `stdout.txt` row):

```markdown
| `flows.jsonl` | Flow record, chỉ có khi CLI hỗ trợ `--flows-output` |
```

`README.md` — replace these lines (match by text):

| Old line | New line |
|---|---|
| ``Ví dụ output: `TEST/case-04-http-get/output.jsonl`, `TEST/case-12-malformed/output.jsonl`.`` | ``Ví dụ output: `TEST/capture-parser/case-04-http-get/output.jsonl`, `TEST/capture-parser/case-12-malformed/output.jsonl`.`` |
| `TEST/                fixture, lệnh chạy và kết quả của từng test case` | `TEST/                test case theo module: TEST/<nhóm>/ (fixture, lệnh chạy, kết quả)` |

- [ ] **Step 4: Verify the move**

Run: `uv run pytest -q`
Expected: PASS (green).

Run: `git grep -n -e '"TEST" / "fixtures"' -e "TEST/fixtures" -- tests TEST/capture-parser/generate_fixtures.py TEST/capture-parser/README.md TEST/README.md TEST/run_cases.sh README.md`
Expected: no output. (The stored `TEST/capture-parser/case-*/command.txt` and `summary.txt` still name the old paths; plan 5 regenerates them.)

Run: `uv run python -c "import runpy; g = runpy.run_path('TEST/capture-parser/generate_fixtures.py'); print(g['FIXTURES'].relative_to(g['ROOT']), g['FIXTURES'].is_dir())"`
Expected: `TEST/capture-parser/fixtures True`.

Run: `sh -n TEST/run_cases.sh && sh TEST/run_cases.sh TEST/capture-parser/fixtures/01-tcp-handshake.pcap`
Expected: one line `TEST/capture-parser/case-01-tcp-handshake    records=3` (more records once plan 4 adds flows).

Run: `git status --short TEST`
Expected: only `TEST/capture-parser/case-01-tcp-handshake/*` files modified (plus the staged renames). Discard that regenerated output; regeneration belongs to plan 5:

```bash
git restore TEST/capture-parser/case-01-tcp-handshake
```

Run: `uv run ruff check . && uv run ruff format --check .`
Expected: `All checks passed!` and `… files already formatted`.

- [ ] **Step 5: Commit**

```bash
git add TEST/README.md TEST/run_cases.sh TEST/capture-parser/generate_fixtures.py TEST/capture-parser/README.md README.md tests/test_pipeline.py tests/test_cli.py tests/test_runner.py tests/test_events_source.py
git commit -m "test: move capture-parser cases to TEST/capture-parser"
```

(The `git mv` renames in Step 3 are already staged.)

---

## Spec coverage (slice of plan 1c)

| Requirement | Task |
|---|---|
| Spec §4 "process() returns None on fallback, fake sha256" | 2 (fallback event, no payload), 4 (every item is written, dropped or skipped) |
| Spec §4 "`json.dumps(default=str)`" | 5 (`codec.encode_line` only), 2/7 (encode in tests) |
| Spec §4 "`--idle-timeout` collides" | 1, 6 (`--capture-idle-timeout`) |
| Spec §4 "dead `open_capture`, `getattr(source, 'warnings')`, mixed namedtuple" | 1 (`warnings` on the protocol, dataclass records), 6 (`source.warnings`) |
| Spec §4 "live linktype hardcoded" | 1 (`conf.l2types.layer2num`) |
| Spec §6.1 stage stamped by the caller | 2 (`Issues.scoped` per step), 4 (stage name on stage failures) |
| Spec §6.4 non-JSON line → stub with line number | 7 |
| Spec §10.1 runner, isolation, one outcome per item | 4 |
| Spec §10.2 sources | 1, 7 |
| Spec §10.3 sink, flows file | 5 (plan 4 adds `--flows-output`) |
| Spec §10.4 CLI flags owned by 1c, negative numbers → exit 2 | 6, 7 |
| Spec §11.1 migrated tests keep behavioural assertions | 1, 2, 6 |
| Spec §11.2 `TEST/capture-parser/` move, `run_cases.sh` regenerates every group | 8 |
| Interfaces §0 green rule, deletion of `describe`/`errors.py` | 2, 6 (green restored) |
