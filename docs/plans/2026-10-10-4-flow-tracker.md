# Flow/Connection Tracker Implementation Plan (plan 4)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `ids/flow/`: group decoded, preprocessed `PacketEvent`s into bidirectional TCP/UDP flows, track TCP connection state, expire/evict/flush flows as `FlowRecord`s, reassemble SMTP DATA bodies into `MessageEvent`s, and wire the tracker into the runner, live capture (`Tick`) and the CLI.

**Architecture:** `key.py` turns a packet into a direction-free `FlowKey` plus its endpoints and derives the `flow_id`. `tcp.py` is a small per-flow state machine (`TcpConnection`). `records.py` holds the mutable per-flow state (`FlowState`) that fills a `FlowRecord` in place and returns a `FlowRef` per packet. `table.py` owns the three `OrderedDict` lanes, the monotonic clock, expiry, eviction, port reuse and flush. `smtp.py` reassembles DATA bodies per SMTP flow. `stage.py` adapts the table to the runner's `Stage` protocol; `ids/capture/live.py` emits `Tick`s while idle and `ids/cli.py` exposes the flags.

**Tech Stack:** Python >= 3.10 stdlib (`collections.OrderedDict`, `hashlib`, `ipaddress`, `re`, `dataclasses`), pytest, ruff, uv; scapy only to build frames in tests and for live capture.

**Spec:** `docs/specs/2026-10-10-decoder-preprocessor-flow-tracker.md` (§9 Flow/Connection Tracker, §10 Pipeline and I/O, §11.3 cases T07–T13) and the shared contract `docs/plans/2026-10-10-interfaces.md` (§3.5 flow model, §3.6 events, §7 sources, §8 runner, §9 CLI, §10 stage APIs). Read both before starting.

## Global Constraints

- `requires-python >= 3.10`; no 3.11+ APIs (`tomllib`, `typing.Self`, `datetime.UTC`, `binascii` `strict_mode`).
- Every module, tests included, starts with `from __future__ import annotations` (after the module docstring, if any).
- No new runtime dependency; stdlib only in `ids/flow/`. Scapy stays for live capture and for building frames in tests.
- Model types come from `ids.model` exactly as in contract §3 (`FlowRecord`, `FlowRef`, `Endpoint`, `DirectionStats`, `TcpFlowStats`, `TcpState`, `Direction`, `EndReason`, `PacketEvent`, `MessageEvent`, `PreprocessStatus`, `Tick`, ...). Nothing in contract §3 is changed; everything new lives in `ids/flow/`.
- `FlowConfig` defaults (contract §10): `tcp_idle_timeout=300.0`, `udp_idle_timeout=60.0`, `tcp_closed_timeout=5.0`, `max_flows=100_000`, `max_message_bytes=1_048_576`. `FlowTrackerStage(config=None, stats=None)`, `name = "flow"`, property `active_count`.
- Stage order in `build_stages()` is always `[DecoderStage, PreprocessorStage, FlowTrackerStage]`.
- `flow_id = sha1(f"{proto}|{lo_ip}:{lo_port}|{hi_ip}:{hi_port}|{round(start_time*1e6)}")` first 16 hex chars, dotted-quad strings in the hash input.
- Ruff: line length 100, rules `E,F,W,I,UP,B,C4,SIM,RUF`, ignore `SIM108,SIM115,BLE001`, target py310.
- Commits: one task per commit, lower-case conventional messages (`feat: …`, `test: …`). Do not push.
- Green rule (contract §0): plans 1a–3 are merged before this plan starts, so `uv run pytest -q` must pass after every commit of this plan.

## Review Focus

1. **Loaded JSONL events with millisecond timestamps.** The preprocessor writes seconds to `normalized.timestamp` but leaves the raw `timestamp` in ms; using the raw value would push the clock 1000× ahead and expire every flow. Expect the tracker to use `normalized.timestamp` when present. Tests: `tests/test_flow_records.py::test_packet_time_prefers_the_normalized_timestamp` (Task 3), `tests/test_flow_stage.py::test_normalized_timestamps_drive_the_clock` (Task 6).
2. **TCP events without `seq`/`ack`** (sparse JSONL events whose transport block has only ports and flags). Expect a FIN/FIN/ACK exchange to still reach `CLOSED` (any peer ACK acknowledges a FIN of unknown sequence) and no exception. Test: `tests/test_flow_tcp.py::test_close_without_sequence_numbers_uses_any_peer_ack` (Task 2).
3. **A DATA segment captured shorter than its TCP length** (`--max-payload-bytes` cap or a short snaplen). Expect `gap = true` and the next segment to stay aligned on sequence numbers instead of being trimmed as overlap. Test: `tests/test_flow_smtp.py::test_segment_captured_shorter_than_its_length_sets_gap` (Task 5).
4. **Midstream SMTP capture where the server is endpoint A** (first packet seen is a server reply). Expect the body to be reassembled anyway, because the client is the side that sent `DATA`. Test: `tests/test_flow_smtp.py::test_client_seen_as_endpoint_b_in_a_midstream_capture` (Task 5).
5. **A flow evicted (`--max-flows`) or idle-expired in the middle of a DATA body.** Expect the partial body as a `MessageEvent` with `complete = false`, written before that flow's record. Test: `tests/test_flow_smtp.py::test_flow_export_mid_message_emits_it_incomplete_before_the_record` (Task 5).

---

## Decisions this plan fixes (read before Task 1)

These resolve points the spec leaves open or states inconsistently. They are pinned by tests.

- **Task order.** The brief listed the flow table before the per-flow statistics. The table stores `FlowState` objects, so this plan builds `records.py` (Task 3) before `table.py` (Task 4). Same six commits, same content.
- **End reason at end of input.** Spec §9.4 says every remaining flow ends with `end_of_input`, but T09 expects `closed`/`reset` for connections that closed shortly before the capture ended. Flows in the closed lane therefore keep `closed`/`reset` at flush; open TCP flows and UDP flows get `end_of_input`. Eviction always reports `evicted`, whatever the lane.
- **Expiry rule.** A flow expires when `clock - touched > timeout` (strict: a gap of exactly `--udp-idle-timeout` stays in the flow, spec §9.3 "within"). `touched` is the tracker clock at the flow's latest packet, so a late packet with an old timestamp still counts as fresh activity and lanes stay ordered. When several lane fronts are expired at once they leave in order of their deadline (`touched + timeout`), ties in lane order `tcp_open`, `tcp_closed`, `udp`. Flush and eviction pick the least recently touched front across lanes.
- **Time fields.** `start_time` is the smallest and `last_seen` the largest packet timestamp seen; `duration = round(last_seen - start_time, 6)`. `flow_id` uses the timestamp of the packet that created the flow.
- **TCP edge rules.** RST from any state, `CLOSED` included, gives `RESET`. A repeated FIN from the same side keeps the first recorded `fin_seq`. With no sequence numbers, any ACK from the peer acknowledges the FIN. A SYN without ACK starts a new flow only when the key sits in the closed lane; on an open flow it is counted and ignored.
- **SMTP reassembly.** The client is the side that sent `DATA` (the forward side in a normal capture). Collection starts at the client's next sequence number after the `DATA` segment, once a `354` reply arrives from the other side. `data` keeps the terminator `\r\n.\r\n` and the dot-stuffing (the MIME decoder strips both). A body that hits the cap and then reaches the terminator is `complete = true, truncated = true`. At flow export a partial body is emitted only if at least one byte was collected. `packet_ids` lists only packets that contributed new bytes.
- **Application protocol of a flow.** Rank = (payload evidence, confidence), where payload evidence means detection method `payload` or `port+payload`; a higher rank replaces the current value, ties keep the earlier one. `normalized.application_protocol` wins over `application.protocol`. A packet with an application but no detection ranks `(0, 0.0)`.
- **What is tracked.** `PacketEvent`s whose `preprocess_status` is not `INVALID` (valid, partial, or `None` when no preprocessor ran), with a finite timestamp and a usable 5-tuple (TCP/UDP transport, IPv4 addresses that `ipaddress` accepts, ports 0–65535). Normalized values win field by field over raw ones. Everything else keeps `flow = None`.
- **CLI ranges.** `--tcp-idle-timeout`, `--udp-idle-timeout`, `--tcp-closed-timeout` use `non_negative_float`; `--max-flows` and `--max-message-bytes` use `positive_int` (plan 1c helpers).

## File structure

| File | Task | Responsibility |
|---|---|---|
| `ids/flow/__init__.py` | 1, 6 | package docstring; from Task 6 re-exports `FlowConfig`, `FlowTrackerStage` |
| `ids/flow/key.py` | 1 | `FlowKey`, `make_key(event)`, `flow_id(key, start_time)` |
| `ids/flow/tcp.py` | 2 | `seq_ge`, `is_syn_ack`, `is_new_syn`, `TERMINAL_STATES`, `TcpConnection` |
| `ids/flow/records.py` | 3, 5 | `packet_time`, `packet_bytes`, `payload_bytes`, `FlowState` (fills `FlowRecord`, returns `FlowRef`) |
| `ids/flow/table.py` | 4, 5 | `FlowTable`: lanes, clock, expiry, eviction, port reuse, flush, SMTP hookup |
| `ids/flow/smtp.py` | 5 | `SmtpReassembler` |
| `ids/flow/stage.py` | 6 | `FlowConfig`, `FlowTrackerStage` |
| `ids/capture/live.py` | 6 | `tick` parameter, `Tick` on idle polls |
| `ids/cli.py` | 6 | flow flags, `build_stages(args, stats)`, `flows_path`, live `tick=True` |
| `tests/flow_events.py` | 1 | hand-built `PacketEvent` helpers for flow unit tests (not collected) |
| `tests/test_flow_key.py` | 1 | key symmetry, usability, flow id format |
| `tests/test_flow_tcp.py` | 2 | every TCP transition, FIN-ACK math, wrap-around |
| `tests/test_flow_records.py` | 3 | counters, directions, initiator, app ranking, time fields |
| `tests/test_flow_table.py` | 4, 5 | lanes, expiry order, T12, eviction, linger, port reuse, clock, T11 |
| `tests/test_flow_smtp.py` | 5 | reassembly cases and table integration |
| `tests/test_flow_stage.py` | 6 | stage filtering, tick, flush stats |
| `tests/test_flow_pipeline.py` | 6 | real `Runner` runs: T07, T08, T09, output order, invalid events |
| `tests/test_cli_flow.py` | 6 | flow flags end to end through `main()` |
| `tests/test_live.py` | 6 | tick emission, live run expiring a flow on ticks |

---
### Task 1: Flow key and flow id

**Files:**
- Create: `ids/flow/__init__.py`
- Create: `ids/flow/key.py`
- Create: `tests/flow_events.py`
- Test: `tests/test_flow_key.py`

**Interfaces:**
- Consumes: `ids.model.PacketEvent`, `TcpInfo`, `UdpInfo`, `Ipv4Info`, `Normalized`, `Endpoint`, `Payload`, `TcpFlags`, `ApplicationInfo`, `Detection`, `SmtpSession` (contract §3).
- Produces:
  - `FlowKey(proto: str, lo_ip: int, lo_port: int, hi_ip: int, hi_port: int)` — `@dataclass(frozen=True, slots=True)`, hashable, `(lo_ip, lo_port) <= (hi_ip, hi_port)`.
  - `make_key(event: PacketEvent) -> tuple[FlowKey, Endpoint, Endpoint] | None` — `(key, source endpoint, destination endpoint)` in packet direction; endpoint `ip` is the canonical dotted quad that was parsed.
  - `flow_id(key: FlowKey, start_time: float) -> str` — 16 lower-case hex chars.
  - Test helpers in `tests/flow_events.py`: `T0 = 1759000000.0`, `CLIENT = ("10.0.0.1", 40000)`, `SERVER = ("10.0.0.2", 80)`, `flags(spec: str) -> TcpFlags` (letters `S A F R P`), `app(protocol, method, confidence, message=None) -> ApplicationInfo`, `smtp_app(message=None) -> ApplicationInfo`, `tcp_event(packet_id, timestamp, src, dst, spec="A", *, seq=0, ack=0, payload=b"", application=None) -> PacketEvent` (IPv4 `total_length = 40 + len(payload)`), `udp_event(packet_id, timestamp, src, dst, *, payload=b"", application=None) -> PacketEvent` (`total_length = 28 + len(payload)`).

- [ ] **Step 1: Write the test helpers and the failing test**

Create `tests/flow_events.py`:

```python
"""Hand-built PacketEvents for the flow tracker unit tests."""

from __future__ import annotations

from ids.model import (
    ApplicationInfo,
    Detection,
    Ipv4Info,
    PacketEvent,
    Payload,
    SmtpSession,
    TcpFlags,
    TcpInfo,
    UdpInfo,
)

T0 = 1759000000.0
CLIENT = ("10.0.0.1", 40000)
SERVER = ("10.0.0.2", 80)


def flags(spec: str) -> TcpFlags:
    """'S' syn, 'A' ack, 'F' fin, 'R' rst, 'P' psh; e.g. flags('SA') is a SYN-ACK."""
    return TcpFlags(
        fin="F" in spec, syn="S" in spec, rst="R" in spec, psh="P" in spec, ack="A" in spec
    )


def app(protocol: str, method: str, confidence: float, message=None) -> ApplicationInfo:
    return ApplicationInfo(
        protocol=protocol,
        detection=Detection(protocol=protocol, method=method, confidence=confidence),
        message=message,
    )


def smtp_app(message: SmtpSession | None = None) -> ApplicationInfo:
    return app("SMTP", "port+payload", 1.0, message)


def tcp_event(
    packet_id: int,
    timestamp: float,
    src: tuple[str, int],
    dst: tuple[str, int],
    spec: str = "A",
    *,
    seq: int | None = 0,
    ack: int | None = 0,
    payload: bytes = b"",
    application: ApplicationInfo | None = None,
) -> PacketEvent:
    return PacketEvent(
        packet_id=packet_id,
        timestamp=timestamp,
        network=Ipv4Info(
            protocol="IPv4", src_ip=src[0], dst_ip=dst[0], total_length=40 + len(payload)
        ),
        transport=TcpInfo(
            src_port=src[1],
            dst_port=dst[1],
            seq=seq,
            ack=ack,
            flags=flags(spec),
            payload_length=len(payload),
        ),
        application=application,
        payload=Payload(length=len(payload), data=payload),
    )


def udp_event(
    packet_id: int,
    timestamp: float,
    src: tuple[str, int],
    dst: tuple[str, int],
    *,
    payload: bytes = b"",
    application: ApplicationInfo | None = None,
) -> PacketEvent:
    return PacketEvent(
        packet_id=packet_id,
        timestamp=timestamp,
        network=Ipv4Info(
            protocol="IPv4", src_ip=src[0], dst_ip=dst[0], total_length=28 + len(payload)
        ),
        transport=UdpInfo(
            src_port=src[1], dst_port=dst[1], length=8 + len(payload), payload_length=len(payload)
        ),
        application=application,
        payload=Payload(length=len(payload), data=payload),
    )
```

Create `tests/test_flow_key.py`:

```python
from __future__ import annotations

import pytest
from flow_events import CLIENT, SERVER, T0, tcp_event, udp_event

from ids.flow.key import flow_id, make_key
from ids.model import Endpoint, Ipv4Info, Normalized, PacketEvent, TcpInfo


def key_of(event: PacketEvent):
    found = make_key(event)
    assert found is not None
    return found[0]


def test_both_directions_share_one_key():
    forward = make_key(tcp_event(1, T0, CLIENT, SERVER))
    backward = make_key(tcp_event(2, T0, SERVER, CLIENT))
    assert forward is not None and backward is not None
    assert forward[0] == backward[0]
    assert hash(forward[0]) == hash(backward[0])


def test_endpoints_are_returned_in_packet_direction():
    _, src, dst = make_key(tcp_event(1, T0, SERVER, CLIENT))
    assert src == Endpoint("10.0.0.2", 80)
    assert dst == Endpoint("10.0.0.1", 40000)


def test_different_source_ports_give_different_keys():
    first = key_of(tcp_event(1, T0, ("10.0.0.1", 40000), SERVER))
    second = key_of(tcp_event(2, T0, ("10.0.0.1", 40001), SERVER))
    assert first != second


def test_tcp_and_udp_on_the_same_tuple_are_different_keys():
    assert key_of(tcp_event(1, T0, CLIENT, SERVER)) != key_of(udp_event(2, T0, CLIENT, SERVER))


def test_normalized_addresses_win_over_raw_ones():
    event = tcp_event(1, T0, ("010.000.000.001", 40000), SERVER)
    assert make_key(event) is None  # raw form is not canonical
    event.normalized = Normalized(src_ip="10.0.0.1", src_port=40000)
    key, src, _ = make_key(event)
    assert src == Endpoint("10.0.0.1", 40000)
    assert key == key_of(tcp_event(2, T0, CLIENT, SERVER))


@pytest.mark.parametrize(
    "event",
    [
        PacketEvent(packet_id=1, timestamp=T0, network=Ipv4Info(src_ip="10.0.0.1")),
        PacketEvent(
            packet_id=1,
            timestamp=T0,
            transport=TcpInfo(src_port=1, dst_port=2),
        ),
        tcp_event(1, T0, ("999.0.0.1", 1), SERVER),
        tcp_event(1, T0, ("10.0.0.1", 70000), SERVER),
        PacketEvent(
            packet_id=1,
            timestamp=T0,
            network=Ipv4Info(src_ip="10.0.0.1", dst_ip="10.0.0.2"),
            transport=TcpInfo(src_port=None, dst_port=80),
        ),
        PacketEvent(
            packet_id=1,
            timestamp=T0,
            network=Ipv4Info(src_ip="10.0.0.1", dst_ip="10.0.0.2"),
            transport=TcpInfo(src_port=True, dst_port=80),
        ),
    ],
    ids=["no-transport", "no-network", "bad-ip", "port-out-of-range", "port-missing", "bool"],
)
def test_events_without_a_usable_five_tuple_have_no_key(event):
    assert make_key(event) is None


def test_port_zero_is_still_a_usable_key():
    assert make_key(udp_event(1, T0, ("10.0.0.1", 0), SERVER)) is not None


def test_flow_id_has_the_documented_format():
    key = key_of(tcp_event(1, T0, CLIENT, SERVER))
    # sha1("TCP|10.0.0.1:40000|10.0.0.2:80|1759000000000000")[:16]
    assert flow_id(key, T0) == "39d401a88e1bbbfa"


def test_flow_id_orders_endpoints_numerically_not_as_text():
    key = key_of(udp_event(1, T0, ("10.0.0.10", 53), ("10.0.0.9", 5353)))
    # sha1("UDP|10.0.0.9:5353|10.0.0.10:53|1759000000500000")[:16]
    assert flow_id(key, T0 + 0.5) == "eb09350a5d961f6c"


def test_flow_id_is_the_same_from_either_direction_and_on_every_call():
    forward = key_of(tcp_event(1, T0, CLIENT, SERVER))
    backward = key_of(tcp_event(2, T0, SERVER, CLIENT))
    assert flow_id(forward, T0) == flow_id(backward, T0) == flow_id(forward, T0)


def test_a_new_start_time_gives_a_new_flow_id():
    key = key_of(tcp_event(1, T0, CLIENT, SERVER))
    assert flow_id(key, T0) != flow_id(key, T0 + 0.000001)
```

The two flow id literals were computed with `hashlib.sha1(...).hexdigest()[:16]` over the strings in the comments; they pin the hash input format, including numeric (not textual) endpoint ordering.

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/test_flow_key.py -q`
Expected: collection error `ModuleNotFoundError: No module named 'ids.flow'`.

- [ ] **Step 3: Implement**

Create `ids/flow/__init__.py`:

```python
"""Flow/Connection Tracker: groups packets into TCP/UDP flows."""

from __future__ import annotations
```

Create `ids/flow/key.py`:

```python
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from ipaddress import IPv4Address

from ..model import Endpoint, PacketEvent, TcpInfo, UdpInfo


@dataclass(frozen=True, slots=True)
class FlowKey:
    """Direction-free identity of a flow: (ip, port) endpoints sorted numerically."""

    proto: str
    lo_ip: int
    lo_port: int
    hi_ip: int
    hi_port: int


def _ip_int(value: object) -> int | None:
    if not isinstance(value, str):
        return None
    try:
        return int(IPv4Address(value))
    except ValueError:
        return None


def _port(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 65535:
        return None
    return value


def _prefer(normalized: object, raw: object) -> object:
    return raw if normalized is None else normalized


def make_key(event: PacketEvent) -> tuple[FlowKey, Endpoint, Endpoint] | None:
    """Return (key, source endpoint, destination endpoint), or None without a usable 5-tuple.

    Normalized addresses and ports win over the raw ones field by field.
    """
    transport = event.transport
    if isinstance(transport, TcpInfo):
        proto = "TCP"
    elif isinstance(transport, UdpInfo):
        proto = "UDP"
    else:
        return None
    src_ip: object = event.network.src_ip if event.network is not None else None
    dst_ip: object = event.network.dst_ip if event.network is not None else None
    src_port: object = transport.src_port
    dst_port: object = transport.dst_port
    normalized = event.normalized
    if normalized is not None:
        src_ip = _prefer(normalized.src_ip, src_ip)
        dst_ip = _prefer(normalized.dst_ip, dst_ip)
        src_port = _prefer(normalized.src_port, src_port)
        dst_port = _prefer(normalized.dst_port, dst_port)
    src_int = _ip_int(src_ip)
    dst_int = _ip_int(dst_ip)
    sport = _port(src_port)
    dport = _port(dst_port)
    if src_int is None or dst_int is None or sport is None or dport is None:
        return None
    if (src_int, sport) <= (dst_int, dport):
        key = FlowKey(proto, src_int, sport, dst_int, dport)
    else:
        key = FlowKey(proto, dst_int, dport, src_int, sport)
    # _ip_int succeeded, so both addresses are canonical dotted-quad strings.
    return key, Endpoint(str(src_ip), sport), Endpoint(str(dst_ip), dport)


def flow_id(key: FlowKey, start_time: float) -> str:
    """First 16 hex chars of sha1 over the key and the start time in microseconds."""
    text = (
        f"{key.proto}|{IPv4Address(key.lo_ip)}:{key.lo_port}"
        f"|{IPv4Address(key.hi_ip)}:{key.hi_port}|{round(start_time * 1e6)}"
    )
    return hashlib.sha1(text.encode("ascii")).hexdigest()[:16]
```

`ipaddress.IPv4Address` rejects leading zeros, surrounding blanks and short forms, so an accepted string is already canonical and can be stored in `Endpoint` as is. Raw values such as `010.000.000.001` only become usable through `normalized.src_ip`.

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/test_flow_key.py -q`
Expected: `16 passed`.

- [ ] **Step 5: Full suite and lint**

Run: `uv run pytest -q`
Expected: all tests pass (0 failed, 0 errors).

Run: `uv run ruff check ids/flow tests/flow_events.py tests/test_flow_key.py && uv run ruff format --check ids/flow tests/flow_events.py tests/test_flow_key.py`
Expected: `All checks passed!` and `N files already formatted` (no file would be reformatted).

- [ ] **Step 6: Commit**

```bash
git add ids/flow/__init__.py ids/flow/key.py tests/flow_events.py tests/test_flow_key.py
git commit -m "feat: add flow key and flow id"
```

---
### Task 2: TCP connection state machine

**Files:**
- Create: `ids/flow/tcp.py`
- Test: `tests/test_flow_tcp.py`

**Interfaces:**
- Consumes: `ids.model.TcpFlags`, `TcpFlowStats`, `TcpState`; test helper `flags()` from Task 1.
- Produces:
  - `SEQ_MOD = 1 << 32`; `TERMINAL_STATES: frozenset[TcpState]` = `{CLOSED, RESET}`.
  - `seq_ge(a: int, b: int) -> bool` — `a` at or after `b` in 32-bit wrap-around space.
  - `is_syn_ack(flags: TcpFlags | None) -> bool`; `is_new_syn(flags: TcpFlags | None) -> bool` (SYN without ACK).
  - `TcpConnection(first_flags: TcpFlags | None)` with attribute `stats: TcpFlowStats` (the object later placed in `FlowRecord.tcp`), property `state -> TcpState`, and `update(forward: bool, flags: TcpFlags | None, seq: int | None, ack: int | None, payload_length: int) -> TcpState`. `forward=True` means sent by endpoint A. `update` is called for every packet, the first one included.

Transition table implemented (spec §9.2), evaluated per packet in this order:

1. Count flags (`syn_count`, `ack_count`, `fin_count`, `rst_count`; a SYN-ACK counts in both SYN and ACK).
2. RST → `RESET` from any state.
3. `CLOSED`/`RESET` → no change (no regression).
4. `HANDSHAKE`: SYN-ACK from B is remembered; a later ACK without SYN from A → `ESTABLISHED`, `handshake_complete = True`.
5. `NEW`: ACK flag remembered per side; once both sides sent one → `ESTABLISHED`.
6. FIN (first one per side) from `NEW`/`HANDSHAKE`/`ESTABLISHED`/`CLOSING` → `CLOSING`, `fin_seq[side] = (seq + payload_length) mod 2**32`.
7. `CLOSING` and ACK flag: the peer's FIN is acknowledged when `seq_ge(ack, fin_seq + 1)`; both FINs acknowledged → `CLOSED`.

The first packet sets the starting state: SYN (with or without ACK) → `HANDSHAKE`, anything else → `NEW` with `midstream = True`. A SYN-ACK first means the table makes its destination endpoint A, so that SYN-ACK arrives as `forward=False`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_flow_tcp.py`:

```python
from __future__ import annotations

import pytest
from flow_events import flags

from ids.flow.tcp import SEQ_MOD, TcpConnection, is_new_syn, is_syn_ack, seq_ge
from ids.model import TcpState

A = True  # sent by endpoint A (forward)
B = False  # sent by endpoint B (backward)
HANDSHAKE = [(A, "S", 1000, 0, 0), (B, "SA", 5000, 1001, 0), (A, "A", 1001, 5001, 0)]


def run(packets):
    """packets: (forward, flags, seq, ack, payload_length); the first one opens the flow."""
    connection = TcpConnection(flags(packets[0][1]))
    states = [
        connection.update(forward, flags(spec), seq, ack, length)
        for forward, spec, seq, ack, length in packets
    ]
    return connection, states


def test_three_way_handshake_reaches_established():
    connection, states = run(HANDSHAKE)
    assert states == [TcpState.HANDSHAKE, TcpState.HANDSHAKE, TcpState.ESTABLISHED]
    assert connection.stats.handshake_complete is True
    assert connection.stats.midstream is False


def test_ack_from_a_before_the_syn_ack_does_not_establish():
    _, states = run([(A, "S", 1000, 0, 0), (A, "A", 1001, 0, 0)])
    assert states[-1] is TcpState.HANDSHAKE


def test_ack_from_b_after_its_syn_ack_does_not_establish():
    _, states = run([*HANDSHAKE[:2], (B, "A", 5001, 1001, 0)])
    assert states[-1] is TcpState.HANDSHAKE


def test_syn_ack_seen_first_completes_on_the_ack_from_its_destination():
    # The flow table makes the SYN-ACK's destination endpoint A, so the SYN-ACK is backward.
    connection, states = run([(B, "SA", 5000, 1001, 0), (A, "A", 1001, 5001, 0)])
    assert states == [TcpState.HANDSHAKE, TcpState.ESTABLISHED]
    assert connection.stats.handshake_complete is True
    assert connection.stats.midstream is False


def test_midstream_flow_starts_new_and_establishes_on_acks_both_ways():
    connection, states = run([(A, "PA", 1, 1, 10), (A, "A", 11, 1, 0), (B, "A", 1, 11, 0)])
    assert states == [TcpState.NEW, TcpState.NEW, TcpState.ESTABLISHED]
    assert connection.stats.midstream is True
    assert connection.stats.handshake_complete is False


def test_new_flow_needs_the_ack_flag_from_both_sides():
    _, states = run([(A, "A", 1, 1, 0), (B, "P", 1, 0, 5)])
    assert states[-1] is TcpState.NEW


def test_first_packet_without_flags_is_midstream_new():
    connection = TcpConnection(None)
    assert connection.update(A, None, None, None, 0) is TcpState.NEW
    assert connection.stats.midstream is True
    assert (connection.stats.syn_count, connection.stats.ack_count) == (0, 0)


def test_graceful_close_with_separate_acks():
    _, states = run(
        [
            *HANDSHAKE,
            (A, "FA", 1001, 5001, 0),
            (B, "A", 5001, 1002, 0),
            (B, "FA", 5001, 1002, 0),
            (A, "A", 1002, 5002, 0),
        ]
    )
    assert states[3:] == [TcpState.CLOSING, TcpState.CLOSING, TcpState.CLOSING, TcpState.CLOSED]


def test_fin_ack_from_the_peer_acknowledges_and_closes_its_side():
    _, states = run([*HANDSHAKE, (A, "FA", 1001, 5001, 0), (B, "FA", 5001, 1002, 0)])
    assert states[-1] is TcpState.CLOSING
    _, states = run(
        [*HANDSHAKE, (A, "FA", 1001, 5001, 0), (B, "FA", 5001, 1002, 0), (A, "A", 1002, 5002, 0)]
    )
    assert states[-1] is TcpState.CLOSED


def test_simultaneous_fins_close_after_both_acks():
    _, states = run(
        [
            *HANDSHAKE,
            (A, "FA", 1001, 5001, 0),
            (B, "FA", 5001, 1001, 0),
            (A, "A", 1002, 5002, 0),
            (B, "A", 5002, 1002, 0),
        ]
    )
    assert states[3:] == [TcpState.CLOSING, TcpState.CLOSING, TcpState.CLOSING, TcpState.CLOSED]


def test_ack_equal_to_the_fin_sequence_does_not_acknowledge_it():
    _, states = run(
        [*HANDSHAKE, (A, "FA", 1001, 5001, 0), (B, "FA", 5001, 1001, 0), (A, "A", 1002, 5002, 0)]
    )
    assert states[-1] is TcpState.CLOSING


def test_fin_carrying_payload_is_acknowledged_after_the_payload():
    _, states = run(
        [
            *HANDSHAKE,
            (A, "FPA", 1001, 5001, 100),
            (B, "FA", 5001, 1101, 0),  # acknowledges the data, not the FIN
            (A, "A", 1102, 5002, 0),
        ]
    )
    assert states[-1] is TcpState.CLOSING
    _, states = run(
        [*HANDSHAKE, (A, "FPA", 1001, 5001, 100), (B, "FA", 5001, 1102, 0), (A, "A", 1102, 5002, 0)]
    )
    assert states[-1] is TcpState.CLOSED


@pytest.mark.parametrize(
    ("fin_seq", "length", "ack", "closed"),
    [
        (SEQ_MOD - 1, 0, 0, True),
        (SEQ_MOD - 1, 0, SEQ_MOD - 1, False),
        (SEQ_MOD - 3, 5, 3, True),
        (SEQ_MOD - 3, 5, 2, False),
    ],
)
def test_fin_acknowledgement_wraps_around_the_sequence_space(fin_seq, length, ack, closed):
    _, states = run(
        [
            (A, "PA", 1, 1, 0),
            (B, "A", 1, 1, 0),
            (B, "FA", 7000, 1, 0),
            (A, "A", 1, 7001, 0),
            (A, "FPA", fin_seq, 7001, length),
            (B, "A", 7001, ack, 0),
        ]
    )
    assert (states[-1] is TcpState.CLOSED) is closed


def test_seq_ge_handles_wrap_around():
    assert seq_ge(5, 5)
    assert seq_ge(0, SEQ_MOD - 1)
    assert not seq_ge(SEQ_MOD - 1, 0)
    assert seq_ge(100, 99)
    assert not seq_ge(99, 100)


def test_close_without_sequence_numbers_uses_any_peer_ack():
    _, states = run(
        [
            (A, "A", None, None, 0),
            (B, "A", None, None, 0),
            (A, "FA", None, None, 0),
            (B, "FA", None, None, 0),
            (A, "A", None, None, 0),
        ]
    )
    assert states == [
        TcpState.NEW,
        TcpState.ESTABLISHED,
        TcpState.CLOSING,
        TcpState.CLOSING,
        TcpState.CLOSED,
    ]


@pytest.mark.parametrize(
    "before",
    [
        [(A, "PA", 1, 1, 5)],
        [(A, "S", 1000, 0, 0)],
        HANDSHAKE,
        [*HANDSHAKE, (A, "FA", 1001, 5001, 0)],
        [*HANDSHAKE, (A, "FA", 1001, 5001, 0), (B, "FA", 5001, 1002, 0), (A, "A", 1002, 5002, 0)],
    ],
    ids=["new", "handshake", "established", "closing", "closed"],
)
def test_rst_from_any_state_resets(before):
    connection, states = run([*before, (B, "R", 5002, 0, 0)])
    assert states[-1] is TcpState.RESET
    assert connection.stats.rst_count == 1


def test_rst_ack_during_the_handshake_resets():
    _, states = run([(A, "S", 1000, 0, 0), (B, "RA", 0, 1001, 0)])
    assert states == [TcpState.HANDSHAKE, TcpState.RESET]


def test_syn_on_an_established_flow_does_not_move_it_back():
    connection, states = run([*HANDSHAKE, (A, "S", 9000, 0, 0)])
    assert states[-1] is TcpState.ESTABLISHED
    assert connection.stats.syn_count == 3


def test_packets_after_close_or_reset_keep_the_final_state():
    closed = [*HANDSHAKE, (A, "FA", 1001, 5001, 0), (B, "FA", 5001, 1002, 0)]
    closed.append((A, "A", 1002, 5002, 0))
    connection, states = run([*closed, (A, "PA", 1002, 5002, 10), (B, "S", 1, 0, 0)])
    assert states[-2:] == [TcpState.CLOSED, TcpState.CLOSED]
    connection, states = run([*HANDSHAKE, (A, "R", 1001, 0, 0), (B, "FA", 5001, 1001, 0)])
    assert states[-1] is TcpState.RESET
    assert connection.stats.fin_count == 1


def test_flag_counters_count_packets_with_each_flag():
    connection, _ = run(
        [
            *HANDSHAKE,
            (A, "PA", 1001, 5001, 20),
            (A, "FA", 1021, 5001, 0),
            (B, "FA", 5001, 1022, 0),
            (A, "A", 1022, 5002, 0),
        ]
    )
    stats = connection.stats
    assert (stats.syn_count, stats.ack_count, stats.fin_count, stats.rst_count) == (2, 6, 2, 0)
    assert stats.state is TcpState.CLOSED


def test_syn_classification_helpers():
    assert is_new_syn(flags("S")) and not is_new_syn(flags("SA")) and not is_new_syn(None)
    assert is_syn_ack(flags("SA")) and not is_syn_ack(flags("S")) and not is_syn_ack(None)
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/test_flow_tcp.py -q`
Expected: collection error `ModuleNotFoundError: No module named 'ids.flow.tcp'`.

- [ ] **Step 3: Implement**

Create `ids/flow/tcp.py`:

```python
from __future__ import annotations

from ..model import TcpFlags, TcpFlowStats, TcpState

SEQ_MOD = 1 << 32
_HALF = 1 << 31
TERMINAL_STATES = frozenset({TcpState.CLOSED, TcpState.RESET})


def seq_ge(a: int, b: int) -> bool:
    """True when sequence number `a` is at or after `b` in 32-bit wrap-around space."""
    return (a - b) % SEQ_MOD < _HALF


def is_syn_ack(flags: TcpFlags | None) -> bool:
    return flags is not None and bool(flags.syn) and bool(flags.ack)


def is_new_syn(flags: TcpFlags | None) -> bool:
    """SYN without ACK: the first packet of a new connection attempt."""
    return flags is not None and bool(flags.syn) and not flags.ack


class TcpConnection:
    """TCP state of one flow. Side 0 is endpoint A (forward), side 1 endpoint B.

    The first packet decides the starting state: a SYN gives HANDSHAKE, anything else NEW with
    `midstream`. `update` must then be called for every packet, the first one included.
    """

    __slots__ = ("_ack_seen", "_fin_acked", "_fin_seen", "_fin_seq", "_syn_ack_from_b", "stats")

    def __init__(self, first_flags: TcpFlags | None) -> None:
        syn = first_flags is not None and bool(first_flags.syn)
        self.stats = TcpFlowStats(
            state=TcpState.HANDSHAKE if syn else TcpState.NEW, midstream=not syn
        )
        self._syn_ack_from_b = False
        self._ack_seen = [False, False]
        self._fin_seen = [False, False]
        self._fin_seq: list[int | None] = [None, None]
        self._fin_acked = [False, False]

    @property
    def state(self) -> TcpState:
        return self.stats.state

    def update(
        self,
        forward: bool,
        flags: TcpFlags | None,
        seq: int | None,
        ack: int | None,
        payload_length: int,
    ) -> TcpState:
        """Count the packet's flags, apply one transition, return the state after it."""
        stats = self.stats
        syn = fin = rst = has_ack = False
        if flags is not None:
            syn, fin = bool(flags.syn), bool(flags.fin)
            rst, has_ack = bool(flags.rst), bool(flags.ack)
        if syn:
            stats.syn_count += 1
        if has_ack:
            stats.ack_count += 1
        if fin:
            stats.fin_count += 1
        if rst:
            stats.rst_count += 1
            stats.state = TcpState.RESET
            return TcpState.RESET

        state = self.state
        if state in TERMINAL_STATES:
            return state
        side = 0 if forward else 1
        peer = 1 - side

        if state is TcpState.HANDSHAKE:
            if syn and has_ack and not forward:
                self._syn_ack_from_b = True
            elif forward and has_ack and not syn and self._syn_ack_from_b:
                state = TcpState.ESTABLISHED
                stats.handshake_complete = True
        elif state is TcpState.NEW and has_ack:
            self._ack_seen[side] = True
            if self._ack_seen[peer]:
                state = TcpState.ESTABLISHED

        if fin and not self._fin_seen[side]:
            self._fin_seen[side] = True
            # The FIN occupies the sequence number right after the segment's payload.
            self._fin_seq[side] = None if seq is None else (seq + payload_length) % SEQ_MOD
            state = TcpState.CLOSING

        if state is TcpState.CLOSING and has_ack and self._fin_seen[peer]:
            fin_seq = self._fin_seq[peer]
            # Without sequence numbers (sparse loaded events) any ACK from the peer counts.
            if fin_seq is None or ack is None or seq_ge(ack, (fin_seq + 1) % SEQ_MOD):
                self._fin_acked[peer] = True
            if self._fin_acked[0] and self._fin_acked[1]:
                state = TcpState.CLOSED

        stats.state = state
        return state
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/test_flow_tcp.py -q`
Expected: `28 passed`.

- [ ] **Step 5: Full suite and lint**

Run: `uv run pytest -q`
Expected: all tests pass (0 failed, 0 errors).

Run: `uv run ruff check ids/flow/tcp.py tests/test_flow_tcp.py && uv run ruff format --check ids/flow/tcp.py tests/test_flow_tcp.py`
Expected: `All checks passed!` and `N files already formatted` (no file would be reformatted).

- [ ] **Step 6: Commit**

```bash
git add ids/flow/tcp.py tests/test_flow_tcp.py
git commit -m "feat: add tcp connection state machine"
```

---
### Task 3: Flow statistics and flow records

**Files:**
- Create: `ids/flow/records.py`
- Test: `tests/test_flow_records.py`

**Interfaces:**
- Consumes: `FlowKey`, `make_key`, `flow_id` (Task 1); `TcpConnection`, `is_syn_ack` (Task 2); `ids.model` `Direction`, `Endpoint`, `EndReason`, `FlowRecord`, `FlowRef`, `PacketEvent`, `TcpInfo`; `ids.model.event.UNKNOWN`.
- Produces:
  - `PAYLOAD_METHODS = frozenset({"payload", "port+payload"})`.
  - `packet_time(event: PacketEvent) -> float | None` — `normalized.timestamp` if set, else `event.timestamp`; `None` when missing, bool or not finite.
  - `packet_bytes(event: PacketEvent) -> int` — `network.total_length`, else `payload.length`, else 0.
  - `payload_bytes(event: PacketEvent) -> int` — `transport.payload_length`, else `payload.length`, else 0.
  - `FlowState(key: FlowKey, src: Endpoint, dst: Endpoint, event: PacketEvent, timestamp: float)` — built from the flow's first packet (before `add` is called for it). Attributes: `key`, `record: FlowRecord` (filled in place), `tcp: TcpConnection | None`, `touched: float`.
  - `FlowState.add(event: PacketEvent, forward: bool, timestamp: float, now: float) -> FlowRef` — accounts one packet; `forward` = sent by endpoint A; `timestamp` = `packet_time(event)`; `now` = tracker clock. Returns `FlowRef(flow_id, direction, state after the packet or None for UDP, 1-based flow_packet_index)`.
  - `FlowState.finish(reason: EndReason) -> FlowRecord` — sets `end_reason` and `duration` and returns the same `record` object (no copy).

Endpoint A: for TCP, the destination when the first packet is a SYN-ACK, otherwise the sender of the first packet (the SYN sender in a normal handshake; the first sender of a midstream flow). For UDP, the sender of the first packet.

- [ ] **Step 1: Write the failing test**

Create `tests/test_flow_records.py`:

```python
from __future__ import annotations

from flow_events import CLIENT, SERVER, T0, app, tcp_event, udp_event

from ids.flow.key import flow_id, make_key
from ids.flow.records import FlowState, packet_bytes, packet_time, payload_bytes
from ids.model import (
    Direction,
    DirectionStats,
    Endpoint,
    EndReason,
    Ipv4Info,
    Normalized,
    PacketEvent,
    Payload,
    TcpState,
    UdpInfo,
)


def track(events):
    """Feed every event into one FlowState, the way the flow table does."""
    first = events[0]
    key, src, dst = make_key(first)
    flow = FlowState(key, src, dst, first, first.timestamp)
    refs = []
    for event in events:
        event_key, src, _ = make_key(event)
        assert event_key == key
        forward = src == flow.record.endpoint_a
        refs.append(flow.add(event, forward, event.timestamp, event.timestamp))
    return flow, refs


def tcp_session():
    """Handshake, 100 B up, 300 B down, graceful close: 6 packets A→B, 4 packets B→A."""
    up, down = b"u" * 100, b"d" * 300
    return [
        tcp_event(1, T0, CLIENT, SERVER, "S", seq=1000, ack=0),
        tcp_event(2, T0 + 0.25, SERVER, CLIENT, "SA", seq=5000, ack=1001),
        tcp_event(3, T0 + 0.5, CLIENT, SERVER, "A", seq=1001, ack=5001),
        tcp_event(4, T0 + 0.75, CLIENT, SERVER, "PA", seq=1001, ack=5001, payload=up),
        tcp_event(5, T0 + 1.0, SERVER, CLIENT, "A", seq=5001, ack=1101),
        tcp_event(6, T0 + 1.25, SERVER, CLIENT, "PA", seq=5001, ack=1101, payload=down),
        tcp_event(7, T0 + 1.5, CLIENT, SERVER, "A", seq=1101, ack=5301),
        tcp_event(8, T0 + 1.75, CLIENT, SERVER, "FA", seq=1101, ack=5301),
        tcp_event(9, T0 + 2.0, SERVER, CLIENT, "FA", seq=5301, ack=1102),
        tcp_event(10, T0 + 2.25, CLIENT, SERVER, "A", seq=1102, ack=5302),
    ]


def test_tcp_session_record_has_exact_counters():
    flow, refs = track(tcp_session())
    record = flow.finish(EndReason.CLOSED)
    assert record.protocol == "TCP"
    assert record.endpoint_a == Endpoint("10.0.0.1", 40000)
    assert record.endpoint_b == Endpoint("10.0.0.2", 80)
    assert (record.start_time, record.last_seen, record.duration) == (T0, T0 + 2.25, 2.25)
    assert (record.packet_count, record.byte_count, record.payload_byte_count) == (10, 800, 400)
    assert record.forward == DirectionStats(packet_count=6, byte_count=340, payload_byte_count=100)
    assert record.backward == DirectionStats(packet_count=4, byte_count=460, payload_byte_count=300)
    tcp = record.tcp
    assert (tcp.syn_count, tcp.ack_count, tcp.fin_count, tcp.rst_count) == (2, 9, 2, 0)
    assert tcp.state is TcpState.CLOSED
    assert tcp.handshake_complete is True and tcp.midstream is False
    assert (record.first_packet_id, record.last_packet_id) == (1, 10)
    assert record.end_reason is EndReason.CLOSED
    assert record.flow_id == flow_id(flow.key, T0)
    assert [ref.flow_packet_index for ref in refs] == list(range(1, 11))
    assert {ref.flow_id for ref in refs} == {record.flow_id}


def test_packet_refs_carry_direction_and_state_after_the_packet():
    _, refs = track(tcp_session()[:4])
    assert [ref.direction for ref in refs] == [
        Direction.FORWARD,
        Direction.BACKWARD,
        Direction.FORWARD,
        Direction.FORWARD,
    ]
    assert [ref.state for ref in refs] == [
        TcpState.HANDSHAKE,
        TcpState.HANDSHAKE,
        TcpState.ESTABLISHED,
        TcpState.ESTABLISHED,
    ]


def test_udp_dns_exchange_is_one_flow_with_one_packet_each_way():
    dns = app("DNS", "port+payload", 1.0)
    client, resolver = ("10.0.0.1", 53000), ("10.0.0.53", 53)
    flow, refs = track(
        [
            udp_event(1, T0, client, resolver, payload=b"q" * 30, application=dns),
            udp_event(2, T0 + 0.02, resolver, client, payload=b"r" * 46, application=dns),
        ]
    )
    record = flow.finish(EndReason.END_OF_INPUT)
    assert record.protocol == "UDP"
    assert record.tcp is None
    assert record.application_protocol == "DNS"
    assert (record.packet_count, record.byte_count) == (2, 58 + 74)
    assert (record.forward.packet_count, record.backward.packet_count) == (1, 1)
    assert record.duration == 0.02
    assert [(ref.direction, ref.state, ref.flow_packet_index) for ref in refs] == [
        (Direction.FORWARD, None, 1),
        (Direction.BACKWARD, None, 2),
    ]


def test_syn_ack_seen_first_makes_its_destination_endpoint_a():
    flow, refs = track(
        [
            tcp_event(1, T0, SERVER, CLIENT, "SA", seq=5000, ack=1001),
            tcp_event(2, T0 + 0.1, CLIENT, SERVER, "A", seq=1001, ack=5001),
        ]
    )
    assert flow.record.endpoint_a == Endpoint("10.0.0.1", 40000)
    assert [ref.direction for ref in refs] == [Direction.BACKWARD, Direction.FORWARD]
    assert refs[-1].state is TcpState.ESTABLISHED


def test_midstream_flow_makes_the_first_sender_endpoint_a():
    flow, refs = track([tcp_event(1, T0, SERVER, CLIENT, "PA", seq=7, ack=9, payload=b"x")])
    assert flow.record.endpoint_a == Endpoint("10.0.0.2", 80)
    assert flow.record.tcp.midstream is True
    assert refs[0].state is TcpState.NEW


def test_out_of_order_timestamps_never_give_a_negative_duration():
    flow, _ = track(
        [
            udp_event(1, T0 + 2, CLIENT, SERVER),
            udp_event(2, T0 + 1, SERVER, CLIENT),
        ]
    )
    record = flow.finish(EndReason.END_OF_INPUT)
    assert (record.start_time, record.last_seen, record.duration) == (T0 + 1, T0 + 2, 1.0)
    assert record.flow_id == flow_id(flow.key, T0 + 2)  # fixed by the first packet


def test_payload_evidence_outranks_port_only_detection():
    flow, _ = track(
        [
            udp_event(1, T0, CLIENT, SERVER, application=app("HTTP", "payload", 0.6)),
            udp_event(2, T0 + 1, CLIENT, SERVER, application=app("SMTP", "port", 0.9)),
        ]
    )
    assert flow.record.application_protocol == "HTTP"


def test_higher_confidence_with_payload_evidence_replaces_the_flow_protocol():
    flow, _ = track(
        [
            tcp_event(1, T0, CLIENT, SERVER, application=app("SMTP", "port", 0.3)),
            tcp_event(2, T0 + 1, CLIENT, SERVER, application=app("HTTP", "payload", 0.7)),
            tcp_event(3, T0 + 2, CLIENT, SERVER, application=app("DNS", "port+payload", 0.9)),
            tcp_event(4, T0 + 3, CLIENT, SERVER, application=app("HTTP", "payload", 0.9)),
        ]
    )
    assert flow.record.application_protocol == "DNS"  # ties keep the earliest


def test_flow_without_any_detection_is_unknown():
    flow, _ = track(
        [
            tcp_event(1, T0, CLIENT, SERVER, "S"),
            tcp_event(2, T0 + 1, SERVER, CLIENT, application=app("UNKNOWN", "none", 0.0)),
        ]
    )
    assert flow.record.application_protocol == "UNKNOWN"


def test_normalized_application_protocol_is_preferred():
    event = udp_event(1, T0, CLIENT, SERVER, application=app("http", "payload", 0.9))
    event.normalized = Normalized(application_protocol="HTTP")
    flow, _ = track([event])
    assert flow.record.application_protocol == "HTTP"


def test_byte_counts_fall_back_to_the_captured_payload_length():
    event = PacketEvent(
        network=Ipv4Info(total_length=None),
        transport=UdpInfo(payload_length=None),
        payload=Payload(length=12),
    )
    assert (packet_bytes(event), payload_bytes(event)) == (12, 12)
    assert (packet_bytes(PacketEvent()), payload_bytes(PacketEvent())) == (0, 0)


def test_packet_time_prefers_the_normalized_timestamp():
    event = udp_event(1, 1759000000123.0, CLIENT, SERVER)  # milliseconds in a loaded event
    event.normalized = Normalized(timestamp=1759000000.123)
    assert packet_time(event) == 1759000000.123
    event.normalized = Normalized()
    assert packet_time(event) == 1759000000123.0


def test_packet_time_rejects_missing_or_non_finite_values():
    assert packet_time(PacketEvent(timestamp=None)) is None
    assert packet_time(PacketEvent(timestamp=float("nan"))) is None
    assert packet_time(PacketEvent(timestamp=float("inf"))) is None
```

Expected values in `test_tcp_session_record_has_exact_counters` (T13 shape): forward = SYN, ACK, 100 B data, ACK, FIN, ACK = 6 packets, `6 × 40 + 100 = 340` bytes; backward = SYN-ACK, ACK, 300 B data, FIN = 4 packets, `4 × 40 + 300 = 460` bytes; every packet except the first SYN carries ACK, so `ack_count = 9`.

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/test_flow_records.py -q`
Expected: collection error `ModuleNotFoundError: No module named 'ids.flow.records'`.

- [ ] **Step 3: Implement**

Create `ids/flow/records.py`:

```python
from __future__ import annotations

import math

from ..model import Direction, Endpoint, EndReason, FlowRecord, FlowRef, PacketEvent, TcpInfo
from ..model.event import UNKNOWN
from .key import FlowKey, flow_id
from .tcp import TcpConnection, is_syn_ack

PAYLOAD_METHODS = frozenset({"payload", "port+payload"})


def packet_time(event: PacketEvent) -> float | None:
    """Normalized timestamp when the preprocessor set one, else the raw one; None if unusable."""
    normalized = event.normalized
    value = normalized.timestamp if normalized is not None else None
    if value is None:
        value = event.timestamp
    if value is None or isinstance(value, bool) or not math.isfinite(value):
        return None
    return float(value)


def packet_bytes(event: PacketEvent) -> int:
    """IPv4 total length, else captured payload length, else 0."""
    if event.network is not None and event.network.total_length is not None:
        return event.network.total_length
    if event.payload is not None and event.payload.length is not None:
        return event.payload.length
    return 0


def payload_bytes(event: PacketEvent) -> int:
    """Transport payload length, else captured payload length, else 0."""
    if event.transport is not None and event.transport.payload_length is not None:
        return event.transport.payload_length
    if event.payload is not None and event.payload.length is not None:
        return event.payload.length
    return 0


class FlowState:
    """Mutable per-flow state. `record` is filled in place and handed out by `finish`."""

    __slots__ = ("_app_rank", "key", "record", "tcp", "touched")

    def __init__(
        self, key: FlowKey, src: Endpoint, dst: Endpoint, event: PacketEvent, timestamp: float
    ) -> None:
        self.key = key
        self.tcp: TcpConnection | None = None
        endpoint_a, endpoint_b = src, dst
        if isinstance(event.transport, TcpInfo):
            flags = event.transport.flags
            if is_syn_ack(flags):
                endpoint_a, endpoint_b = dst, src
            self.tcp = TcpConnection(flags)
        self.record = FlowRecord(
            flow_id=flow_id(key, timestamp),
            protocol=key.proto,
            application_protocol=UNKNOWN,
            endpoint_a=endpoint_a,
            endpoint_b=endpoint_b,
            start_time=timestamp,
            last_seen=timestamp,
            tcp=self.tcp.stats if self.tcp is not None else None,
            first_packet_id=event.packet_id,
        )
        self.touched = timestamp  # tracker clock at the latest packet; drives expiry
        self._app_rank: tuple[int, float] | None = None

    def add(self, event: PacketEvent, forward: bool, timestamp: float, now: float) -> FlowRef:
        """Account one packet sent in `forward` (A→B) or backward direction; `now` = clock."""
        record = self.record
        self.touched = now
        if timestamp < record.start_time:
            record.start_time = timestamp
        if timestamp > record.last_seen:
            record.last_seen = timestamp
        size = packet_bytes(event)
        payload = payload_bytes(event)
        record.packet_count += 1
        record.byte_count += size
        record.payload_byte_count += payload
        direction = record.forward if forward else record.backward
        direction.packet_count += 1
        direction.byte_count += size
        direction.payload_byte_count += payload
        record.last_packet_id = event.packet_id
        self._observe_application(event)
        state = None
        if self.tcp is not None:
            tcp = event.transport  # a TCP key guarantees TcpInfo
            state = self.tcp.update(forward, tcp.flags, tcp.seq, tcp.ack, payload)
        return FlowRef(
            flow_id=record.flow_id,
            direction=Direction.FORWARD if forward else Direction.BACKWARD,
            state=state,
            flow_packet_index=record.packet_count,
        )

    def finish(self, reason: EndReason) -> FlowRecord:
        record = self.record
        record.end_reason = reason
        record.duration = round(record.last_seen - record.start_time, 6)
        return record

    def _observe_application(self, event: PacketEvent) -> None:
        application = event.application
        if application is None:
            return
        normalized = event.normalized
        protocol = application.protocol
        if normalized is not None and normalized.application_protocol:
            protocol = normalized.application_protocol
        if not protocol or protocol == UNKNOWN:
            return
        detection = application.detection
        if detection is None:
            rank = (0, 0.0)
        else:
            rank = (int(detection.method in PAYLOAD_METHODS), detection.confidence or 0.0)
        if self._app_rank is None or rank > self._app_rank:
            self._app_rank = rank
            self.record.application_protocol = protocol
```

The record's `forward`, `backward` and `tcp` objects are mutated in place and handed over by `finish`; a flow is exported exactly once, so nothing is copied.

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/test_flow_records.py -q`
Expected: `13 passed`.

- [ ] **Step 5: Full suite and lint**

Run: `uv run pytest -q`
Expected: all tests pass (0 failed, 0 errors).

Run: `uv run ruff check ids/flow/records.py tests/test_flow_records.py && uv run ruff format --check ids/flow/records.py tests/test_flow_records.py`
Expected: `All checks passed!` and `N files already formatted` (no file would be reformatted).

- [ ] **Step 6: Commit**

```bash
git add ids/flow/records.py tests/test_flow_records.py
git commit -m "feat: add flow statistics and flow records"
```

---
### Task 4: Flow table with expiry lanes and eviction

**Files:**
- Create: `ids/flow/table.py`
- Test: `tests/test_flow_table.py`

**Interfaces:**
- Consumes: `FlowKey`, `make_key` (Task 1); `TERMINAL_STATES`, `is_new_syn` (Task 2); `FlowState` (Task 3); `ids.model` `Endpoint`, `EndReason`, `FlowRef`, `PacketEvent`, `TcpState`; `ids.pipeline.Emit` (type only, contract §8).
- Produces:
  - `FlowTable(*, tcp_idle_timeout: float, udp_idle_timeout: float, tcp_closed_timeout: float, max_flows: int)` (Task 5 adds `max_message_bytes: int`).
  - Attributes `tcp_open`, `tcp_closed`, `udp: OrderedDict[FlowKey, FlowState]`; `clock: float | None`; property `active_count -> int`.
  - `advance(now: float, emit: Emit) -> float` — clock = max(clock, now), export expired flows, return the clock.
  - `apply(event: PacketEvent, key: FlowKey, src: Endpoint, dst: Endpoint, timestamp: float, emit: Emit) -> FlowRef` — `advance(timestamp)` first (expiry before the packet, spec §9.5), then account the packet.
  - `flush(emit: Emit) -> None` — export every flow, oldest activity first.

Behaviour:

- Lookup: TCP keys in `tcp_open`, then `tcp_closed`; UDP keys in `udp`. Activity moves the flow to the end of its lane.
- A TCP packet that leaves its flow in `CLOSED`/`RESET` moves the flow from `tcp_open` to the end of `tcp_closed`.
- A SYN without ACK on a key in `tcp_closed` exports the old flow with `closed`/`reset` and creates a new flow (port reuse during the linger).
- New flow while `active_count >= max_flows`: the least recently touched lane front is exported with `evicted` first.
- Expiry: lane front expires when `clock - touched > lane timeout` (`tcp_idle_timeout`, `tcp_closed_timeout`, `udp_idle_timeout`); reasons `idle_timeout`, or `closed`/`reset` for the closed lane; several expired fronts leave in deadline order.

- [ ] **Step 1: Write the failing test**

Create `tests/test_flow_table.py`:

```python
from __future__ import annotations

from flow_events import CLIENT, SERVER, T0, tcp_event, udp_event

from ids.flow.key import make_key
from ids.flow.table import FlowTable
from ids.model import EndReason, TcpState

DNS_CLIENT = ("10.0.0.1", 53000)
RESOLVER = ("10.0.0.53", 53)
OTHER = ("10.0.0.7", 9999)


def make_table(**overrides) -> FlowTable:
    config = {
        "tcp_idle_timeout": 300.0,
        "udp_idle_timeout": 60.0,
        "tcp_closed_timeout": 5.0,
        "max_flows": 100,
    }
    config.update(overrides)
    return FlowTable(**config)


def feed(table: FlowTable, event, out: list):
    key, src, dst = make_key(event)
    return table.apply(event, key, src, dst, event.timestamp, out.append)


def closed_connection(first_id: int, start: float, client=CLIENT):
    """Handshake and graceful close, 0.1 s apart; the flow is CLOSED after the last one."""
    t = start
    return [
        tcp_event(first_id, t, client, SERVER, "S", seq=1000, ack=0),
        tcp_event(first_id + 1, t + 0.1, SERVER, client, "SA", seq=5000, ack=1001),
        tcp_event(first_id + 2, t + 0.2, client, SERVER, "A", seq=1001, ack=5001),
        tcp_event(first_id + 3, t + 0.3, client, SERVER, "FA", seq=1001, ack=5001),
        tcp_event(first_id + 4, t + 0.4, SERVER, client, "FA", seq=5001, ack=1002),
        tcp_event(first_id + 5, t + 0.5, client, SERVER, "A", seq=1002, ack=5002),
    ]


def test_udp_flow_expires_before_a_later_packet_of_another_flow_is_applied():
    table = make_table()
    emitted = []

    def emit(record):
        emitted.append((record, table.active_count))

    first = udp_event(1, T0, DNS_CLIENT, RESOLVER)
    second = udp_event(2, T0 + 1, RESOLVER, DNS_CLIENT)
    for event in (first, second):
        key, src, dst = make_key(event)
        table.apply(event, key, src, dst, event.timestamp, emit)
    late = udp_event(3, T0 + 62, OTHER, RESOLVER)
    key, src, dst = make_key(late)
    ref = table.apply(late, key, src, dst, late.timestamp, emit)
    assert len(emitted) == 1
    record, active_when_emitted = emitted[0]
    assert active_when_emitted == 0  # the late packet's flow did not exist yet
    assert record.end_reason is EndReason.IDLE_TIMEOUT
    assert record.packet_count == 2
    assert ref.flow_packet_index == 1
    assert table.active_count == 1
    assert make_key(first)[0] not in table.udp


def test_gap_equal_to_the_udp_timeout_stays_in_the_same_flow():
    table, out = make_table(), []
    first = feed(table, udp_event(1, T0, DNS_CLIENT, RESOLVER), out)
    second = feed(table, udp_event(2, T0 + 60, DNS_CLIENT, RESOLVER), out)
    assert out == []
    assert second.flow_id == first.flow_id
    assert second.flow_packet_index == 2


def test_same_key_after_expiry_starts_a_new_flow():
    table, out = make_table(), []
    first = feed(table, udp_event(1, T0, DNS_CLIENT, RESOLVER), out)
    second = feed(table, udp_event(2, T0 + 61, DNS_CLIENT, RESOLVER), out)
    assert [record.flow_id for record in out] == [first.flow_id]
    assert second.flow_id != first.flow_id
    assert second.flow_packet_index == 1


def test_expired_flows_leave_in_order_of_their_deadline_across_lanes():
    table, out = make_table(), []
    udp = feed(table, udp_event(1, T0, DNS_CLIENT, RESOLVER), out)  # deadline T0 + 60
    tcp_open = feed(table, tcp_event(2, T0 + 1, OTHER, SERVER, "S"), out)  # T0 + 301
    for event in closed_connection(3, T0 + 9.5):  # closed at T0 + 10, deadline T0 + 15
        closed = feed(table, event, out)
    assert closed.state is TcpState.CLOSED
    table.advance(T0 + 70, out.append)
    assert [(r.flow_id, r.end_reason) for r in out] == [
        (closed.flow_id, EndReason.CLOSED),
        (udp.flow_id, EndReason.IDLE_TIMEOUT),
    ]
    table.advance(T0 + 400, out.append)
    assert (out[-1].flow_id, out[-1].end_reason) == (tcp_open.flow_id, EndReason.IDLE_TIMEOUT)
    assert table.active_count == 0


def test_eviction_exports_the_least_recently_active_flow_across_lanes():
    table, out = make_table(max_flows=2), []
    feed(table, tcp_event(1, T0, CLIENT, SERVER, "S"), out)
    udp = feed(table, udp_event(2, T0 + 1, DNS_CLIENT, RESOLVER), out)
    feed(table, tcp_event(3, T0 + 2, CLIENT, SERVER, "S"), out)  # TCP flow active again
    feed(table, udp_event(4, T0 + 3, OTHER, RESOLVER), out)
    assert [(r.flow_id, r.end_reason) for r in out] == [(udp.flow_id, EndReason.EVICTED)]
    assert table.active_count == 2


def test_closed_flow_lingers_for_trailing_packets_then_a_new_syn_starts_a_new_flow():
    table, out = make_table(), []
    for event in closed_connection(1, T0):
        old = feed(table, event, out)
    trailing = feed(table, tcp_event(7, T0 + 1, SERVER, CLIENT, "A", seq=5002, ack=1002), out)
    assert (trailing.flow_id, trailing.flow_packet_index) == (old.flow_id, 7)
    assert trailing.state is TcpState.CLOSED
    assert out == []
    new = feed(table, tcp_event(8, T0 + 2, CLIENT, SERVER, "S", seq=9000, ack=0), out)
    assert [(r.flow_id, r.end_reason, r.packet_count) for r in out] == [
        (old.flow_id, EndReason.CLOSED, 7)
    ]
    assert new.flow_id != old.flow_id
    assert (new.flow_packet_index, new.state) == (1, TcpState.HANDSHAKE)
    assert table.active_count == 1


def test_closed_flow_is_exported_after_the_linger_since_its_last_packet():
    table, out = make_table(), []
    for event in closed_connection(1, T0):
        feed(table, event, out)
    feed(table, tcp_event(7, T0 + 4, SERVER, CLIENT, "A", seq=5002, ack=1002), out)
    feed(table, udp_event(8, T0 + 6, DNS_CLIENT, RESOLVER), out)
    assert out == []  # 2 s since the trailing ACK
    feed(table, udp_event(9, T0 + 9.5, DNS_CLIENT, RESOLVER), out)
    assert [(r.protocol, r.end_reason) for r in out] == [("TCP", EndReason.CLOSED)]


def test_reset_flow_is_exported_with_reason_reset():
    table, out = make_table(), []
    feed(table, tcp_event(1, T0, CLIENT, SERVER, "S", seq=1000, ack=0), out)
    feed(table, tcp_event(2, T0 + 0.1, SERVER, CLIENT, "RA", seq=0, ack=1001), out)
    table.advance(T0 + 10, out.append)
    assert [(r.end_reason, r.tcp.state) for r in out] == [(EndReason.RESET, TcpState.RESET)]


def test_syn_on_an_open_flow_does_not_start_a_new_flow():
    table, out = make_table(), []
    for event in closed_connection(1, T0)[:3]:
        first = feed(table, event, out)
    again = feed(table, tcp_event(4, T0 + 1, CLIENT, SERVER, "S", seq=7000, ack=0), out)
    assert out == []
    assert again.flow_id == first.flow_id
    assert again.state is TcpState.ESTABLISHED


def test_clock_never_moves_backwards_with_out_of_order_timestamps():
    table, out = make_table(), []
    feed(table, udp_event(1, T0 + 100, DNS_CLIENT, RESOLVER), out)
    feed(table, udp_event(2, T0 + 90, OTHER, RESOLVER), out)
    assert table.clock == T0 + 100
    feed(table, udp_event(3, T0 + 155, CLIENT, RESOLVER), out)
    assert out == []  # the late packet counts as activity at T0 + 100, not T0 + 90
    table.advance(T0 + 120, out.append)
    assert table.clock == T0 + 155
    table.advance(T0 + 161, out.append)
    assert [r.first_packet_id for r in out] == [1, 2]
    assert out[1].last_seen == T0 + 90
    assert table.active_count == 1


def test_flush_exports_everything_oldest_activity_first():
    table, out = make_table(), []
    feed(table, udp_event(1, T0, DNS_CLIENT, RESOLVER), out)
    for event in closed_connection(2, T0 + 1):
        feed(table, event, out)
    feed(table, tcp_event(8, T0 + 2, OTHER, SERVER, "S"), out)
    table.flush(out.append)
    assert [(r.protocol, r.end_reason) for r in out] == [
        ("UDP", EndReason.END_OF_INPUT),
        ("TCP", EndReason.CLOSED),
        ("TCP", EndReason.END_OF_INPUT),
    ]
    assert table.active_count == 0


def test_three_interleaved_flows_are_kept_apart():
    table, out = make_table(), []
    second_client = ("10.0.0.3", 40002)
    events = [
        tcp_event(1, T0, CLIENT, SERVER, "S", seq=100, ack=0),
        tcp_event(2, T0 + 0.1, second_client, SERVER, "S", seq=200, ack=0),
        udp_event(3, T0 + 0.2, DNS_CLIENT, RESOLVER, payload=b"q" * 20),
        tcp_event(4, T0 + 0.3, SERVER, CLIENT, "SA", seq=900, ack=101),
        tcp_event(5, T0 + 0.4, SERVER, second_client, "SA", seq=800, ack=201),
        udp_event(6, T0 + 0.5, RESOLVER, DNS_CLIENT, payload=b"r" * 40),
        tcp_event(7, T0 + 0.6, CLIENT, SERVER, "A", seq=101, ack=901),
        tcp_event(8, T0 + 0.7, second_client, SERVER, "A", seq=201, ack=801),
        tcp_event(9, T0 + 0.8, CLIENT, SERVER, "PA", seq=101, ack=901, payload=b"x" * 10),
    ]
    refs = [feed(table, event, out) for event in events]
    table.flush(out.append)
    by_id = {record.flow_id: record for record in out}
    assert len(by_id) == 3
    assert [refs[i].flow_id for i in (0, 3, 6, 8)] == [refs[0].flow_id] * 4
    assert [refs[i].flow_id for i in (1, 4, 7)] == [refs[1].flow_id] * 3
    assert refs[2].flow_id == refs[5].flow_id
    assert by_id[refs[0].flow_id].packet_count == 4
    assert by_id[refs[0].flow_id].payload_byte_count == 10
    assert by_id[refs[1].flow_id].packet_count == 3
    assert by_id[refs[2].flow_id].packet_count == 2
    assert by_id[refs[2].flow_id].byte_count == 48 + 68
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/test_flow_table.py -q`
Expected: collection error `ModuleNotFoundError: No module named 'ids.flow.table'`.

- [ ] **Step 3: Implement**

Create `ids/flow/table.py`:

```python
from __future__ import annotations

from collections import OrderedDict
from typing import TYPE_CHECKING

from ..model import Endpoint, EndReason, FlowRef, PacketEvent, TcpState
from .key import FlowKey
from .records import FlowState
from .tcp import TERMINAL_STATES, is_new_syn

if TYPE_CHECKING:
    from ..pipeline import Emit

Lane = OrderedDict[FlowKey, FlowState]

_CLOSED_REASONS = {TcpState.CLOSED: EndReason.CLOSED, TcpState.RESET: EndReason.RESET}


def _closed_reason(flow: FlowState) -> EndReason:
    """End reason of a flow in the closed lane: its terminal TCP state."""
    return _CLOSED_REASONS[flow.tcp.state]


class FlowTable:
    """Active flows in three lanes ordered by last activity: TCP open, TCP closed, UDP.

    The clock is the largest packet or tick time seen and never moves backwards. A flow
    expires when `clock - touched > lane timeout`, where `touched` is the clock value at its
    latest packet.
    """

    def __init__(
        self,
        *,
        tcp_idle_timeout: float,
        udp_idle_timeout: float,
        tcp_closed_timeout: float,
        max_flows: int,
    ) -> None:
        self.tcp_open: Lane = OrderedDict()
        self.tcp_closed: Lane = OrderedDict()
        self.udp: Lane = OrderedDict()
        self.clock: float | None = None
        self.max_flows = max_flows
        self._lanes = (self.tcp_open, self.tcp_closed, self.udp)
        self._timeouts = (
            (self.tcp_open, tcp_idle_timeout),
            (self.tcp_closed, tcp_closed_timeout),
            (self.udp, udp_idle_timeout),
        )

    @property
    def active_count(self) -> int:
        return len(self.tcp_open) + len(self.tcp_closed) + len(self.udp)

    def advance(self, now: float, emit: Emit) -> float:
        """Move the clock forward to `now` (never back), export expired flows, return clock."""
        if self.clock is None or now > self.clock:
            self.clock = now
        self._expire(self.clock, emit)
        return self.clock

    def apply(
        self,
        event: PacketEvent,
        key: FlowKey,
        src: Endpoint,
        dst: Endpoint,
        timestamp: float,
        emit: Emit,
    ) -> FlowRef:
        """Expire first, then account `event` to its flow (created if needed)."""
        now = self.advance(timestamp, emit)
        if key.proto == "TCP":
            flow, lane = self._tcp_flow(event, key, src, dst, timestamp, emit)
        else:
            lane = self.udp
            flow = lane.get(key)
            if flow is None:
                flow = self._create(lane, key, src, dst, event, timestamp, emit)
            else:
                lane.move_to_end(key)
        ref = flow.add(event, src == flow.record.endpoint_a, timestamp, now)
        if lane is self.tcp_open and ref.state in TERMINAL_STATES:
            del self.tcp_open[key]
            self.tcp_closed[key] = flow
        return ref

    def flush(self, emit: Emit) -> None:
        """Export every flow, oldest activity first.

        Closed-lane flows keep their closed/reset reason; the others end with end_of_input.
        """
        while (lane := self._oldest_lane()) is not None:
            _, flow = lane.popitem(last=False)
            self._export(flow, self._reason(lane, flow, EndReason.END_OF_INPUT), emit)

    def _tcp_flow(
        self,
        event: PacketEvent,
        key: FlowKey,
        src: Endpoint,
        dst: Endpoint,
        timestamp: float,
        emit: Emit,
    ) -> tuple[FlowState, Lane]:
        flow = self.tcp_open.get(key)
        if flow is not None:
            self.tcp_open.move_to_end(key)
            return flow, self.tcp_open
        flow = self.tcp_closed.get(key)
        if flow is not None:
            if not is_new_syn(event.transport.flags):
                self.tcp_closed.move_to_end(key)
                return flow, self.tcp_closed
            # Port reuse during the linger: the old connection ends, a new flow starts.
            del self.tcp_closed[key]
            self._export(flow, _closed_reason(flow), emit)
        return self._create(self.tcp_open, key, src, dst, event, timestamp, emit), self.tcp_open

    def _create(
        self,
        lane: Lane,
        key: FlowKey,
        src: Endpoint,
        dst: Endpoint,
        event: PacketEvent,
        timestamp: float,
        emit: Emit,
    ) -> FlowState:
        if self.active_count >= self.max_flows:
            oldest = self._oldest_lane()
            _, evicted = oldest.popitem(last=False)
            self._export(evicted, EndReason.EVICTED, emit)
        flow = FlowState(key, src, dst, event, timestamp)
        lane[key] = flow
        return flow

    def _expire(self, clock: float, emit: Emit) -> None:
        """Export expired lane fronts in order of their expiry deadline."""
        while True:
            best: Lane | None = None
            best_deadline = 0.0
            for lane, timeout in self._timeouts:
                if not lane:
                    continue
                touched = next(iter(lane.values())).touched
                deadline = touched + timeout
                if clock - touched > timeout and (best is None or deadline < best_deadline):
                    best, best_deadline = lane, deadline
            if best is None:
                return
            _, flow = best.popitem(last=False)
            self._export(flow, self._reason(best, flow, EndReason.IDLE_TIMEOUT), emit)

    def _oldest_lane(self) -> Lane | None:
        best: Lane | None = None
        best_touched = 0.0
        for lane in self._lanes:
            if lane:
                touched = next(iter(lane.values())).touched
                if best is None or touched < best_touched:
                    best, best_touched = lane, touched
        return best

    def _reason(self, lane: Lane, flow: FlowState, default: EndReason) -> EndReason:
        return _closed_reason(flow) if lane is self.tcp_closed else default

    def _export(self, flow: FlowState, reason: EndReason, emit: Emit) -> None:
        emit(flow.finish(reason))
```

`Lane = OrderedDict[FlowKey, FlowState]` is evaluated at runtime; `collections.OrderedDict` is subscriptable since Python 3.9. `Emit` is imported only for type checking, so `ids.flow` does not import `ids.pipeline` at runtime.

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/test_flow_table.py -q`
Expected: `12 passed`.

- [ ] **Step 5: Full suite and lint**

Run: `uv run pytest -q`
Expected: all tests pass (0 failed, 0 errors).

Run: `uv run ruff check ids/flow/table.py tests/test_flow_table.py && uv run ruff format --check ids/flow/table.py tests/test_flow_table.py`
Expected: `All checks passed!` and `N files already formatted` (no file would be reformatted).

- [ ] **Step 6: Commit**

```bash
git add ids/flow/table.py tests/test_flow_table.py
git commit -m "feat: add flow table with expiry lanes and eviction"
```

---
### Task 5: SMTP DATA reassembly

**Files:**
- Create: `ids/flow/smtp.py`
- Modify: `ids/flow/records.py` (add the `smtp` slot)
- Modify: `ids/flow/table.py` (`max_message_bytes`, feed/finish the reassembler)
- Modify: `tests/test_flow_table.py` (`make_table` passes `max_message_bytes`)
- Test: `tests/test_flow_smtp.py`

**Interfaces:**
- Consumes: `SEQ_MOD` (Task 2); `FlowState` (Task 3); `FlowTable` (Task 4); `ids.model` `MessageEvent`, `PacketEvent`, `SmtpSession`, `TcpInfo`.
- Produces:
  - `TERMINATOR = b"\r\n.\r\n"`.
  - `SmtpReassembler(flow_id: str, max_bytes: int)`.
  - `SmtpReassembler.feed(event: PacketEvent, forward: bool, timestamp: float) -> MessageEvent | None` — returns a completed message (`complete=True`) when this packet carries the end of the terminator.
  - `SmtpReassembler.finish() -> MessageEvent | None` — the body being collected as `complete=False`, or `None` if no byte was collected.
  - `FlowState.smtp: SmtpReassembler | None`.
  - `FlowTable(*, tcp_idle_timeout, udp_idle_timeout, tcp_closed_timeout, max_flows, max_message_bytes: int)`; `apply` may now `emit` a `MessageEvent`; every export emits the flow's unfinished message (if any) right before its `FlowRecord`.
  - `MessageEvent` fields set: `message_id = f"{flow_id}-{n}"` (n 1-based per flow), `flow_id`, `protocol = "SMTP"`, `packet_ids`, `start_time`, `end_time` (timestamps of the first/last contributing packet), `data` (bytes incl. terminator, at most `max_bytes`), `complete`, `truncated`, `gap`. Other fields keep their defaults; the runner sends the message through decoder and preprocessor (contract §8).

Phases of one reassembler:

| Phase | Packet | Effect |
|---|---|---|
| idle | payload has a `DATA` line (raw bytes, case-insensitive) or `SmtpSession.commands` contains verb `DATA` | client := packet's direction; next client seq := seq + length; → wait |
| wait | client packet | next client seq advances |
| wait | other side, `354` reply line or `SmtpSession.replies` code 354 | → collect |
| collect | client packet | trim bytes before next seq (retransmission/overlap), jump ahead or bytes missing from the capture → `gap`; append up to `max_bytes` (`truncated`); search the terminator across segment borders with a 4-byte tail; on terminator emit and go idle, or wait if a `DATA` line follows the terminator in the same segment |

The start of the body counts as a line start, so a body that begins with `.\r\n` is an empty message.

The table creates the reassembler on the first packet after which the flow's `application_protocol` is `SMTP` (TCP flows only) and feeds it every later packet of the flow.

- [ ] **Step 1: Write the failing test**

Create `tests/test_flow_smtp.py`:

```python
from __future__ import annotations

import pytest
from flow_events import T0, app, smtp_app, tcp_event

from ids.flow.key import make_key
from ids.flow.smtp import SmtpReassembler
from ids.flow.table import FlowTable
from ids.flow.tcp import SEQ_MOD
from ids.model import (
    EndReason,
    FlowRecord,
    MessageEvent,
    SmtpCommand,
    SmtpReply,
    SmtpSession,
)

FLOW_ID = "0123456789abcdef"
MAIL_CLIENT = ("10.0.0.1", 40000)
MAIL_SERVER = ("10.0.0.2", 25)


class Exchange:
    """Feeds client/server segments with running sequence numbers into one reassembler."""

    def __init__(self, *, max_bytes=1_048_576, client_seq=1000, client_forward=True):
        self.reassembler = SmtpReassembler(FLOW_ID, max_bytes)
        self.client_seq = client_seq
        self.server_seq = 5000
        self.client_forward = client_forward
        self.events = []

    def _event(self, src, dst, data, seq, ack):
        packet_id = len(self.events) + 1
        event = tcp_event(packet_id, T0 + packet_id, src, dst, "PA", seq=seq, ack=ack, payload=data)
        self.events.append(event)
        return event

    def client(self, data: bytes, *, seq: int | None = None, event=None):
        start = self.client_seq if seq is None else seq
        if event is None:
            event = self._event(MAIL_CLIENT, MAIL_SERVER, data, start, self.server_seq)
        end = (start + event.transport.payload_length) % SEQ_MOD
        if (end - self.client_seq) % SEQ_MOD < 1 << 31:
            self.client_seq = end
        return self.reassembler.feed(event, self.client_forward, event.timestamp)

    def server(self, data: bytes):
        event = self._event(MAIL_SERVER, MAIL_CLIENT, data, self.server_seq, self.client_seq)
        self.server_seq += len(data)
        return self.reassembler.feed(event, not self.client_forward, event.timestamp)

    def start(self):
        assert self.client(b"DATA\r\n") is None
        assert self.server(b"354 End data with <CR><LF>.<CR><LF>\r\n") is None


def test_message_split_over_two_segments():
    exchange = Exchange()
    exchange.start()
    assert exchange.client(b"Subject: hi\r\n\r\nline one\r\n") is None
    message = exchange.client(b"line two\r\n.\r\n")
    assert isinstance(message, MessageEvent)
    assert message.data == b"Subject: hi\r\n\r\nline one\r\nline two\r\n.\r\n"
    assert (message.complete, message.truncated, message.gap) == (True, False, False)
    assert (message.message_id, message.flow_id, message.protocol) == (
        f"{FLOW_ID}-1",
        FLOW_ID,
        "SMTP",
    )
    assert message.packet_ids == [3, 4]
    assert (message.start_time, message.end_time) == (T0 + 3, T0 + 4)


@pytest.mark.parametrize("split", [1, 2, 3, 4])
def test_terminator_split_across_segments_is_found(split):
    exchange = Exchange()
    exchange.start()
    stream = b"body\r\n.\r\n"
    assert exchange.client(stream[: 4 + split]) is None
    message = exchange.client(stream[4 + split :])
    assert message.data == stream
    assert message.complete is True


def test_empty_message_is_a_lone_dot_line():
    exchange = Exchange()
    exchange.start()
    message = exchange.client(b".\r\n")
    assert message.data == b".\r\n"
    assert message.complete is True


def test_dot_that_does_not_start_a_line_is_not_the_terminator():
    exchange = Exchange()
    exchange.start()
    assert exchange.client(b"a.\r\n") is None
    assert exchange.client(b"b\r\n.\r\n").data == b"a.\r\nb\r\n.\r\n"


def test_retransmitted_and_overlapping_segments_are_trimmed():
    exchange = Exchange()
    exchange.start()
    first_seq = exchange.client_seq
    assert exchange.client(b"Hello\r\n") is None
    assert exchange.client(b"Hello\r\n", seq=first_seq) is None  # full retransmission
    message = exchange.client(b"o\r\nWorld\r\n.\r\n", seq=first_seq + 4)  # 3 bytes overlap
    assert message.data == b"Hello\r\nWorld\r\n.\r\n"
    assert message.packet_ids == [3, 5]
    assert message.gap is False


def test_missing_bytes_set_gap_and_collection_continues():
    exchange = Exchange()
    exchange.start()
    assert exchange.client(b"part one\r\n") is None
    message = exchange.client(b"part three\r\n.\r\n", seq=exchange.client_seq + 50)
    assert message.data == b"part one\r\npart three\r\n.\r\n"
    assert (message.gap, message.complete) == (True, True)


def test_segment_captured_shorter_than_its_length_sets_gap():
    exchange = Exchange()
    exchange.start()
    seq = exchange.client_seq
    short = tcp_event(3, T0 + 3, MAIL_CLIENT, MAIL_SERVER, "PA", seq=seq, ack=1, payload=b"12345")
    short.transport.payload_length = 20  # only 5 of 20 bytes kept (--max-payload-bytes)
    exchange.events.append(short)
    assert exchange.client(b"", event=short) is None
    message = exchange.client(b"tail\r\n.\r\n")
    assert message.data == b"12345tail\r\n.\r\n"
    assert message.gap is True


def test_cap_keeps_the_first_bytes_and_still_finds_the_terminator():
    exchange = Exchange(max_bytes=8)
    exchange.start()
    message = exchange.client(b"0123456789abcdef\r\n.\r\n")
    assert message.data == b"01234567"
    assert (message.truncated, message.complete) == (True, True)


def test_terminator_straddling_segments_is_found_after_the_cap():
    exchange = Exchange(max_bytes=4)
    exchange.start()
    assert exchange.client(b"AAAAAAAAAA\r\n.") is None
    message = exchange.client(b"\r\n")
    assert message.data == b"AAAA"
    assert (message.truncated, message.complete) == (True, True)


def test_flow_end_during_collection_gives_an_incomplete_message():
    exchange = Exchange()
    exchange.start()
    exchange.client(b"partial body\r\n")
    message = exchange.reassembler.finish()
    assert message.data == b"partial body\r\n"
    assert message.complete is False
    assert message.packet_ids == [3]
    assert exchange.reassembler.finish() is None


def test_nothing_to_finish_without_collected_bytes():
    idle = Exchange()
    assert idle.reassembler.finish() is None
    waiting = Exchange()
    waiting.client(b"DATA\r\n")
    assert waiting.reassembler.finish() is None
    accepted = Exchange()
    accepted.start()
    assert accepted.reassembler.finish() is None


def test_pipelined_data_in_the_same_segment_as_rcpt():
    exchange = Exchange()
    exchange.client(b"MAIL FROM:<a@example.test>\r\nRCPT TO:<b@example.test>\r\nDATA\r\n")
    exchange.server(b"250 OK\r\n250 OK\r\n354 go ahead\r\n")
    assert exchange.client(b"Hi\r\n.\r\n").data == b"Hi\r\n.\r\n"


def test_body_is_not_collected_without_a_354_after_data():
    rejected = Exchange()
    rejected.client(b"DATA\r\n")
    rejected.server(b"554 no valid recipients\r\n")
    assert rejected.client(b"body\r\n.\r\n") is None
    early = Exchange()
    early.server(b"354 go ahead\r\n")
    assert early.client(b"body\r\n.\r\n") is None


def test_several_messages_in_one_flow_are_numbered():
    exchange = Exchange()
    exchange.start()
    first = exchange.client(b"one\r\n.\r\n")
    exchange.client(b"MAIL FROM:<a@example.test>\r\n")
    exchange.server(b"250 OK\r\n")
    exchange.start()
    second = exchange.client(b"two\r\n.\r\n")
    assert [first.message_id, second.message_id] == [f"{FLOW_ID}-1", f"{FLOW_ID}-2"]
    assert second.data == b"two\r\n.\r\n"
    assert second.packet_ids == [8]


def test_next_data_pipelined_after_the_terminator():
    exchange = Exchange()
    exchange.start()
    first = exchange.client(b"one\r\n.\r\nMAIL FROM:<a@x.test>\r\nRCPT TO:<b@x.test>\r\nDATA\r\n")
    assert first.data == b"one\r\n.\r\n"
    exchange.server(b"250 OK\r\n250 OK\r\n354 go ahead\r\n")
    second = exchange.client(b"two\r\n.\r\n")
    assert second.data == b"two\r\n.\r\n"
    assert second.message_id == f"{FLOW_ID}-2"


def test_parsed_commands_and_replies_also_drive_collection():
    exchange = Exchange()
    data_cmd = tcp_event(1, T0 + 1, MAIL_CLIENT, MAIL_SERVER, "PA", seq=1000, ack=5000)
    data_cmd.transport.payload_length = 6
    data_cmd.application = smtp_app(SmtpSession(commands=[SmtpCommand(verb="DATA")]))
    reply = tcp_event(2, T0 + 2, MAIL_SERVER, MAIL_CLIENT, "PA", seq=5000, ack=1006)
    reply.transport.payload_length = 10
    reply.application = smtp_app(SmtpSession(replies=[SmtpReply(code=354)]))
    exchange.events += [data_cmd, reply]
    exchange.reassembler.feed(data_cmd, True, data_cmd.timestamp)
    exchange.reassembler.feed(reply, False, reply.timestamp)
    exchange.client_seq = 1006
    message = exchange.client(b"x\r\n.\r\n")
    assert message.data == b"x\r\n.\r\n"
    assert message.gap is False


def test_client_seen_as_endpoint_b_in_a_midstream_capture():
    exchange = Exchange(client_forward=False)
    exchange.start()
    assert exchange.client(b"Hi\r\n.\r\n").data == b"Hi\r\n.\r\n"


def test_sequence_numbers_wrapping_around_during_collection():
    exchange = Exchange(client_seq=SEQ_MOD - 6)
    exchange.start()  # DATA\r\n ends exactly at the wrap
    assert exchange.client_seq == 0
    assert exchange.client(b"Hello\r\n") is None
    assert exchange.client(b"Hello\r\n", seq=0) is None
    message = exchange.client(b"\r\n.\r\n")
    assert message.data == b"Hello\r\n\r\n.\r\n"
    assert message.gap is False


def make_table(**overrides) -> FlowTable:
    config = {
        "tcp_idle_timeout": 300.0,
        "udp_idle_timeout": 60.0,
        "tcp_closed_timeout": 5.0,
        "max_flows": 100,
        "max_message_bytes": 1_048_576,
    }
    config.update(overrides)
    return FlowTable(**config)


def smtp_flow_events(application=None, body=b"Subject: x\r\n\r\nhello\r\n.\r\n"):
    application = application or smtp_app()
    c, s = MAIL_CLIENT, MAIL_SERVER
    return [
        tcp_event(
            1, T0, c, s, "PA", seq=100, ack=900, payload=b"EHLO c\r\n", application=application
        ),
        tcp_event(2, T0 + 1, s, c, "PA", seq=900, ack=108, payload=b"250 ok\r\n"),
        tcp_event(3, T0 + 2, c, s, "PA", seq=108, ack=908, payload=b"DATA\r\n"),
        tcp_event(4, T0 + 3, s, c, "PA", seq=908, ack=114, payload=b"354 go\r\n"),
        tcp_event(5, T0 + 4, c, s, "PA", seq=114, ack=916, payload=body),
    ]


def feed_all(table, events, out):
    for event in events:
        key, src, dst = make_key(event)
        table.apply(event, key, src, dst, event.timestamp, out.append)


def test_table_emits_the_message_while_applying_the_terminating_packet():
    table, out = make_table(), []
    events = smtp_flow_events()
    feed_all(table, events[:-1], out)
    assert out == []
    feed_all(table, events[-1:], out)
    assert [type(r) for r in out] == [MessageEvent]
    table.flush(out.append)
    message, record = out
    assert isinstance(record, FlowRecord)
    assert message.flow_id == record.flow_id
    assert message.message_id == f"{record.flow_id}-1"
    assert message.data == b"Subject: x\r\n\r\nhello\r\n.\r\n"


@pytest.mark.parametrize(
    ("finish", "reason"),
    [
        ("flush", EndReason.END_OF_INPUT),
        ("evict", EndReason.EVICTED),
        ("expire", EndReason.IDLE_TIMEOUT),
    ],
)
def test_flow_export_mid_message_emits_it_incomplete_before_the_record(finish, reason):
    table, out = make_table(max_flows=1), []
    feed_all(table, smtp_flow_events(body=b"Subject: x\r\n\r\nunfinished"), out)
    if finish == "flush":
        table.flush(out.append)
    elif finish == "evict":
        other = tcp_event(6, T0 + 5, ("10.0.0.9", 1234), MAIL_SERVER, "S", seq=1, ack=0)
        feed_all(table, [other], out)
    else:
        table.advance(T0 + 400, out.append)
    message, record = out[:2]
    assert isinstance(message, MessageEvent)
    assert (message.complete, message.data) == (False, b"Subject: x\r\n\r\nunfinished")
    assert (record.flow_id, record.end_reason) == (message.flow_id, reason)


def test_flows_not_detected_as_smtp_are_not_reassembled():
    table, out = make_table(), []
    feed_all(table, smtp_flow_events(application=app("HTTP", "payload", 0.9)), out)
    table.flush(out.append)
    assert [type(r) for r in out] == [FlowRecord]
```

In `tests/test_flow_table.py`, make `make_table` pass the new argument. Replace:

```python
        "max_flows": 100,
    }
```

with:

```python
        "max_flows": 100,
        "max_message_bytes": 1_048_576,
    }
```


- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_flow_smtp.py tests/test_flow_table.py -q`
Expected: collection error `ModuleNotFoundError: No module named 'ids.flow.smtp'` for `tests/test_flow_smtp.py`, and every `tests/test_flow_table.py` test fails with `TypeError: FlowTable.__init__() got an unexpected keyword argument 'max_message_bytes'`.

- [ ] **Step 3: Implement the reassembler**

Create `ids/flow/smtp.py`:

```python
from __future__ import annotations

import re

from ..model import MessageEvent, PacketEvent, SmtpSession, TcpInfo
from .tcp import SEQ_MOD

TERMINATOR = b"\r\n.\r\n"
_HALF = 1 << 31
_DATA_LINE = re.compile(rb"^DATA[ \t]*\r?$", re.IGNORECASE | re.MULTILINE)
_REPLY_354 = re.compile(rb"^354(?:[ \t-]|\r?$)", re.MULTILINE)

_IDLE, _WAIT_REPLY, _COLLECT = 0, 1, 2


def _seq_offset(seq: int, expected: int) -> int:
    """Signed distance from `expected` to `seq` in 32-bit sequence space."""
    diff = (seq - expected) % SEQ_MOD
    return diff - SEQ_MOD if diff >= _HALF else diff


def _has_data_command(data: bytes, session: SmtpSession | None) -> bool:
    if _DATA_LINE.search(data):
        return True
    return session is not None and any(command.verb == "DATA" for command in session.commands)


def _has_354(data: bytes, session: SmtpSession | None) -> bool:
    if _REPLY_354.search(data):
        return True
    return session is not None and any(reply.code == 354 for reply in session.replies)


class SmtpReassembler:
    """Rebuilds SMTP DATA bodies of one TCP flow into MessageEvents.

    The client is the side that sends `DATA`; collection starts after a `354` reply from the
    other side and stops at the `\\r\\n.\\r\\n` terminator, which is kept in `data`.
    """

    __slots__ = (
        "_buffer",
        "_client",
        "_count",
        "_end",
        "_flow_id",
        "_gap",
        "_max_bytes",
        "_next_seq",
        "_packet_ids",
        "_phase",
        "_seen",
        "_start",
        "_tail",
        "_truncated",
    )

    def __init__(self, flow_id: str, max_bytes: int) -> None:
        self._flow_id = flow_id
        self._max_bytes = max_bytes
        self._count = 0
        self._phase = _IDLE
        self._client: bool | None = None
        self._next_seq: int | None = None
        self._reset_message()

    def feed(self, event: PacketEvent, forward: bool, timestamp: float) -> MessageEvent | None:
        """Account one packet of the flow; return a MessageEvent when a body completes."""
        transport = event.transport
        if not isinstance(transport, TcpInfo):
            return None
        payload = event.payload
        data = payload.data if payload is not None and payload.data is not None else b""
        length = transport.payload_length if transport.payload_length is not None else len(data)
        if length == 0 and not data:
            return None
        message = event.application.message if event.application is not None else None
        session = message if isinstance(message, SmtpSession) else None

        if self._phase == _IDLE:
            if _has_data_command(data, session):
                self._phase = _WAIT_REPLY
                self._client = forward
                self._advance(transport.seq, length)
            return None
        if forward != self._client:
            if self._phase == _WAIT_REPLY and _has_354(data, session):
                self._phase = _COLLECT
            return None
        if self._phase == _WAIT_REPLY:
            self._advance(transport.seq, length)
            return None
        return self._collect(transport.seq, data, length, event.packet_id, timestamp)

    def finish(self) -> MessageEvent | None:
        """At flow export: the body being collected, if any, as an incomplete message."""
        if self._phase != _COLLECT or self._start is None:
            return None
        return self._emit(complete=False)

    def _advance(self, seq: int | None, length: int) -> None:
        if seq is None:
            return
        end = (seq + length) % SEQ_MOD
        if self._next_seq is None or _seq_offset(end, self._next_seq) > 0:
            self._next_seq = end

    def _collect(
        self, seq: int | None, data: bytes, length: int, packet_id: int | None, timestamp: float
    ) -> MessageEvent | None:
        offset = 0
        if seq is not None and self._next_seq is not None:
            offset = _seq_offset(seq, self._next_seq)
            if offset + length <= 0:
                return None  # retransmission of bytes already collected
        self._advance(seq, length)
        if offset > 0 or len(data) < length:
            self._gap = True  # bytes before or inside this segment were never captured
        if offset < 0:
            data = data[-offset:]  # overlap with bytes already collected
        if not data:
            return None
        if packet_id is not None:
            self._packet_ids.append(packet_id)
        if self._start is None:
            self._start = timestamp
        self._end = timestamp

        prefix = self._tail if self._seen else b"\r\n"
        cut = (prefix + data[:4]).find(TERMINATOR)
        if cut >= 0:
            cut += len(TERMINATOR) - len(prefix)
        else:
            cut = data.find(TERMINATOR)
            if cut >= 0:
                cut += len(TERMINATOR)
        body = data if cut < 0 else data[:cut]
        room = self._max_bytes - len(self._buffer)
        if len(body) > room:
            self._buffer += body[:room]
            self._truncated = True
        else:
            self._buffer += body
        self._seen += len(body)
        self._tail = body[-4:] if len(body) >= 4 else (prefix + body)[-4:]
        if cut < 0:
            return None

        message = self._emit(complete=True)
        # Pipelined commands after the terminator may already contain the next DATA.
        self._phase = _WAIT_REPLY if _DATA_LINE.search(data, cut) else _IDLE
        return message

    def _emit(self, *, complete: bool) -> MessageEvent:
        self._count += 1
        message = MessageEvent(
            message_id=f"{self._flow_id}-{self._count}",
            flow_id=self._flow_id,
            protocol="SMTP",
            packet_ids=self._packet_ids,
            start_time=self._start,
            end_time=self._end,
            data=bytes(self._buffer),
            complete=complete,
            truncated=self._truncated,
            gap=self._gap,
        )
        self._phase = _IDLE
        self._reset_message()
        return message

    def _reset_message(self) -> None:
        self._buffer = bytearray()
        self._packet_ids: list[int] = []
        self._start: float | None = None
        self._end: float | None = None
        self._seen = 0
        self._tail = b""
        self._truncated = False
        self._gap = False
```

- [ ] **Step 4: Give `FlowState` an `smtp` slot**

In `ids/flow/records.py`:

Replace:

```python
import math
```

with:

```python
import math
from typing import TYPE_CHECKING
```

Replace:

```python
from .tcp import TcpConnection, is_syn_ack
```

with:

```python
from .tcp import TcpConnection, is_syn_ack

if TYPE_CHECKING:
    from .smtp import SmtpReassembler
```

Replace:

```python
    __slots__ = ("_app_rank", "key", "record", "tcp", "touched")
```

with:

```python
    __slots__ = ("_app_rank", "key", "record", "smtp", "tcp", "touched")
```

Replace:

```python
        self._app_rank: tuple[int, float] | None = None
```

with:

```python
        self._app_rank: tuple[int, float] | None = None
        self.smtp: SmtpReassembler | None = None  # set by the table once the flow is SMTP
```


- [ ] **Step 5: Hook the reassembler into the table**

In `ids/flow/table.py`:

Replace:

```python
from .records import FlowState
from .tcp import TERMINAL_STATES, is_new_syn
```

with:

```python
from .records import FlowState
from .smtp import SmtpReassembler
from .tcp import TERMINAL_STATES, is_new_syn
```

Replace:

```python
        max_flows: int,
    ) -> None:
```

with:

```python
        max_flows: int,
        max_message_bytes: int,
    ) -> None:
```

Replace:

```python
        self.max_flows = max_flows
```

with:

```python
        self.max_flows = max_flows
        self.max_message_bytes = max_message_bytes
```

Replace:

```python
        ref = flow.add(event, src == flow.record.endpoint_a, timestamp, now)
```

with:

```python
        forward = src == flow.record.endpoint_a
        ref = flow.add(event, forward, timestamp, now)
        if flow.tcp is not None:
            if flow.smtp is None and flow.record.application_protocol == "SMTP":
                flow.smtp = SmtpReassembler(flow.record.flow_id, self.max_message_bytes)
            if flow.smtp is not None:
                message = flow.smtp.feed(event, forward, timestamp)
                if message is not None:
                    emit(message)
```

Replace:

```python
    def _export(self, flow: FlowState, reason: EndReason, emit: Emit) -> None:
        emit(flow.finish(reason))
```

with:

```python
    def _export(self, flow: FlowState, reason: EndReason, emit: Emit) -> None:
        if flow.smtp is not None:
            message = flow.smtp.finish()
            if message is not None:
                emit(message)  # an unfinished DATA body goes out before its flow record
        emit(flow.finish(reason))
```

After these edits `ids/flow/table.py` reads:

```python
from __future__ import annotations

from collections import OrderedDict
from typing import TYPE_CHECKING

from ..model import Endpoint, EndReason, FlowRef, PacketEvent, TcpState
from .key import FlowKey
from .records import FlowState
from .smtp import SmtpReassembler
from .tcp import TERMINAL_STATES, is_new_syn

if TYPE_CHECKING:
    from ..pipeline import Emit

Lane = OrderedDict[FlowKey, FlowState]

_CLOSED_REASONS = {TcpState.CLOSED: EndReason.CLOSED, TcpState.RESET: EndReason.RESET}


def _closed_reason(flow: FlowState) -> EndReason:
    """End reason of a flow in the closed lane: its terminal TCP state."""
    return _CLOSED_REASONS[flow.tcp.state]


class FlowTable:
    """Active flows in three lanes ordered by last activity: TCP open, TCP closed, UDP.

    The clock is the largest packet or tick time seen and never moves backwards. A flow
    expires when `clock - touched > lane timeout`, where `touched` is the clock value at its
    latest packet.
    """

    def __init__(
        self,
        *,
        tcp_idle_timeout: float,
        udp_idle_timeout: float,
        tcp_closed_timeout: float,
        max_flows: int,
        max_message_bytes: int,
    ) -> None:
        self.tcp_open: Lane = OrderedDict()
        self.tcp_closed: Lane = OrderedDict()
        self.udp: Lane = OrderedDict()
        self.clock: float | None = None
        self.max_flows = max_flows
        self.max_message_bytes = max_message_bytes
        self._lanes = (self.tcp_open, self.tcp_closed, self.udp)
        self._timeouts = (
            (self.tcp_open, tcp_idle_timeout),
            (self.tcp_closed, tcp_closed_timeout),
            (self.udp, udp_idle_timeout),
        )

    @property
    def active_count(self) -> int:
        return len(self.tcp_open) + len(self.tcp_closed) + len(self.udp)

    def advance(self, now: float, emit: Emit) -> float:
        """Move the clock forward to `now` (never back), export expired flows, return clock."""
        if self.clock is None or now > self.clock:
            self.clock = now
        self._expire(self.clock, emit)
        return self.clock

    def apply(
        self,
        event: PacketEvent,
        key: FlowKey,
        src: Endpoint,
        dst: Endpoint,
        timestamp: float,
        emit: Emit,
    ) -> FlowRef:
        """Expire first, then account `event` to its flow (created if needed)."""
        now = self.advance(timestamp, emit)
        if key.proto == "TCP":
            flow, lane = self._tcp_flow(event, key, src, dst, timestamp, emit)
        else:
            lane = self.udp
            flow = lane.get(key)
            if flow is None:
                flow = self._create(lane, key, src, dst, event, timestamp, emit)
            else:
                lane.move_to_end(key)
        forward = src == flow.record.endpoint_a
        ref = flow.add(event, forward, timestamp, now)
        if flow.tcp is not None:
            if flow.smtp is None and flow.record.application_protocol == "SMTP":
                flow.smtp = SmtpReassembler(flow.record.flow_id, self.max_message_bytes)
            if flow.smtp is not None:
                message = flow.smtp.feed(event, forward, timestamp)
                if message is not None:
                    emit(message)
        if lane is self.tcp_open and ref.state in TERMINAL_STATES:
            del self.tcp_open[key]
            self.tcp_closed[key] = flow
        return ref

    def flush(self, emit: Emit) -> None:
        """Export every flow, oldest activity first.

        Closed-lane flows keep their closed/reset reason; the others end with end_of_input.
        """
        while (lane := self._oldest_lane()) is not None:
            _, flow = lane.popitem(last=False)
            self._export(flow, self._reason(lane, flow, EndReason.END_OF_INPUT), emit)

    def _tcp_flow(
        self,
        event: PacketEvent,
        key: FlowKey,
        src: Endpoint,
        dst: Endpoint,
        timestamp: float,
        emit: Emit,
    ) -> tuple[FlowState, Lane]:
        flow = self.tcp_open.get(key)
        if flow is not None:
            self.tcp_open.move_to_end(key)
            return flow, self.tcp_open
        flow = self.tcp_closed.get(key)
        if flow is not None:
            if not is_new_syn(event.transport.flags):
                self.tcp_closed.move_to_end(key)
                return flow, self.tcp_closed
            # Port reuse during the linger: the old connection ends, a new flow starts.
            del self.tcp_closed[key]
            self._export(flow, _closed_reason(flow), emit)
        return self._create(self.tcp_open, key, src, dst, event, timestamp, emit), self.tcp_open

    def _create(
        self,
        lane: Lane,
        key: FlowKey,
        src: Endpoint,
        dst: Endpoint,
        event: PacketEvent,
        timestamp: float,
        emit: Emit,
    ) -> FlowState:
        if self.active_count >= self.max_flows:
            oldest = self._oldest_lane()
            _, evicted = oldest.popitem(last=False)
            self._export(evicted, EndReason.EVICTED, emit)
        flow = FlowState(key, src, dst, event, timestamp)
        lane[key] = flow
        return flow

    def _expire(self, clock: float, emit: Emit) -> None:
        """Export expired lane fronts in order of their expiry deadline."""
        while True:
            best: Lane | None = None
            best_deadline = 0.0
            for lane, timeout in self._timeouts:
                if not lane:
                    continue
                touched = next(iter(lane.values())).touched
                deadline = touched + timeout
                if clock - touched > timeout and (best is None or deadline < best_deadline):
                    best, best_deadline = lane, deadline
            if best is None:
                return
            _, flow = best.popitem(last=False)
            self._export(flow, self._reason(best, flow, EndReason.IDLE_TIMEOUT), emit)

    def _oldest_lane(self) -> Lane | None:
        best: Lane | None = None
        best_touched = 0.0
        for lane in self._lanes:
            if lane:
                touched = next(iter(lane.values())).touched
                if best is None or touched < best_touched:
                    best, best_touched = lane, touched
        return best

    def _reason(self, lane: Lane, flow: FlowState, default: EndReason) -> EndReason:
        return _closed_reason(flow) if lane is self.tcp_closed else default

    def _export(self, flow: FlowState, reason: EndReason, emit: Emit) -> None:
        if flow.smtp is not None:
            message = flow.smtp.finish()
            if message is not None:
                emit(message)  # an unfinished DATA body goes out before its flow record
        emit(flow.finish(reason))
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `uv run pytest tests/test_flow_smtp.py tests/test_flow_table.py tests/test_flow_records.py -q`
Expected: `51 passed`.

- [ ] **Step 7: Full suite and lint**

Run: `uv run pytest -q`
Expected: all tests pass (0 failed, 0 errors).

Run: `uv run ruff check ids/flow tests/test_flow_smtp.py tests/test_flow_table.py && uv run ruff format --check ids/flow tests/test_flow_smtp.py tests/test_flow_table.py`
Expected: `All checks passed!` and `N files already formatted` (no file would be reformatted).

- [ ] **Step 8: Commit**

```bash
git add ids/flow/smtp.py ids/flow/records.py ids/flow/table.py tests/test_flow_smtp.py tests/test_flow_table.py
git commit -m "feat: add smtp data reassembly"
```

---
### Task 6: Flow tracker stage, live ticks and CLI wiring

**Files:**
- Create: `ids/flow/stage.py`
- Modify: `ids/flow/__init__.py`
- Modify: `ids/capture/live.py` (`LiveSource.__init__`, `LiveSource.items`, model import)
- Modify: `ids/cli.py` (imports, `build_parser`, `build_stages`, `main`, `_open_source`)
- Modify: `tests/test_live.py` (imports + three tests)
- Test: `tests/test_flow_stage.py`, `tests/test_flow_pipeline.py`, `tests/test_cli_flow.py`

**Interfaces:**
- Consumes: `make_key` (Task 1); `packet_time` (Task 3); `FlowTable` (Tasks 4–5); `ids.model` `MessageEvent`, `PacketEvent`, `PreprocessStatus`, `RawPacket`, `Tick`; `ids.stats.Stats` (`extra: dict[str, object]`); `ids.pipeline.Runner`, `Emit`; `ids.parsers.PacketParser`; `ids.decoder.stage.DecoderStage`; `ids.preprocess.stage.PreprocessorStage`; `ids.cli` helpers `non_negative_float`, `positive_int`, `_open_source(args)`, `JsonlSink(path, *, flows_path=None)`; test fixture `fake` and `FakePacket` (from `tests/fake_scapy.py`, plan 1c) in `tests/test_live.py`; `golden.UDP`, `golden.CLIENT_MAC`, `golden.SERVER_MAC`.
- Produces (contract §10, verbatim):
  - `FlowConfig(tcp_idle_timeout: float = 300.0, udp_idle_timeout: float = 60.0, tcp_closed_timeout: float = 5.0, max_flows: int = 100_000, max_message_bytes: int = 1_048_576)` — `@dataclass(slots=True)`.
  - `FlowTrackerStage(config: FlowConfig | None = None, stats: Stats | None = None)`, `name = "flow"`, attribute `config`, property `active_count -> int`, `process(record, emit)`, `tick(now, emit)`, `flush(emit)`. `flush` sets `stats.extra["active_flows"]` to the number of flows still active when the input ended, then exports them.
  - `ids.flow` re-exports `FlowConfig`, `FlowTrackerStage`.
  - `LiveSource(interface, *, bpf_filter=None, count=None, promiscuous=True, capture_idle_timeout=None, poll_interval=1.0, tick=False)`; with `tick=True`, `items()` yields `Tick(time.time())` after every idle poll that does not stop the capture.
  - `build_stages(args: argparse.Namespace, stats: Stats) -> list[Stage]` (signature change; `main` is its only caller).
  - CLI flags `--flows-output FILE`, `--tcp-idle-timeout`, `--udp-idle-timeout`, `--tcp-closed-timeout`, `--max-flows`, `--max-message-bytes`.

- [ ] **Step 1: Write the failing stage tests**

Create `tests/test_flow_stage.py`:

```python
from __future__ import annotations

from flow_events import CLIENT, SERVER, T0, tcp_event, udp_event

from ids.flow import FlowConfig, FlowTrackerStage
from ids.model import (
    EndReason,
    FlowRecord,
    MessageEvent,
    Normalized,
    PacketEvent,
    PreprocessStatus,
)
from ids.stats import Stats


def test_message_events_pass_untouched():
    stage, out = FlowTrackerStage(), []
    message = MessageEvent(message_id="x-1", data=b"hi")
    stage.process(message, out.append)
    assert out == []
    assert stage.active_count == 0


def test_invalid_events_are_not_tracked():
    stage, out = FlowTrackerStage(), []
    event = udp_event(1, T0, CLIENT, SERVER)
    event.preprocess_status = PreprocessStatus.INVALID
    stage.process(event, out.append)
    assert event.flow is None
    assert stage.active_count == 0


def test_partial_events_are_tracked():
    stage, out = FlowTrackerStage(), []
    event = udp_event(1, T0, CLIENT, SERVER)
    event.preprocess_status = PreprocessStatus.PARTIAL
    stage.process(event, out.append)
    assert event.flow is not None
    assert event.flow.flow_packet_index == 1


def test_events_without_a_five_tuple_or_time_are_not_tracked():
    stage, out = FlowTrackerStage(), []
    no_transport = PacketEvent(packet_id=1, timestamp=T0)
    no_time = udp_event(2, T0, CLIENT, SERVER)
    no_time.timestamp = None
    for event in (no_transport, no_time):
        stage.process(event, out.append)
        assert event.flow is None
    assert stage.active_count == 0


def test_normalized_timestamps_drive_the_clock():
    stage, out = FlowTrackerStage(), []
    first = udp_event(1, 1759000000000.0, CLIENT, SERVER)  # raw value in milliseconds
    first.normalized = Normalized(timestamp=T0)
    second = udp_event(2, 1759000001000.0, SERVER, CLIENT)
    second.normalized = Normalized(timestamp=T0 + 1)
    stage.process(first, out.append)
    stage.process(second, out.append)
    assert out == []
    assert second.flow.flow_id == first.flow.flow_id
    stage.flush(out.append)
    assert (out[0].start_time, out[0].duration) == (T0, 1.0)


def test_tick_expires_idle_flows_without_new_packets():
    stage = FlowTrackerStage(FlowConfig(udp_idle_timeout=60.0))
    out = []
    stage.process(udp_event(1, T0, CLIENT, SERVER), out.append)
    stage.tick(T0 + 30, out.append)
    assert out == []
    stage.tick(T0 + 61, out.append)
    assert [(type(r), r.end_reason) for r in out] == [(FlowRecord, EndReason.IDLE_TIMEOUT)]
    assert stage.active_count == 0


def test_flush_reports_active_flows_and_exports_them():
    stats = Stats()
    stage, out = FlowTrackerStage(stats=stats), []
    stage.process(udp_event(1, T0, CLIENT, SERVER), out.append)
    stage.process(tcp_event(2, T0 + 1, CLIENT, SERVER, "S"), out.append)
    stage.flush(out.append)
    assert stats.extra["active_flows"] == 2
    assert [r.end_reason for r in out] == [EndReason.END_OF_INPUT, EndReason.END_OF_INPUT]
    assert stage.active_count == 0
```

Create `tests/test_flow_pipeline.py` (real parser, decoder, preprocessor and tracker behind the plan 1c `Runner`; frames built with scapy):

```python
from __future__ import annotations

from golden import CLIENT_MAC, SERVER_MAC
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

from ids.decoder.stage import DecoderStage
from ids.flow import FlowConfig, FlowTrackerStage
from ids.model import (
    Direction,
    Endpoint,
    EndReason,
    FlowRecord,
    Ipv4Info,
    PacketEvent,
    RawPacket,
    TcpState,
    UdpInfo,
)
from ids.parsers import PacketParser
from ids.pipeline import Runner
from ids.preprocess.stage import PreprocessorStage
from ids.stats import Stats

T0 = 1759000000.0
CLIENT = ("10.0.0.1", 40000)
SERVER = ("10.0.0.2", 80)


class ListSink:
    def __init__(self) -> None:
        self.records = []

    def write(self, record) -> None:
        self.records.append(record)


def tcp(src, dst, flags, seq, ack, payload=b""):
    packet = Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IP(src=src[0], dst=dst[0])
    packet = packet / TCP(sport=src[1], dport=dst[1], flags=flags, seq=seq, ack=ack)
    return bytes(packet / payload) if payload else bytes(packet)


def udp(src, dst, payload):
    packet = Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IP(src=src[0], dst=dst[0])
    return bytes(packet / UDP(sport=src[1], dport=dst[1]) / payload)


def raw_packets(frames):
    """frames: (timestamp, ethernet bytes); packet ids are 1-based positions."""
    for packet_id, (timestamp, data) in enumerate(frames, start=1):
        yield RawPacket(
            packet_id=packet_id,
            timestamp=timestamp,
            data=data,
            linktype=1,
            source="pcap",
            origin="test.pcap",
            original_length=len(data),
            declared_capture_length=len(data),
        )


def run(items, config: FlowConfig | None = None):
    sink, stats = ListSink(), Stats()
    stages = [DecoderStage(), PreprocessorStage(), FlowTrackerStage(config, stats)]
    Runner(PacketParser(), stages, sink, stats).run(items)
    return sink.records, stats


def handshake(client=CLIENT, start=T0):
    return [
        (start, tcp(client, SERVER, "S", 1000, 0)),
        (start + 0.1, tcp(SERVER, client, "SA", 5000, 1001)),
        (start + 0.2, tcp(client, SERVER, "A", 1001, 5001)),
    ]


def packets_of(records):
    return [r for r in records if isinstance(r, PacketEvent)]


def flows_of(records):
    return [r for r in records if isinstance(r, FlowRecord)]


def test_t07_handshake_gives_one_established_flow():
    records, stats = run(raw_packets(handshake()))
    packets = packets_of(records)
    assert [type(r) for r in records] == [PacketEvent, PacketEvent, PacketEvent, FlowRecord]
    assert len({p.flow.flow_id for p in packets}) == 1
    assert packets[2].flow.state is TcpState.ESTABLISHED
    (flow,) = flows_of(records)
    assert flow.tcp.state is TcpState.ESTABLISHED
    assert flow.tcp.handshake_complete is True
    assert flow.endpoint_a == Endpoint("10.0.0.1", 40000)
    assert flow.end_reason is EndReason.END_OF_INPUT
    assert stats.extra["active_flows"] == 1


def test_t08_directions_follow_the_sender():
    request = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    frames = [
        *handshake(),
        (T0 + 0.3, tcp(CLIENT, SERVER, "PA", 1001, 5001, request)),
        (T0 + 0.4, tcp(SERVER, CLIENT, "PA", 5001, 1001 + len(request), response)),
        (T0 + 0.5, tcp(CLIENT, SERVER, "A", 1001 + len(request), 5001 + len(response))),
    ]
    records, _ = run(raw_packets(frames))
    packets = packets_of(records)
    assert len({p.flow.flow_id for p in packets}) == 1
    assert [p.flow.direction for p in packets] == [
        Direction.FORWARD,
        Direction.BACKWARD,
        Direction.FORWARD,
        Direction.FORWARD,
        Direction.BACKWARD,
        Direction.FORWARD,
    ]
    (flow,) = flows_of(records)
    assert flow.application_protocol == "HTTP"
    assert (flow.forward.packet_count, flow.backward.packet_count) == (4, 2)
    assert (flow.forward.payload_byte_count, flow.backward.payload_byte_count) == (
        len(request),
        len(response),
    )


def test_t09_fin_close_and_rst_abort():
    reset_client = ("10.0.0.1", 40001)
    frames = [
        *handshake(),
        (T0 + 0.3, tcp(CLIENT, SERVER, "FA", 1001, 5001)),
        (T0 + 0.4, tcp(SERVER, CLIENT, "FA", 5001, 1002)),
        (T0 + 0.5, tcp(CLIENT, SERVER, "A", 1002, 5002)),
        *handshake(reset_client, T0 + 1),
        (T0 + 1.3, tcp(reset_client, SERVER, "R", 1001, 0)),
    ]
    records, _ = run(raw_packets(frames))
    packets = packets_of(records)
    assert packets[5].flow.state is TcpState.CLOSED
    assert packets[9].flow.state is TcpState.RESET
    by_port = {flow.endpoint_a.port: flow for flow in flows_of(records)}
    assert (by_port[40000].tcp.state, by_port[40000].end_reason) == (
        TcpState.CLOSED,
        EndReason.CLOSED,
    )
    assert (by_port[40001].tcp.state, by_port[40001].end_reason) == (
        TcpState.RESET,
        EndReason.RESET,
    )


def test_expired_flow_record_is_written_before_the_packet_that_expired_it():
    frames = [
        (T0, udp(("10.0.0.1", 9000), ("10.0.0.2", 9001), b"ping")),
        (T0 + 61, udp(("10.0.0.3", 9000), ("10.0.0.2", 9001), b"ping")),
    ]
    records, _ = run(raw_packets(frames))
    assert [type(r) for r in records] == [PacketEvent, FlowRecord, PacketEvent, FlowRecord]
    assert records[1].flow_id == records[0].flow.flow_id
    assert records[1].end_reason is EndReason.IDLE_TIMEOUT
    assert records[3].flow_id == records[2].flow.flow_id


def test_invalid_event_is_written_without_a_flow():
    event = PacketEvent(
        packet_id=1,
        timestamp=T0,
        network=Ipv4Info(protocol="IPv4", src_ip="10.0.0.1", dst_ip="10.0.0.2"),
        transport=UdpInfo(src_port=70000, dst_port=53),
    )
    records, stats = run([event])
    assert records == [event]
    assert event.flow is None
    assert stats.extra["active_flows"] == 0
```

Create `tests/test_cli_flow.py`:

```python
from __future__ import annotations

import base64
import json

import pytest
from golden import CLIENT_MAC, SERVER_MAC
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from ids.cli import build_parser, main

T0 = 1759000000.0
CLIENT = ("10.0.0.1", 53000)
RESOLVER = ("10.0.0.53", 53)


def frame(timestamp, src, dst, layer4, payload=b""):
    packet = Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IP(src=src[0], dst=dst[0]) / layer4
    if payload:
        packet = packet / payload
    packet.time = timestamp
    return packet


def udp_frame(timestamp, src, dst, payload=b"ping"):
    return frame(timestamp, src, dst, UDP(sport=src[1], dport=dst[1]), payload)


def tcp_frame(timestamp, src, dst, flags, seq, ack, payload=b""):
    layer4 = TCP(sport=src[1], dport=dst[1], flags=flags, seq=seq, ack=ack)
    return frame(timestamp, src, dst, layer4, payload)


def run_cli(tmp_path, frames, *extra):
    pcap = tmp_path / "in.pcap"
    out = tmp_path / "out.jsonl"
    wrpcap(str(pcap), frames)
    assert main(["-r", str(pcap), "-o", str(out), "-q", *extra]) == 0
    return [json.loads(line) for line in out.read_text().splitlines()]


def test_flow_records_share_the_main_stream_by_default(tmp_path):
    records = run_cli(
        tmp_path, [udp_frame(T0, CLIENT, RESOLVER), udp_frame(T0 + 0.5, RESOLVER, CLIENT)]
    )
    assert [r["record_type"] for r in records] == ["packet", "packet", "flow"]
    assert records[2]["packet_count"] == 2
    assert records[2]["end_reason"] == "end_of_input"
    assert records[0]["flow"]["flow_id"] == records[2]["flow_id"]


def test_flows_output_moves_flow_records_to_their_own_file(tmp_path):
    flows = tmp_path / "flows.jsonl"
    records = run_cli(
        tmp_path,
        [udp_frame(T0, CLIENT, RESOLVER), udp_frame(T0 + 0.5, RESOLVER, CLIENT)],
        "--flows-output",
        str(flows),
    )
    assert [r["record_type"] for r in records] == ["packet", "packet"]
    flow_records = [json.loads(line) for line in flows.read_text().splitlines()]
    assert [r["record_type"] for r in flow_records] == ["flow"]
    assert flow_records[0]["flow_id"] == records[0]["flow"]["flow_id"]


def test_udp_idle_timeout_flag_splits_a_quiet_flow(tmp_path):
    frames = [udp_frame(T0, CLIENT, RESOLVER), udp_frame(T0 + 5, CLIENT, RESOLVER)]
    assert [r["record_type"] for r in run_cli(tmp_path, frames)] == ["packet", "packet", "flow"]
    records = run_cli(tmp_path, frames, "--udp-idle-timeout", "2")
    assert [r["record_type"] for r in records] == ["packet", "flow", "packet", "flow"]
    assert records[1]["end_reason"] == "idle_timeout"


def test_tcp_idle_timeout_flag_splits_a_quiet_connection(tmp_path):
    server = ("10.0.0.2", 8080)
    frames = [
        tcp_frame(T0, CLIENT, server, "S", 1, 0),
        tcp_frame(T0 + 10, server, CLIENT, "SA", 9, 2),
    ]
    records = run_cli(tmp_path, frames, "--tcp-idle-timeout", "5")
    flows = [r for r in records if r["record_type"] == "flow"]
    assert [f["end_reason"] for f in flows] == ["idle_timeout", "end_of_input"]


def test_tcp_closed_timeout_flag_ends_the_linger(tmp_path):
    server = ("10.0.0.2", 8080)
    frames = [
        tcp_frame(T0, CLIENT, server, "S", 1, 0),
        tcp_frame(T0 + 0.1, server, CLIENT, "R", 0, 2),
        udp_frame(T0 + 2, CLIENT, RESOLVER),
    ]
    default = run_cli(tmp_path, frames)
    assert [r["record_type"] for r in default] == ["packet", "packet", "packet", "flow", "flow"]
    records = run_cli(tmp_path, frames, "--tcp-closed-timeout", "1")
    assert [r["record_type"] for r in records] == ["packet", "packet", "flow", "packet", "flow"]
    assert records[2]["end_reason"] == "reset"


def test_max_flows_flag_evicts_the_oldest_flow(tmp_path):
    other = ("10.0.0.9", 53001)
    frames = [udp_frame(T0, CLIENT, RESOLVER), udp_frame(T0 + 1, other, RESOLVER)]
    records = run_cli(tmp_path, frames, "--max-flows", "1")
    assert [r["record_type"] for r in records] == ["packet", "flow", "packet", "flow"]
    assert records[1]["end_reason"] == "evicted"


def test_max_message_bytes_flag_caps_a_reassembled_smtp_body(tmp_path):
    client, server = ("10.0.0.1", 40000), ("10.0.0.2", 25)
    body = b"Subject: hi\r\n\r\nhello world\r\n.\r\n"
    frames = [
        tcp_frame(T0, client, server, "PA", 100, 900, b"EHLO client.test\r\n"),
        tcp_frame(T0 + 0.1, server, client, "PA", 900, 118, b"250 ok\r\n"),
        tcp_frame(T0 + 0.2, client, server, "PA", 118, 908, b"DATA\r\n"),
        tcp_frame(T0 + 0.3, server, client, "PA", 908, 124, b"354 go ahead\r\n"),
        tcp_frame(T0 + 0.4, client, server, "PA", 124, 922, body),
    ]
    records = run_cli(tmp_path, frames, "--max-message-bytes", "4")
    assert [r["record_type"] for r in records] == [
        "packet",
        "packet",
        "packet",
        "packet",
        "message",
        "packet",
        "flow",
    ]
    message = records[4]
    assert base64.b64decode(message["data_b64"]) == b"Subj"
    assert (message["complete"], message["truncated"], message["gap"]) == (True, True, False)
    assert message["packet_ids"] == [5]
    assert message["flow_id"] == records[6]["flow_id"]


@pytest.mark.parametrize(
    ("flag", "value"),
    [
        ("--tcp-idle-timeout", "-1"),
        ("--udp-idle-timeout", "-1"),
        ("--tcp-closed-timeout", "-1"),
        ("--max-flows", "0"),
        ("--max-message-bytes", "0"),
    ],
)
def test_flow_limits_reject_out_of_range_values(flag, value):
    with pytest.raises(SystemExit) as caught:
        build_parser().parse_args(["-r", "in.pcap", flag, value])
    assert caught.value.code == 2
```

Append to `tests/test_live.py`:

```python
def test_tick_mode_yields_ticks_while_the_interface_is_idle(fake):
    fake(packets=[FakePacket(UDP, 1759000000.5)])
    before = time.time()
    items = list(LiveSource("eth0", tick=True, capture_idle_timeout=0.05).items())
    after = time.time()
    assert isinstance(items[0], RawPacket)
    ticks = items[1:]
    assert ticks
    assert all(isinstance(item, Tick) and before <= item.now <= after for item in ticks)


def test_no_ticks_without_tick_mode(fake):
    fake(packets=[FakePacket(UDP, 1759000000.5)])
    items = list(LiveSource("eth0", capture_idle_timeout=0.05).items())
    assert [type(item) for item in items] == [RawPacket]


def test_live_run_expires_idle_flows_on_ticks(fake, tmp_path):
    fake(packets=[FakePacket(UDP, time.time() - 30)])
    out = tmp_path / "out.jsonl"
    argv = ["-i", "eth0", "-o", str(out), "-q", "--capture-idle-timeout", "0.2"]
    assert main([*argv, "--udp-idle-timeout", "1"]) == 0
    records = [json.loads(line) for line in out.read_text().splitlines()]
    assert [r["record_type"] for r in records] == ["packet", "flow"]
    assert records[1]["end_reason"] == "idle_timeout"
```

and merge these imports into the existing import block of `tests/test_live.py` (keep the ones already there; `ruff check --fix` sorts them if needed):

```python
import json
import time

from golden import UDP

from ids.capture.live import LiveSource
from ids.cli import main
from ids.model import RawPacket, Tick
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_flow_stage.py tests/test_flow_pipeline.py tests/test_cli_flow.py tests/test_live.py -q`
Expected:
- `tests/test_flow_stage.py`, `tests/test_flow_pipeline.py`: collection error `ImportError: cannot import name 'FlowConfig' from 'ids.flow'`.
- `tests/test_cli_flow.py`: `test_flow_records_share_the_main_stream_by_default`, `test_udp_idle_timeout_flag_splits_a_quiet_flow` and `test_tcp_closed_timeout_flag_ends_the_linger` fail their first record-type assertion (no `"flow"` line is written yet); the other flag tests fail with `SystemExit: 2` (argparse `unrecognized arguments`); the five range tests fail on `assert f"argument {flag}:" in …` because argparse reports `unrecognized arguments` instead.
- `tests/test_live.py`: `test_tick_mode_yields_ticks_while_the_interface_is_idle` fails with `TypeError: LiveSource.__init__() got an unexpected keyword argument 'tick'`; `test_live_run_expires_idle_flows_on_ticks` fails with `SystemExit: 2` (`--udp-idle-timeout` unknown); `test_no_ticks_without_tick_mode` already passes, it pins the default that must not change.

- [ ] **Step 3: Implement the stage**

Create `ids/flow/stage.py`:

```python
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..model import MessageEvent, PacketEvent, PreprocessStatus
from .key import make_key
from .records import packet_time
from .table import FlowTable

if TYPE_CHECKING:
    from ..pipeline import Emit
    from ..stats import Stats


@dataclass(slots=True)
class FlowConfig:
    tcp_idle_timeout: float = 300.0
    udp_idle_timeout: float = 60.0
    tcp_closed_timeout: float = 5.0
    max_flows: int = 100_000
    max_message_bytes: int = 1_048_576


class FlowTrackerStage:
    """Annotates packets with `flow`, emits FlowRecords and reassembled SMTP MessageEvents."""

    name = "flow"

    def __init__(self, config: FlowConfig | None = None, stats: Stats | None = None) -> None:
        self.config = config if config is not None else FlowConfig()
        self._stats = stats
        self._table = FlowTable(
            tcp_idle_timeout=self.config.tcp_idle_timeout,
            udp_idle_timeout=self.config.udp_idle_timeout,
            tcp_closed_timeout=self.config.tcp_closed_timeout,
            max_flows=self.config.max_flows,
            max_message_bytes=self.config.max_message_bytes,
        )

    @property
    def active_count(self) -> int:
        return self._table.active_count

    def process(self, record: PacketEvent | MessageEvent, emit: Emit) -> None:
        if not isinstance(record, PacketEvent):
            return
        if record.preprocess_status is PreprocessStatus.INVALID:
            return
        timestamp = packet_time(record)
        if timestamp is None:
            return
        found = make_key(record)
        if found is None:
            return
        key, src, dst = found
        record.flow = self._table.apply(record, key, src, dst, timestamp, emit)

    def tick(self, now: float, emit: Emit) -> None:
        self._table.advance(now, emit)

    def flush(self, emit: Emit) -> None:
        if self._stats is not None:
            self._stats.extra["active_flows"] = self._table.active_count
        self._table.flush(emit)
```

Replace the whole of `ids/flow/__init__.py` with:

```python
"""Flow/Connection Tracker: groups packets into TCP/UDP flows."""

from __future__ import annotations

from .stage import FlowConfig, FlowTrackerStage

__all__ = ["FlowConfig", "FlowTrackerStage"]
```

- [ ] **Step 4: Run the stage tests to verify they pass**

Run: `uv run pytest tests/test_flow_stage.py tests/test_flow_pipeline.py -q`
Expected: `12 passed`.

- [ ] **Step 5: Emit ticks from the live source**

In `ids/capture/live.py`:

1. Add `Tick` to the existing `from ..model import …` line (e.g. `from ..model import RawPacket, Tick`).
2. In `LiveSource.__init__`, add the keyword-only parameter `tick: bool = False` after `poll_interval: float = 1.0`, and next to `self.poll_interval = poll_interval` add:

```python
        self.tick = tick
```

3. Replace the whole `items` method with:

```python
    def items(self) -> Iterator[RawPacket | Tick]:
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
                    if self.tick:
                        yield Tick(time.time())  # lets the flow tracker expire idle flows
                    continue
                packet = socket.recv()
                if packet is None:
                    continue
                last_packet = time.monotonic()
                index += 1
                yield self._raw_packet(index, packet, layer2num.get(type(packet), DLT_EN10MB))
        finally:
            socket.close()
```

Only the return annotation and the `if self.tick:` branch differ from plan 1c's method. Without `tick=True` the source behaves exactly as before, so pcap and events runs never see a `Tick`.

- [ ] **Step 6: Wire the tracker into the CLI**

In `ids/cli.py`:

1. Add the import right after the `from .decoder import …` line:

```python
from .flow import FlowConfig, FlowTrackerStage
```

2. In `build_parser()`, insert immediately before the final `return parser`:

```python
    parser.add_argument(
        "--flows-output",
        metavar="FILE",
        default=None,
        help="write flow records to FILE instead of the main output",
    )
    parser.add_argument(
        "--tcp-idle-timeout",
        type=non_negative_float,
        default=300.0,
        metavar="SECONDS",
        help="export an open TCP flow after this long without packets (default: 300)",
    )
    parser.add_argument(
        "--udp-idle-timeout",
        type=non_negative_float,
        default=60.0,
        metavar="SECONDS",
        help="export a UDP flow after this long without packets (default: 60)",
    )
    parser.add_argument(
        "--tcp-closed-timeout",
        type=non_negative_float,
        default=5.0,
        metavar="SECONDS",
        help="keep a closed or reset TCP flow this long for trailing packets (default: 5)",
    )
    parser.add_argument(
        "--max-flows",
        type=positive_int,
        default=100_000,
        metavar="N",
        help="evict the least recently active flow above N active flows (default: 100000)",
    )
    parser.add_argument(
        "--max-message-bytes",
        type=positive_int,
        default=1_048_576,
        metavar="BYTES",
        help="bytes kept per reassembled SMTP message (default: 1048576)",
    )
```

3. Replace `build_stages` (as left by plans 2 and 3):

```python
def build_stages(args: argparse.Namespace) -> list[Stage]:
    return [
        DecoderStage(DecoderConfig(max_decoded_bytes=args.max_decoded_bytes)),
        PreprocessorStage(
            PreprocessConfig(
                invalid_policy=args.invalid_policy, unsupported_policy=args.unsupported_policy
            )
        ),
    ]
```

with:

```python
def build_stages(args: argparse.Namespace, stats: Stats) -> list[Stage]:
    return [
        DecoderStage(DecoderConfig(max_decoded_bytes=args.max_decoded_bytes)),
        PreprocessorStage(
            PreprocessConfig(
                invalid_policy=args.invalid_policy, unsupported_policy=args.unsupported_policy
            )
        ),
        FlowTrackerStage(
            FlowConfig(
                tcp_idle_timeout=args.tcp_idle_timeout,
                udp_idle_timeout=args.udp_idle_timeout,
                tcp_closed_timeout=args.tcp_closed_timeout,
                max_flows=args.max_flows,
                max_message_bytes=args.max_message_bytes,
            ),
            stats,
        ),
    ]
```

If the `DecoderStage(...)` or `PreprocessorStage(...)` element in your file differs from the text above, keep your file's two elements unchanged and only change the signature and append the `FlowTrackerStage(...)` element.

4. In `main()`, `stats = Stats()` is created before the stages; pass it in and route flow records:

Replace:

```python
    stages = build_stages(args)
```

with:

```python
    stages = build_stages(args, stats)
```

Replace:

```python
    with JsonlSink(args.output) as sink:
```

with:

```python
    with JsonlSink(args.output, flows_path=args.flows_output) as sink:
```

5. In `_open_source(args)`, add `tick=True` to the `LiveSource(...)` call:

Replace:

```python
LiveSource(
            args.interface,
            bpf_filter=args.bpf_filter,
            count=args.count,
            capture_idle_timeout=args.capture_idle_timeout,
        )
```

with:

```python
LiveSource(
            args.interface,
            bpf_filter=args.bpf_filter,
            count=args.count,
            capture_idle_timeout=args.capture_idle_timeout,
            tick=True,
        )
```

(The call may sit on one line in plan 1c's file; the change is the extra `tick=True` keyword.) `build_stages` has no other caller (plans 1c, 2 and 3 test through `main()`), so nothing else needs the new argument.

- [ ] **Step 7: Run the CLI and live tests to verify they pass**

Run: `uv run pytest tests/test_cli_flow.py tests/test_live.py -q`
Expected: all pass (`tests/test_cli_flow.py`: 12 tests; `tests/test_live.py`: plan 1c's tests plus the 3 new ones).

- [ ] **Step 8: Full suite and lint**

Run: `uv run pytest -q`
Expected: all tests pass (0 failed, 0 errors).

Existing CLI tests from plans 1c–3 filter output on `record_type == "packet"`, so the new `flow`/`message` lines in the main stream do not affect them.

Run: `uv run ruff check ids/flow ids/capture/live.py ids/cli.py tests/test_flow_stage.py tests/test_flow_pipeline.py tests/test_cli_flow.py tests/test_live.py && uv run ruff format --check ids/flow ids/capture/live.py ids/cli.py tests/test_flow_stage.py tests/test_flow_pipeline.py tests/test_cli_flow.py tests/test_live.py`
Expected: `All checks passed!` and `N files already formatted` (no file would be reformatted).

- [ ] **Step 9: Commit**

```bash
git add ids/flow/stage.py ids/flow/__init__.py ids/capture/live.py ids/cli.py tests/test_flow_stage.py tests/test_flow_pipeline.py tests/test_cli_flow.py tests/test_live.py
git commit -m "feat: add flow tracker stage, live ticks and cli flags"
```
