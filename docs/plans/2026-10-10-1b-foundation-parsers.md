# Foundation parsers (plan 1b) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rewrite every parser in `ids/parsers/` onto the typed model (`ids.model`) and the single error model (`ids.issues`), and add the application-protocol registry that the detector and the parsers share.

**Architecture:** Each layer parser returns a frozen `*Result` dataclass (`LinkResult`, `NetworkResult`, `TransportResult`) holding a typed info block plus the next layer's bytes; application parsers return `HttpMessage` / `DnsMessage` / `SmtpSession`. Fatal problems raise `ParseError(code, message, **context)` with no stage; non-fatal problems go to an `Issues` collector the caller passes in. Each application module owns its grammar, `NAME`, `PORTS` and `score()`; `registry.py` collects them and `detector.py` only combines scores.

**Tech Stack:** Python >= 3.10 stdlib (`dataclasses`, `re`, `struct`, `ipaddress`), pytest, ruff, uv.

**Spec:** `docs/specs/2026-10-10-decoder-preprocessor-flow-tracker.md` (§4, §5, §6.1, §6.2, §13 item 3) and the shared contract `docs/plans/2026-10-10-interfaces.md` (§1, §2, §3.1, §3.2, §6). Read both before starting.

## Global Constraints

- `requires-python >= 3.10`; no 3.11+ APIs (`tomllib`, `binascii` `strict_mode`, `datetime.UTC`, `typing.Self`).
- No new runtime dependency; stdlib only in `ids/parsers/`.
- Every module starts with `from __future__ import annotations`.
- Models are the contract's `@dataclass(slots=True)` classes from `ids.model`; never redefine or extend them here. Result wrappers are `@dataclass(frozen=True, slots=True)`.
- Parsers raise `ParseError(code, message, **context)` and never name a stage; non-fatal problems use `issues.add(code, message, **context)`.
- Issue codes used by this plan: `truncated_packet`, `malformed_header`, `unsupported_protocol`, `decode_error`, `truncated_body`, `incomplete_message`, `invalid_content_length`, `malformed_header_line`, `incomplete_reply`.
- HTTP parser keeps raw data only: no `parse_qs`/`urlsplit`, no form parsing, header names in original case and order, body as offset/length into the payload (spec §4, §6.2).
- `smtp.parse` never raises for non-empty input; no command/reply line → `kind = "data"` (contract §6).
- Lint: `uv run ruff check <paths> && uv run ruff format --check <paths>` (line length 100; rules E,F,W,I,UP,B,C4,SIM,RUF; ignored SIM108, SIM115, BLE001).
- Commit style: lower case conventional (`refactor: …`, `feat: …`), one task per commit.
- Green rule (contract §0): during plan 1b the legacy dict layer (`ids/pipeline.py`, `ids/event.py`, `ids/errors.py`, `ids/logger.py`, `ids/stats.py`, `ids/cli.py`, `tests/test_pipeline.py`, `tests/test_cli.py`) is left untouched and may fail. Each task runs only the parser test files it owns; every file a task owns is green at its commit.

## Review Focus

Inputs the spec implies but the migrated tests did not cover; each has a test in its owning task.

1. Ethernet frames padded to the 60-byte minimum (captured bytes > IPv4 total length): payload trimmed to `total_length` and **no** `truncated_packet` issue — Task 2, `test_ethernet_padding_is_trimmed_without_an_issue`.
2. LF-only HTTP messages (`\n\n` header terminator): headers parsed and `body.offset` points just past the blank line — Task 4, `test_lf_only_message_locates_the_body`.
3. HTTP header block longer than `MAX_HEADER_BYTES` with the terminator past the window: `complete = False`, one `incomplete_message` issue, empty body at the end of the payload, no exception — Task 4, `test_header_block_beyond_the_limit_is_incomplete`.
4. DNS answer with malformed rdata (an A record with 3 bytes): record kept with hex `rdata` and an `rdata_error` Issue, later records still parsed, message not rejected — Task 5, `test_bad_rdata_is_kept_on_the_record_and_parsing_continues`.
5. SMTP DATA-phase segment (MIME headers and body lines, no command or reply): `kind = "data"`, no issue, no exception — Task 6, `test_data_phase_content_is_kind_data`.

## Decisions this plan takes (contract gaps)

- `parse_transport` drops the legacy `more_fragments` keyword; the contract §6 signature has no such parameter, so its error context no longer carries it.
- `parse_ipv4` reports the IPv4 truncation itself: `issues.add("truncated_packet", "captured bytes are shorter than the IPv4 total length", declared=total_length, captured=len(data))`. Plan 1c's `PacketParser` must not add it a second time.
- `DnsRecord.rdata_error` is `Issue(issues.stage, code, message, context)` built from the caught `ParseError`; it is stored on the record only and **not** appended to `issues` (legacy behaviour: rdata errors never reached the event error list). With the pipeline's `Issues("application")` the stage is `"application"`.
- Application `parse()` functions take `tcp` and `issues` as required keyword arguments, exactly as contract §6; HTTP and SMTP ignore `tcp`.
- HTTP: `reason` is `""` when the status line has no reason phrase (legacy value); `body` is always present; when the header terminator is missing, `body.offset = len(payload)` and `body.length = 0`.
- HTTP `score()` builds its strict request-line regex from the same `METHODS` set the module defines; the parser keeps accepting any `[A-Z]{3,12}` method token (legacy behaviour), which the detector already scores 0.8.
- SMTP: one `COMMANDS` set drives both `parse()` and the 0.7 "SMTP verb" score tier, so `TURN`, `HELO`, `EHLO`, `MAIL`, `RCPT` without arguments now score 0.7 (they were 0.0). One `REPLY_LINE` regex (`^(\d{3})(?:([ -])(.*))?$`) serves both: `parse()` therefore also accepts a bare `250` line (RFC 5321 allows an empty text), which the detector already scored 0.85. Score keeps its 200–599 range, parse keeps 100–599.
- SMTP: an out-of-range numeric line (`999 nope`) now counts against `MAX_UNPARSED` like every other unparsed line (legacy appended it without the cap); `RCPT` without a path no longer appends `None` to `rcpt_to`.
- Dead code removed with the rewrite: `link.supported_linktypes()` and `network.MAX_OPTIONS` (no callers), `http.FORM_TYPES`, the legacy derived HTTP/SMTP summary keys (`header_order`, `header_count`, `host`, `cookie_count`, `command_count`, `status_text`, …) that are not fields of the contract models.
- `by_name()` matches the canonical upper-case name exactly (`"HTTP"`, `"DNS"`, `"SMTP"`).
- `tests/golden.py` needs no new constants; new fixtures are built inline in the tests that use them.
- `ids/parsers/checksum.py` is unchanged.

## File Structure

| File | Responsibility | Task |
|---|---|---|
| `ids/parsers/link.py` | Ethernet/VLAN/802.3 LLC-SNAP, NULL/LOOP, Linux SLL/SLL2, raw IP → `LinkResult` | 1 |
| `ids/parsers/network.py` | IPv4 header + options → `NetworkResult`; `IPPROTO_TCP`, `IPPROTO_UDP`; truncation issue | 2 |
| `ids/parsers/transport.py` | TCP (flags, options, checksum) and UDP → `TransportResult`; dispatch keyed by `IPPROTO_*` | 3 |
| `ids/parsers/http.py` | raw HTTP/1.x message → `HttpMessage`; `NAME`, `PORTS`, `score` | 4 |
| `ids/parsers/dns.py` | DNS over UDP/TCP → `DnsMessage`; `NAME`, `PORTS`, `score` | 5 |
| `ids/parsers/smtp.py` | SMTP commands/replies/DATA → `SmtpSession`; `NAME`, `PORTS`, `score` | 6 |
| `ids/parsers/registry.py` | `AppProtocol`, `PROTOCOLS`, `STANDARD_PORTS`, `by_name` | 7 |
| `ids/parsers/detector.py` | combines registry scores + port hints → `Detection` (Tasks 4–6 make transitional edits, Task 7 rewrites) | 4, 5, 6, 7 |
| `tests/test_link.py`, `tests/test_network.py`, `tests/test_transport.py`, `tests/test_http.py`, `tests/test_dns.py`, `tests/test_smtp.py`, `tests/test_detector.py`, `tests/test_registry.py` | unit tests (migrated + new) | 1–7 |

Paths are post-rename (plan 1a moved `pcparser/` to `ids/`). Plan 1a provides `ids/issues.py` and `ids/model/` exactly as contract §2/§3, keeps `ids/capture/base.py` with the `DLT_*` constants, and keeps the legacy `ids/errors.py` and `ids/payload.py` in place.

---

### Task 1: Link layer on the typed model

**Files:**
- Modify (full rewrite): `ids/parsers/link.py`
- Test (full rewrite): `tests/test_link.py`

**Interfaces:**
- Consumes: `ids.issues.ParseError(code, message, **context)`; `ids.model.LinkInfo`, `VlanTag`, `LlcHeader`, `SnapHeader` (contract §3.1); `ids.capture.base.DLT_EN10MB, DLT_RAW, DLT_RAW_BSD, DLT_NULL, DLT_LOOP, DLT_IPV4, DLT_IPV6, DLT_LINUX_SLL, DLT_LINUX_SLL2`.
- Produces:
  - `@dataclass(frozen=True, slots=True) class LinkResult: info: LinkInfo; payload: bytes; network_protocol: str | None`
  - `def parse_link(data: bytes, linktype: int) -> LinkResult` — raises `ParseError` with codes `truncated_packet` (context `declared`, `captured`; raw IP: `captured` only), `malformed_header` (`limit` for VLAN stacking, `version` for raw IP), `unsupported_protocol` (`linktype`).
  - constants `ETHERTYPES`, `ETHERTYPE_IPV4 = 0x0800`, `ETHERTYPE_IPV6 = 0x86DD`, `VLAN_TPIDS`, `MAX_VLAN_TAGS = 3`; helpers `mac_str(raw: bytes) -> str`, `ethertype_name(value: int) -> str`.
  - `network_protocol` values: `"IPv4"`, `"IPv6"`, `"ARP"`, other `ETHERTYPES` names, or `None`.

- [ ] **Step 1: Write the failing test**

Replace `tests/test_link.py` with:

```python
import pytest
from golden import ICMP, IPV6, SERVER_MAC, TCP_SYN_OPTIONS, UDP, VLAN

from ids.capture.base import (
    DLT_EN10MB,
    DLT_LINUX_SLL,
    DLT_LINUX_SLL2,
    DLT_LOOP,
    DLT_NULL,
    DLT_RAW,
)
from ids.issues import ParseError
from ids.model import LlcHeader, SnapHeader, VlanTag
from ids.parsers.link import MAX_VLAN_TAGS, LinkResult, parse_link

MACS = bytes.fromhex("020000000002020000000001")
IPV4_PACKET = UDP[14:]


def stacked(tags: list[tuple[int, int]], ethertype: int, payload: bytes) -> bytes:
    header = b"".join(tpid.to_bytes(2, "big") + tci.to_bytes(2, "big") for tpid, tci in tags)
    return MACS + header + ethertype.to_bytes(2, "big") + payload


def test_ethernet_fields_and_payload():
    result = parse_link(TCP_SYN_OPTIONS, DLT_EN10MB)
    assert isinstance(result, LinkResult)
    assert result.info.protocol == "Ethernet"
    assert result.info.src_mac == "02:00:00:00:00:01"
    assert result.info.dst_mac == SERVER_MAC
    assert result.info.ethertype == 0x0800
    assert result.info.ethertype_name == "IPv4"
    assert result.info.vlan == []
    assert result.network_protocol == "IPv4"
    assert result.payload[0] == 0x45


def test_vlan_tag_is_reported():
    result = parse_link(VLAN, DLT_EN10MB)
    assert result.info.vlan == [VlanTag(tpid="0x8100", pcp=5, dei=False, vid=42)]
    assert result.network_protocol == "IPv4"
    assert result.payload[0] == 0x45


def test_three_stacked_vlan_tags_are_accepted():
    frame = stacked([(0x88A8, 1), (0x8100, 2), (0x9100, 0x1003)], 0x0800, IPV4_PACKET)
    result = parse_link(frame, DLT_EN10MB)
    assert [tag.tpid for tag in result.info.vlan] == ["0x88a8", "0x8100", "0x9100"]
    assert [tag.vid for tag in result.info.vlan] == [1, 2, 3]
    assert result.info.vlan[2].dei is True
    assert result.network_protocol == "IPv4"
    assert result.payload == IPV4_PACKET


def test_more_than_max_vlan_tags_is_malformed():
    tags = [(0x8100, vid) for vid in range(MAX_VLAN_TAGS + 1)]
    with pytest.raises(ParseError) as caught:
        parse_link(stacked(tags, 0x0800, IPV4_PACKET), DLT_EN10MB)
    assert caught.value.code == "malformed_header"
    assert caught.value.context == {"limit": 3}


def test_truncated_vlan_tag_reports_declared_and_captured():
    with pytest.raises(ParseError) as caught:
        parse_link(MACS + b"\x81\x00\x00", DLT_EN10MB)
    assert caught.value.code == "truncated_packet"
    assert caught.value.context == {"declared": 18, "captured": 15}


def test_icmp_frame_resolves_to_ipv4():
    result = parse_link(ICMP, DLT_EN10MB)
    assert result.network_protocol == "IPv4"
    assert len(result.payload) == 28
    assert result.payload[9] == 1


def test_unknown_ethertype_is_not_an_error():
    result = parse_link(MACS + bytes.fromhex("1234") + b"noise", DLT_EN10MB)
    assert result.network_protocol is None
    assert result.info.ethertype == 0x1234
    assert result.info.ethertype_name == "0x1234"


def test_arp_ethertype_is_reported():
    result = parse_link(MACS + bytes.fromhex("0806") + b"\x00" * 28, DLT_EN10MB)
    assert result.network_protocol == "ARP"


def test_8023_snap_frame_carries_ipv4():
    llc_snap = bytes.fromhex("aaaa03") + bytes.fromhex("000000") + bytes.fromhex("0800")
    frame = MACS + (len(llc_snap) + len(IPV4_PACKET)).to_bytes(2, "big") + llc_snap + IPV4_PACKET
    result = parse_link(frame, DLT_EN10MB)
    assert result.info.length_field == len(llc_snap) + len(IPV4_PACKET)
    assert result.info.llc == LlcHeader(dsap="0xaa", ssap="0xaa", control=3)
    assert result.info.snap == SnapHeader(oui="000000", protocol=0x0800)
    assert result.info.ethertype == 0x0800
    assert result.network_protocol == "IPv4"
    assert result.payload == IPV4_PACKET


def test_8023_llc_without_snap_has_no_network_protocol():
    frame = MACS + (38).to_bytes(2, "big") + bytes.fromhex("424203") + b"\x00" * 35
    result = parse_link(frame, DLT_EN10MB)
    assert result.info.llc == LlcHeader(dsap="0x42", ssap="0x42", control=3)
    assert result.info.snap is None
    assert result.info.ethertype == 0
    assert result.info.ethertype_name == "0x0000"
    assert result.network_protocol is None


def test_snap_with_vendor_oui_is_not_resolved():
    llc_snap = bytes.fromhex("aaaa03") + bytes.fromhex("00000c") + bytes.fromhex("2000")
    frame = MACS + (40).to_bytes(2, "big") + llc_snap + b"\x00" * 32
    result = parse_link(frame, DLT_EN10MB)
    assert result.info.snap == SnapHeader(oui="00000c", protocol=0x2000)
    assert result.info.ethertype == 0
    assert result.network_protocol is None


def test_truncated_snap_header_is_reported():
    with pytest.raises(ParseError) as caught:
        parse_link(MACS + (8).to_bytes(2, "big") + bytes.fromhex("aaaa0300"), DLT_EN10MB)
    assert caught.value.code == "truncated_packet"
    assert caught.value.context == {"declared": 22, "captured": 18}


def test_truncated_ethernet_reports_declared_and_captured():
    with pytest.raises(ParseError) as caught:
        parse_link(b"\x02\x00\x00\x00\x00\x02", DLT_EN10MB)
    assert caught.value.code == "truncated_packet"
    assert caught.value.context == {"declared": 14, "captured": 6}


def test_unsupported_linktype_is_rejected():
    with pytest.raises(ParseError) as caught:
        parse_link(b"\x00" * 64, 999)
    assert caught.value.code == "unsupported_protocol"
    assert caught.value.context == {"linktype": 999}


def test_linux_cooked_v1():
    header = bytes.fromhex("000100010006") + bytes.fromhex("020000000001") + bytes.fromhex("0000")
    header += bytes.fromhex("0800")
    result = parse_link(header + IPV4_PACKET, DLT_LINUX_SLL)
    assert result.info.protocol == "LINUX_SLL"
    assert result.info.packet_type == 1
    assert result.info.address_type == 1
    assert result.info.address == "02:00:00:00:00:01"
    assert result.network_protocol == "IPv4"
    assert result.payload == IPV4_PACKET


def test_linux_cooked_v2():
    header = bytes.fromhex("0800") + bytes.fromhex("0000") + bytes.fromhex("00000005")
    header += bytes.fromhex("0001") + bytes.fromhex("00") + bytes.fromhex("06")
    header += bytes.fromhex("020000000001") + bytes.fromhex("0000")
    result = parse_link(header + IPV4_PACKET, DLT_LINUX_SLL2)
    assert result.info.protocol == "LINUX_SLL2"
    assert result.info.interface_index == 5
    assert result.info.address == "02:00:00:00:00:01"
    assert result.network_protocol == "IPv4"
    assert result.payload == IPV4_PACKET


@pytest.mark.parametrize("family,expected", [(2, "IPv4"), (10, "IPv6")])
def test_null_header_family(family, expected):
    result = parse_link(family.to_bytes(4, "little") + IPV4_PACKET, DLT_NULL)
    assert result.info.protocol == "NULL"
    assert result.info.address_family == family
    assert result.network_protocol == expected


def test_loop_header_is_big_endian():
    result = parse_link((2).to_bytes(4, "big") + IPV4_PACKET, DLT_LOOP)
    assert result.info.protocol == "LOOP"
    assert result.network_protocol == "IPv4"


def test_null_header_unknown_family_is_named_not_resolved():
    result = parse_link((99).to_bytes(4, "little") + IPV4_PACKET, DLT_NULL)
    assert result.info.ethertype is None
    assert result.info.ethertype_name == "AF_99"
    assert result.network_protocol is None


def test_raw_link_sniffs_ip_version():
    assert parse_link(IPV4_PACKET, DLT_RAW).network_protocol == "IPv4"
    assert parse_link(ICMP[14:], DLT_RAW).network_protocol == "IPv4"
    assert parse_link(IPV6[14:], DLT_RAW).network_protocol == "IPv6"


def test_raw_link_rejects_garbage():
    with pytest.raises(ParseError) as caught:
        parse_link(b"\x00\x01\x02\x03", DLT_RAW)
    assert caught.value.code == "malformed_header"
    assert caught.value.context == {"version": 0}


def test_empty_raw_link_is_truncated():
    with pytest.raises(ParseError) as caught:
        parse_link(b"", DLT_RAW)
    assert caught.value.code == "truncated_packet"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_link.py -q`
Expected: collection error `ImportError: cannot import name 'LinkResult' from 'ids.parsers.link'`.

- [ ] **Step 3: Write the implementation**

Replace `ids/parsers/link.py` with:

```python
from __future__ import annotations

from dataclasses import dataclass

from ..capture.base import (
    DLT_EN10MB,
    DLT_IPV4,
    DLT_IPV6,
    DLT_LINUX_SLL,
    DLT_LINUX_SLL2,
    DLT_LOOP,
    DLT_NULL,
    DLT_RAW,
    DLT_RAW_BSD,
)
from ..issues import ParseError
from ..model import LinkInfo, LlcHeader, SnapHeader, VlanTag

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD

ETHERTYPES = {
    ETHERTYPE_IPV4: "IPv4",
    0x0806: "ARP",
    ETHERTYPE_IPV6: "IPv6",
    0x8100: "VLAN",
    0x8847: "MPLS",
    0x8848: "MPLS-MC",
    0x8863: "PPPoE-Discovery",
    0x8864: "PPPoE-Session",
    0x88A8: "QinQ",
    0x88CC: "LLDP",
    0x9100: "QinQ",
}

VLAN_TPIDS = frozenset((0x8100, 0x88A8, 0x9100))
MAX_VLAN_TAGS = 3
MAX_8023_LENGTH = 1500

_AF_INET = frozenset((2,))
_AF_INET6 = frozenset((10, 23, 24, 28, 30))


@dataclass(frozen=True, slots=True)
class LinkResult:
    info: LinkInfo
    payload: bytes
    network_protocol: str | None


def mac_str(raw: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in raw)


def ethertype_name(value: int) -> str:
    return ETHERTYPES.get(value, f"0x{value:04x}")


def _truncated(message: str, declared: int, captured: int) -> ParseError:
    return ParseError("truncated_packet", message, declared=declared, captured=captured)


def _llc(info: LinkInfo, data: bytes, offset: int) -> tuple[int, int]:
    if len(data) < offset + 3:
        raise _truncated("802.3 LLC header truncated", offset + 3, len(data))
    dsap, ssap = data[offset], data[offset + 1]
    info.llc = LlcHeader(dsap=f"0x{dsap:02x}", ssap=f"0x{ssap:02x}", control=data[offset + 2])
    offset += 3
    if dsap != 0xAA or ssap != 0xAA:
        return 0, offset
    if len(data) < offset + 5:
        raise _truncated("SNAP header truncated", offset + 5, len(data))
    oui = data[offset : offset + 3]
    protocol = int.from_bytes(data[offset + 3 : offset + 5], "big")
    info.snap = SnapHeader(oui=oui.hex(), protocol=protocol)
    return (protocol if oui == b"\x00\x00\x00" else 0), offset + 5


def _ethernet(data: bytes) -> LinkResult:
    if len(data) < 14:
        raise _truncated("ethernet frame shorter than 14 bytes", 14, len(data))
    info = LinkInfo(protocol="Ethernet", dst_mac=mac_str(data[0:6]), src_mac=mac_str(data[6:12]))
    ethertype = int.from_bytes(data[12:14], "big")
    offset = 14
    while ethertype in VLAN_TPIDS:
        if len(info.vlan) >= MAX_VLAN_TAGS:
            raise ParseError(
                "malformed_header",
                f"more than {MAX_VLAN_TAGS} stacked VLAN tags",
                limit=MAX_VLAN_TAGS,
            )
        if len(data) < offset + 4:
            raise _truncated("VLAN tag truncated", offset + 4, len(data))
        tci = int.from_bytes(data[offset : offset + 2], "big")
        info.vlan.append(
            VlanTag(
                tpid=f"0x{ethertype:04x}",
                pcp=(tci >> 13) & 0x07,
                dei=bool(tci & 0x1000),
                vid=tci & 0x0FFF,
            )
        )
        ethertype = int.from_bytes(data[offset + 2 : offset + 4], "big")
        offset += 4
    if ethertype <= MAX_8023_LENGTH:
        info.length_field = ethertype
        ethertype, offset = _llc(info, data, offset)
    info.ethertype = ethertype
    info.ethertype_name = ethertype_name(ethertype)
    return LinkResult(info, data[offset:], ETHERTYPES.get(ethertype))


def _null(data: bytes, big_endian: bool, protocol: str) -> LinkResult:
    if len(data) < 4:
        raise _truncated(f"{protocol} header truncated", 4, len(data))
    family = int.from_bytes(data[0:4], "big" if big_endian else "little")
    info = LinkInfo(protocol=protocol, address_family=family)
    if family in _AF_INET:
        info.ethertype, info.ethertype_name = ETHERTYPE_IPV4, "IPv4"
        return LinkResult(info, data[4:], "IPv4")
    if family in _AF_INET6:
        info.ethertype, info.ethertype_name = ETHERTYPE_IPV6, "IPv6"
        return LinkResult(info, data[4:], "IPv6")
    info.ethertype_name = f"AF_{family}"
    return LinkResult(info, data[4:], None)


def _sll(data: bytes) -> LinkResult:
    if len(data) < 16:
        raise _truncated("linux cooked header truncated", 16, len(data))
    addr_len = int.from_bytes(data[4:6], "big")
    ethertype = int.from_bytes(data[14:16], "big")
    info = LinkInfo(
        protocol="LINUX_SLL",
        packet_type=int.from_bytes(data[0:2], "big"),
        address_type=int.from_bytes(data[2:4], "big"),
        address=mac_str(data[6 : 6 + min(addr_len, 8)]),
        ethertype=ethertype,
        ethertype_name=ethertype_name(ethertype),
    )
    return LinkResult(info, data[16:], ETHERTYPES.get(ethertype))


def _sll2(data: bytes) -> LinkResult:
    if len(data) < 20:
        raise _truncated("linux cooked v2 header truncated", 20, len(data))
    ethertype = int.from_bytes(data[0:2], "big")
    info = LinkInfo(
        protocol="LINUX_SLL2",
        ethertype=ethertype,
        ethertype_name=ethertype_name(ethertype),
        interface_index=int.from_bytes(data[4:8], "big"),
        address_type=int.from_bytes(data[8:10], "big"),
        packet_type=data[10],
        address=mac_str(data[12 : 12 + min(data[11], 8)]),
    )
    return LinkResult(info, data[20:], ETHERTYPES.get(ethertype))


def _ip_only(protocol: str, data: bytes, version: int) -> LinkResult:
    if version == 4:
        info = LinkInfo(protocol=protocol, ethertype=ETHERTYPE_IPV4, ethertype_name="IPv4")
        return LinkResult(info, data, "IPv4")
    info = LinkInfo(protocol=protocol, ethertype=ETHERTYPE_IPV6, ethertype_name="IPv6")
    return LinkResult(info, data, "IPv6")


def _raw_ip(data: bytes) -> LinkResult:
    if not data:
        raise ParseError("truncated_packet", "empty raw IP payload", captured=0)
    version = data[0] >> 4
    if version not in (4, 6):
        raise ParseError(
            "malformed_header",
            f"raw link payload starts with IP version {version}",
            version=version,
        )
    return _ip_only("RAW", data, version)


def parse_link(data: bytes, linktype: int) -> LinkResult:
    if linktype == DLT_EN10MB:
        return _ethernet(data)
    if linktype in (DLT_RAW, DLT_RAW_BSD):
        return _raw_ip(data)
    if linktype == DLT_NULL:
        return _null(data, False, "NULL")
    if linktype == DLT_LOOP:
        return _null(data, True, "LOOP")
    if linktype == DLT_IPV4:
        return _ip_only("IPV4", data, 4)
    if linktype == DLT_IPV6:
        return _ip_only("IPV6", data, 6)
    if linktype == DLT_LINUX_SLL:
        return _sll(data)
    if linktype == DLT_LINUX_SLL2:
        return _sll2(data)
    raise ParseError("unsupported_protocol", "link layer type is not supported", linktype=linktype)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_link.py -q`
Expected: `23 passed`.

- [ ] **Step 5: Lint**

Run: `uv run ruff check ids/parsers/link.py tests/test_link.py && uv run ruff format --check ids/parsers/link.py tests/test_link.py`
Expected: `All checks passed!` then `2 files already formatted`.

- [ ] **Step 6: Commit**

```bash
git add ids/parsers/link.py tests/test_link.py
git commit -m "refactor: move the link parser onto the typed model"
```

---

### Task 2: IPv4 layer on the typed model, truncation reported by the parser

**Files:**
- Modify (full rewrite): `ids/parsers/network.py`
- Test (full rewrite): `tests/test_network.py`
- Modify: `tests/test_transport.py` (its two `parse_ipv4` call sites adopt the new signature; the transport assertions stay legacy until Task 3)

**Interfaces:**
- Consumes: `ids.issues.Issues`, `ParseError`; `ids.model.Ipv4Info`, `Ipv4Flags`, `IpOption`; `ids.parsers.checksum.internet_checksum(data: bytes) -> int`.
- Produces:
  - `IPPROTO_TCP = 6`, `IPPROTO_UDP = 17`
  - `@dataclass(frozen=True, slots=True) class NetworkResult: info: Ipv4Info; payload: bytes`
  - `def parse_ipv4(data: bytes, issues: Issues) -> NetworkResult` — raises `ParseError` (`truncated_packet` / `unsupported_protocol` with `version` / `malformed_header` with `ihl` or `total_length`+`header_length`); when `total_length > len(data)` sets `info.captured_truncated = True`, keeps all captured bytes after the header as payload and calls `issues.add("truncated_packet", "captured bytes are shorter than the IPv4 total length", declared=total_length, captured=len(data))`.
  - `def parse_options(raw: bytes) -> list[IpOption]` — `EOL`, `NOP`, named options with hex `data`, `TRUNCATED` (no length byte), `malformed=True` with `declared_length`/`available`, and `IpOption(type=0, name="PADDING", length=n)` for non-zero bytes after EOL.
  - `def protocol_name(number: int) -> str`, `def option_name(kind: int) -> str`, `IP_PROTOCOLS`, `IP_OPTION_NAMES`.

- [ ] **Step 1: Write the failing tests**

Replace `tests/test_network.py` with:

```python
import pytest
from golden import DST, ICMP, IPV4_MF, IPV4_OPTIONS, IPV6, SRC, TCP_DATA, TCP_SYN_OPTIONS, UDP

from ids.issues import Issue, Issues, ParseError
from ids.model import IpOption, Ipv4Flags
from ids.parsers.checksum import internet_checksum
from ids.parsers.network import NetworkResult, parse_ipv4, parse_options


def ipv4_bytes(frame):
    return frame[14:]


def parse(data, issues=None):
    return parse_ipv4(data, issues if issues is not None else Issues("network"))


def with_options(options: bytes) -> bytes:
    """IPv4 header (no payload) carrying `options`, with a valid header checksum."""
    ihl = 5 + len(options) // 4
    header = bytearray(ipv4_bytes(TCP_SYN_OPTIONS)[:20] + options)
    header[0] = 0x40 | ihl
    header[2:4] = (ihl * 4).to_bytes(2, "big")
    header[10:12] = b"\x00\x00"
    header[10:12] = internet_checksum(bytes(header)).to_bytes(2, "big")
    return bytes(header)


def test_header_fields():
    issues = Issues("network")
    result = parse(ipv4_bytes(TCP_SYN_OPTIONS), issues)
    assert isinstance(result, NetworkResult)
    info = result.info
    assert info.protocol == "IPv4"
    assert info.version == 4
    assert info.header_length == 20
    assert info.src_ip == SRC
    assert info.dst_ip == DST
    assert info.ttl == 64
    assert info.identification == 4242
    assert info.dscp == 0
    assert info.ecn == 0
    assert info.protocol_number == 6
    assert info.protocol_name == "TCP"
    assert info.total_length == 64
    assert info.declared_payload_length == 44
    assert info.captured_payload_length == 44
    assert info.captured_truncated is False
    assert info.options == []
    assert issues.records == []


def test_good_checksum_is_accepted():
    assert parse(ipv4_bytes(TCP_SYN_OPTIONS)).info.header_checksum_valid is True
    assert parse(ipv4_bytes(UDP)).info.header_checksum_valid is True


def test_corrupted_checksum_is_detected():
    raw = bytearray(ipv4_bytes(TCP_DATA))
    raw[10] ^= 0xFF
    assert parse(bytes(raw)).info.header_checksum_valid is False


def test_options_are_decoded_and_header_length_grows():
    result = parse(ipv4_bytes(IPV4_OPTIONS))
    assert result.info.header_length == 28
    assert [option.name for option in result.info.options] == ["NOP", "RR"]
    assert result.info.options[1] == IpOption(type=7, name="RR", length=7, data="0409090909")
    assert result.info.header_checksum_valid is True
    assert len(result.payload) == 20


def test_eol_with_zero_padding_adds_no_padding_entry():
    options = parse(with_options(bytes.fromhex("01000000"))).info.options
    assert options == [IpOption(type=1, name="NOP"), IpOption(type=0, name="EOL")]


def test_non_zero_bytes_after_eol_become_a_padding_entry():
    options = parse_options(bytes.fromhex("0100ab00"))
    assert options == [
        IpOption(type=1, name="NOP"),
        IpOption(type=0, name="EOL"),
        IpOption(type=0, name="PADDING", length=2),
    ]


def test_option_length_past_the_header_is_malformed():
    assert parse_options(bytes.fromhex("070a0400")) == [
        IpOption(type=7, name="RR", malformed=True, declared_length=10, available=4)
    ]


def test_option_without_a_length_byte_is_truncated():
    assert parse_options(bytes.fromhex("01010182")) == [
        IpOption(type=1, name="NOP"),
        IpOption(type=1, name="NOP"),
        IpOption(type=1, name="NOP"),
        IpOption(type=130, name="TRUNCATED"),
    ]


def test_unknown_option_type_is_named():
    assert parse_options(bytes.fromhex("63030a00")) == [
        IpOption(type=99, name="UNKNOWN(99)", length=3, data="0a"),
        IpOption(type=0, name="EOL"),
    ]


def test_more_fragments_sets_fragmented_flag():
    info = parse(ipv4_bytes(IPV4_MF)).info
    assert info.flags == Ipv4Flags(reserved=False, df=False, mf=True)
    assert info.fragment_offset == 0
    assert info.fragmented is True


def test_ethernet_padding_is_trimmed_without_an_issue():
    issues = Issues("network")
    result = parse(ipv4_bytes(TCP_DATA) + b"\x00" * 10, issues)
    assert result.info.total_length == 58
    assert len(result.payload) == 38
    assert result.info.captured_truncated is False
    assert issues.records == []


def test_short_capture_is_flagged_and_reported():
    issues = Issues("network")
    result = parse(ipv4_bytes(TCP_DATA)[:40], issues)
    assert result.info.captured_truncated is True
    assert result.info.declared_payload_length == 38
    assert result.info.captured_payload_length == 20
    assert result.payload == ipv4_bytes(TCP_DATA)[20:40]
    assert issues.records == [
        Issue(
            "network",
            "truncated_packet",
            "captured bytes are shorter than the IPv4 total length",
            {"declared": 58, "captured": 40},
        )
    ]


def test_ipv6_is_unsupported():
    with pytest.raises(ParseError) as caught:
        parse(ipv4_bytes(IPV6))
    assert caught.value.code == "unsupported_protocol"
    assert caught.value.context == {"version": 6}


def test_other_ip_versions_are_unsupported():
    with pytest.raises(ParseError) as caught:
        parse(b"\x50" + b"\x00" * 19)
    assert caught.value.code == "unsupported_protocol"
    assert caught.value.context == {"version": 5}


def test_icmp_is_parsed_as_a_network_payload():
    info = parse(ipv4_bytes(ICMP)).info
    assert info.protocol_number == 1
    assert info.protocol_name == "ICMP"


def test_unknown_protocol_number_is_named():
    raw = bytearray(ipv4_bytes(ICMP))
    raw[9] = 200
    assert parse(bytes(raw)).info.protocol_name == "UNKNOWN(200)"


def test_empty_and_short_input():
    with pytest.raises(ParseError) as caught:
        parse(b"")
    assert caught.value.code == "truncated_packet"
    assert caught.value.context == {"captured": 0}
    with pytest.raises(ParseError) as caught:
        parse(ipv4_bytes(TCP_SYN_OPTIONS)[:12])
    assert caught.value.code == "truncated_packet"
    assert caught.value.context == {"declared": 20, "captured": 12}


def test_invalid_ihl_is_malformed():
    raw = bytearray(ipv4_bytes(TCP_SYN_OPTIONS))
    raw[0] = 0x40
    with pytest.raises(ParseError) as caught:
        parse(bytes(raw))
    assert caught.value.code == "malformed_header"
    assert caught.value.context == {"ihl": 0}


def test_total_length_below_header_length_is_malformed():
    raw = bytearray(ipv4_bytes(TCP_SYN_OPTIONS))
    raw[2:4] = (10).to_bytes(2, "big")
    with pytest.raises(ParseError) as caught:
        parse(bytes(raw))
    assert caught.value.code == "malformed_header"
    assert caught.value.context == {"total_length": 10, "header_length": 20}


def test_truncated_options_are_reported():
    raw = bytearray(ipv4_bytes(IPV4_OPTIONS))
    raw[0] = 0x48
    with pytest.raises(ParseError) as caught:
        parse(bytes(raw)[:24])
    assert caught.value.code == "truncated_packet"
    assert caught.value.context == {"declared": 32, "captured": 24}
```

Replace `tests/test_transport.py` with this transitional version (only the imports and the two network calls change; Task 3 rewrites the file):

```python
import pytest
from golden import TCP_DATA, TCP_FIN, TCP_SYN_OPTIONS, UDP

from ids.errors import MalformedHeaderError, TruncatedPacketError, UnsupportedProtocolError
from ids.issues import Issues
from ids.parsers.link import parse_link
from ids.parsers.network import parse_ipv4
from ids.parsers.transport import parse_transport


def transport(frame, **overrides):
    link = parse_link(frame, 1)
    net = parse_ipv4(link.payload, Issues("network"))
    kwargs = {
        "src_ip": net.info.src_ip,
        "dst_ip": net.info.dst_ip,
        "declared_length": net.info.declared_payload_length,
    }
    kwargs.update(overrides)
    return parse_transport(net.info.protocol_number, net.payload, **kwargs)


def test_syn_with_options():
    result = transport(TCP_SYN_OPTIONS)
    info = result.info
    assert info["protocol"] == "TCP"
    assert info["src_port"] == 51234
    assert info["dst_port"] == 80
    assert info["seq"] == 1000
    assert info["ack"] == 0
    assert info["flags"] == {
        "fin": False,
        "syn": True,
        "rst": False,
        "psh": False,
        "ack": False,
        "urg": False,
        "ece": False,
        "cwr": False,
        "ns": False,
    }
    assert info["flags_string"] == "S"
    assert info["flags_list"] == ["SYN"]
    assert info["header_length"] == 44
    assert info["window"] == 8192
    assert info["checksum_valid"] is True
    assert info["payload_length"] == 0
    assert result.payload == b""

    names = [option["name"] for option in info["options"]]
    assert names == ["MSS", "SACK-Permitted", "WScale", "NOP", "NOP", "Timestamps", "EOL"]
    assert info["options"][0]["mss"] == 1460
    assert info["options"][2]["shift"] == 7
    assert info["options"][5]["tsval"] == 111


def test_psh_ack_carries_the_payload():
    result = transport(TCP_DATA)
    assert result.info["flags_string"] == "PA"
    assert result.info["header_length"] == 20
    assert result.info["payload_length"] == 18
    assert result.payload == b"GET / HTTP/1.1\r\n\r\n"
    assert result.info["checksum_valid"] is True


def test_fin_psh_ack_flag_string():
    assert transport(TCP_FIN).info["flags_string"] == "FPA"


def test_udp_fields():
    result = transport(UDP)
    info = result.info
    assert info["protocol"] == "UDP"
    assert info["src_port"] == 40000
    assert info["dst_port"] == 53
    assert info["length"] == 17
    assert info["declared_payload_length"] == 9
    assert info["payload_length"] == 9
    assert info["checksum_valid"] is True
    assert result.payload == b"payload01"


def test_udp_zero_checksum_means_not_computed():
    raw = bytearray(UDP[14:][20:])
    raw[6:8] = b"\x00\x00"
    info = parse_transport(
        17, bytes(raw), src_ip="10.0.0.1", dst_ip="10.0.0.2", declared_length=len(raw)
    ).info
    assert info["checksum"] == "0x0000"
    assert info["checksum_valid"] is None


def test_checksum_is_not_verified_when_the_capture_is_short():
    link = parse_link(UDP, 1)
    net = parse_ipv4(link.payload, Issues("network"))
    info = parse_transport(
        17, net.payload[:12], src_ip="10.0.0.1", dst_ip="10.0.0.2", declared_length=17
    ).info
    assert info["checksum_valid"] is None


def test_corrupted_tcp_checksum_is_detected():
    segment = bytearray(TCP_DATA[14:][20:])
    segment[16] ^= 0xFF
    info = parse_transport(
        6, bytes(segment), src_ip="10.0.0.1", dst_ip="10.0.0.2", declared_length=len(segment)
    ).info
    assert info["checksum_valid"] is False


def test_tcp_data_offset_below_five_is_malformed():
    raw = bytearray(TCP_DATA[14:][20:])
    raw[12:14] = (0x4018).to_bytes(2, "big")
    with pytest.raises(MalformedHeaderError):
        parse_transport(6, bytes(raw), src_ip="10.0.0.1", dst_ip="10.0.0.2")


def test_tcp_header_shorter_than_twenty_bytes():
    with pytest.raises(TruncatedPacketError):
        parse_transport(6, b"\x00" * 10, src_ip="10.0.0.1", dst_ip="10.0.0.2")


def test_udp_length_below_eight_is_malformed():
    header = (
        bytes.fromhex("9c40")
        + bytes.fromhex("9c40")
        + bytes.fromhex("0004")
        + bytes.fromhex("0000")
    )
    with pytest.raises(MalformedHeaderError):
        parse_transport(17, header, src_ip="10.0.0.1", dst_ip="10.0.0.2")


def test_udp_declared_length_longer_than_capture_is_flagged():
    header = (
        bytes.fromhex("9c40")
        + bytes.fromhex("9c40")
        + bytes.fromhex("0064")
        + bytes.fromhex("0000")
    )
    info = parse_transport(17, header + b"only12bytes!", src_ip="10.0.0.1", dst_ip="10.0.0.2").info
    assert info["captured_truncated"] is True
    assert info["declared_payload_length"] == 92
    assert info["payload_length"] == 12


def test_non_first_fragment_has_no_transport_header():
    with pytest.raises(UnsupportedProtocolError):
        parse_transport(6, b"\x00" * 20, src_ip="10.0.0.1", dst_ip="10.0.0.2", fragment_offset=8)


def test_other_ip_protocols_are_unsupported():
    with pytest.raises(UnsupportedProtocolError) as caught:
        parse_transport(1, b"\x08\x00" + b"\x00" * 6, src_ip="10.0.0.1", dst_ip="10.0.0.2")
    assert caught.value.context["protocol_number"] == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_network.py tests/test_transport.py -q`
Expected: collection error `ImportError: cannot import name 'NetworkResult' from 'ids.parsers.network'`.

- [ ] **Step 3: Write the implementation**

Replace `ids/parsers/network.py` with:

```python
from __future__ import annotations

import struct
from dataclasses import dataclass
from ipaddress import IPv4Address

from ..issues import Issues, ParseError
from ..model import IpOption, Ipv4Flags, Ipv4Info
from .checksum import internet_checksum

IPV4_MIN_HEADER = 20
IPV4_MAX_HEADER = 60

IPPROTO_TCP = 6
IPPROTO_UDP = 17

IP_PROTOCOLS = {
    1: "ICMP",
    2: "IGMP",
    IPPROTO_TCP: "TCP",
    IPPROTO_UDP: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
    103: "PIM",
    112: "VRRP",
    132: "SCTP",
}

IP_OPTION_NAMES = {
    0: "EOL",
    1: "NOP",
    7: "RR",
    25: "QS",
    30: "EXP",
    68: "TS",
    94: "ADDRESS-EXT",
    130: "SEC",
    131: "LSR",
    136: "SID",
    137: "SSR",
    148: "RTRALT",
}

FLAG_RESERVED = 0x8000
FLAG_DF = 0x4000
FLAG_MF = 0x2000


@dataclass(frozen=True, slots=True)
class NetworkResult:
    info: Ipv4Info
    payload: bytes


def protocol_name(number: int) -> str:
    return IP_PROTOCOLS.get(number, f"UNKNOWN({number})")


def option_name(kind: int) -> str:
    return IP_OPTION_NAMES.get(kind, f"UNKNOWN({kind})")


def parse_options(raw: bytes) -> list[IpOption]:
    options: list[IpOption] = []
    offset = 0
    while offset < len(raw):
        kind = raw[offset]
        if kind == 0:
            options.append(IpOption(type=0, name="EOL"))
            remaining = raw[offset + 1 :]
            if any(remaining):
                options.append(IpOption(type=0, name="PADDING", length=len(remaining)))
            break
        if kind == 1:
            options.append(IpOption(type=1, name="NOP"))
            offset += 1
            continue
        if offset + 2 > len(raw):
            options.append(IpOption(type=kind, name="TRUNCATED"))
            break
        length = raw[offset + 1]
        if length < 2 or offset + length > len(raw):
            options.append(
                IpOption(
                    type=kind,
                    name=option_name(kind),
                    malformed=True,
                    declared_length=length,
                    available=len(raw) - offset,
                )
            )
            break
        options.append(
            IpOption(
                type=kind,
                name=option_name(kind),
                length=length,
                data=raw[offset + 2 : offset + length].hex(),
            )
        )
        offset += length
    return options


def parse_ipv4(data: bytes, issues: Issues) -> NetworkResult:
    if not data:
        raise ParseError("truncated_packet", "empty network layer payload", captured=0)

    version = data[0] >> 4
    if version == 6:
        raise ParseError("unsupported_protocol", "IPv6 is not supported", version=6)
    if version != 4:
        raise ParseError(
            "unsupported_protocol", f"unsupported IP version {version}", version=version
        )
    if len(data) < IPV4_MIN_HEADER:
        raise ParseError(
            "truncated_packet",
            "IPv4 header shorter than 20 bytes",
            declared=IPV4_MIN_HEADER,
            captured=len(data),
        )

    ihl = data[0] & 0x0F
    if ihl < 5:
        raise ParseError("malformed_header", f"IPv4 IHL {ihl} is below the minimum of 5", ihl=ihl)
    header_length = ihl * 4
    if header_length > IPV4_MAX_HEADER:
        raise ParseError(
            "malformed_header", f"IPv4 header length {header_length} exceeds 60 bytes", ihl=ihl
        )
    if len(data) < header_length:
        raise ParseError(
            "truncated_packet",
            "IPv4 header options truncated",
            declared=header_length,
            captured=len(data),
        )

    total_length, identification, flags_fragment, ttl, protocol, checksum, src_raw, dst_raw = (
        struct.unpack_from("!HHHBBH4s4s", data, 2)
    )
    if total_length < header_length:
        raise ParseError(
            "malformed_header",
            f"IPv4 total length {total_length} is smaller than its header length {header_length}",
            total_length=total_length,
            header_length=header_length,
        )

    truncated = total_length > len(data)
    if truncated:
        issues.add(
            "truncated_packet",
            "captured bytes are shorter than the IPv4 total length",
            declared=total_length,
            captured=len(data),
        )
    payload = data[header_length:] if truncated else data[header_length:total_length]
    fragment_offset = flags_fragment & 0x1FFF
    more_fragments = bool(flags_fragment & FLAG_MF)
    info = Ipv4Info(
        protocol="IPv4",
        version=4,
        header_length=header_length,
        dscp=data[1] >> 2,
        ecn=data[1] & 0x03,
        tos=data[1],
        total_length=total_length,
        identification=identification,
        flags=Ipv4Flags(
            reserved=bool(flags_fragment & FLAG_RESERVED),
            df=bool(flags_fragment & FLAG_DF),
            mf=more_fragments,
        ),
        fragment_offset=fragment_offset,
        fragmented=fragment_offset > 0 or more_fragments,
        ttl=ttl,
        protocol_number=protocol,
        protocol_name=protocol_name(protocol),
        header_checksum=f"0x{checksum:04x}",
        header_checksum_valid=internet_checksum(data[:header_length]) == 0,
        src_ip=str(IPv4Address(src_raw)),
        dst_ip=str(IPv4Address(dst_raw)),
        options=(
            parse_options(data[IPV4_MIN_HEADER:header_length])
            if header_length > IPV4_MIN_HEADER
            else []
        ),
        captured_truncated=truncated,
        declared_payload_length=total_length - header_length,
        captured_payload_length=len(payload),
    )
    return NetworkResult(info, payload)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_network.py tests/test_transport.py -q`
Expected: `33 passed`.

- [ ] **Step 5: Lint**

Run: `uv run ruff check ids/parsers/network.py tests/test_network.py tests/test_transport.py && uv run ruff format --check ids/parsers/network.py tests/test_network.py tests/test_transport.py`
Expected: `All checks passed!` then `3 files already formatted`.

- [ ] **Step 6: Commit**

```bash
git add ids/parsers/network.py tests/test_network.py tests/test_transport.py
git commit -m "refactor: move the ipv4 parser onto the typed model and report truncation"
```

---

### Task 3: TCP/UDP on the typed model

**Files:**
- Modify (full rewrite): `ids/parsers/transport.py`
- Test (full rewrite): `tests/test_transport.py`

**Interfaces:**
- Consumes: Task 2 `IPPROTO_TCP`, `IPPROTO_UDP`, `parse_ipv4(data, issues) -> NetworkResult`; Task 1 `parse_link`; `ids.model.TcpInfo`, `TcpFlags`, `TcpOption`, `UdpInfo`; `ids.parsers.checksum.internet_checksum`, `pseudo_header(src: bytes, dst: bytes, protocol: int, length: int) -> bytes`.
- Produces:
  - `@dataclass(frozen=True, slots=True) class TransportResult: info: TcpInfo | UdpInfo; payload: bytes`
  - `def parse_transport(protocol_number: int, data: bytes, *, src_ip: str, dst_ip: str, declared_length: int | None = None, fragment_offset: int = 0) -> TransportResult` — `fragment_offset != 0` → `ParseError("unsupported_protocol", …, fragment_offset=…)`; protocol other than `IPPROTO_TCP`/`IPPROTO_UDP` → `ParseError("unsupported_protocol", …, protocol_number=…)`.
  - `def parse_tcp(data: bytes, *, src_ip: str, dst_ip: str, declared_length: int | None = None) -> TransportResult`
  - `def parse_udp(data: bytes, *, src_ip: str, dst_ip: str, declared_length: int | None = None) -> TransportResult`
  - `def tcp_options(raw: bytes) -> list[TcpOption]`; `TCP_OPTION_NAMES`, `TCP_FLAG_BITS`.
  - `checksum_valid` is `None` whenever the checksum cannot be verified (declared length missing or different from captured; UDP checksum 0 or truncated datagram).

- [ ] **Step 1: Write the failing test**

Replace `tests/test_transport.py` with:

```python
import pytest
from golden import DST, SRC, TCP_DATA, TCP_FIN, TCP_SYN_OPTIONS, UDP

from ids.issues import Issues, ParseError
from ids.model import TcpFlags, TcpInfo, TcpOption, UdpInfo
from ids.parsers.link import parse_link
from ids.parsers.network import IPPROTO_TCP, IPPROTO_UDP, parse_ipv4
from ids.parsers.transport import TransportResult, parse_transport, tcp_options


def transport(frame, **overrides):
    net = parse_ipv4(parse_link(frame, 1).payload, Issues("network"))
    kwargs = {
        "src_ip": net.info.src_ip,
        "dst_ip": net.info.dst_ip,
        "declared_length": net.info.declared_payload_length,
    }
    kwargs.update(overrides)
    return parse_transport(net.info.protocol_number, net.payload, **kwargs)


def test_syn_with_options():
    result = transport(TCP_SYN_OPTIONS)
    assert isinstance(result, TransportResult)
    info = result.info
    assert isinstance(info, TcpInfo)
    assert info.protocol == "TCP"
    assert info.src_port == 51234
    assert info.dst_port == 80
    assert info.seq == 1000
    assert info.ack == 0
    assert info.flags == TcpFlags(
        fin=False,
        syn=True,
        rst=False,
        psh=False,
        ack=False,
        urg=False,
        ece=False,
        cwr=False,
        ns=False,
    )
    assert info.flags_string == "S"
    assert info.flags_list == ["SYN"]
    assert info.header_length == 44
    assert info.window == 8192
    assert info.checksum_valid is True
    assert info.payload_length == 0
    assert result.payload == b""

    names = [option.name for option in info.options]
    assert names == ["MSS", "SACK-Permitted", "WScale", "NOP", "NOP", "Timestamps", "EOL"]
    assert info.options[0].mss == 1460
    assert info.options[2].shift == 7
    assert info.options[5].tsval == 111
    assert info.options[5].tsecr == 0


def test_psh_ack_carries_the_payload():
    result = transport(TCP_DATA)
    assert result.info.flags_string == "PA"
    assert result.info.flags_list == ["PSH", "ACK"]
    assert result.info.header_length == 20
    assert result.info.payload_length == 18
    assert result.payload == b"GET / HTTP/1.1\r\n\r\n"
    assert result.info.checksum_valid is True


def test_fin_psh_ack_flag_string():
    assert transport(TCP_FIN).info.flags_string == "FPA"


def test_tcp_checksum_is_not_verified_without_a_declared_length():
    assert transport(TCP_DATA, declared_length=None).info.checksum_valid is None


def test_sack_blocks_and_unknown_options():
    raw = bytes.fromhex("050a000000010000000a") + bytes.fromhex("fe0399") + bytes.fromhex("00")
    assert tcp_options(raw) == [
        TcpOption(type=5, name="SACK", length=10, blocks=[[1, 10]]),
        TcpOption(type=254, name="UNKNOWN(254)", length=3, data="99"),
        TcpOption(type=0, name="EOL"),
    ]


def test_tcp_option_overrunning_the_header_is_malformed():
    assert tcp_options(bytes.fromhex("0101080a00000000")) == [
        TcpOption(type=1, name="NOP"),
        TcpOption(type=1, name="NOP"),
        TcpOption(type=8, name="Timestamps", malformed=True, declared_length=10, available=6),
    ]


def test_tcp_option_without_a_length_byte_is_malformed():
    assert tcp_options(bytes.fromhex("010102")) == [
        TcpOption(type=1, name="NOP"),
        TcpOption(type=1, name="NOP"),
        TcpOption(type=2, name="MSS", malformed=True),
    ]


def test_udp_fields():
    result = transport(UDP)
    info = result.info
    assert isinstance(info, UdpInfo)
    assert info.protocol == "UDP"
    assert info.src_port == 40000
    assert info.dst_port == 53
    assert info.length == 17
    assert info.declared_payload_length == 9
    assert info.payload_length == 9
    assert info.checksum_valid is True
    assert info.captured_truncated is False
    assert result.payload == b"payload01"


def test_udp_zero_checksum_means_not_computed():
    raw = bytearray(UDP[14:][20:])
    raw[6:8] = b"\x00\x00"
    info = parse_transport(
        IPPROTO_UDP, bytes(raw), src_ip=SRC, dst_ip=DST, declared_length=len(raw)
    ).info
    assert info.checksum == "0x0000"
    assert info.checksum_valid is None


def test_checksum_is_not_verified_when_the_capture_is_short():
    net = parse_ipv4(parse_link(UDP, 1).payload, Issues("network"))
    info = parse_transport(
        IPPROTO_UDP, net.payload[:12], src_ip=SRC, dst_ip=DST, declared_length=17
    ).info
    assert info.checksum_valid is None


def test_corrupted_tcp_checksum_is_detected():
    segment = bytearray(TCP_DATA[14:][20:])
    segment[16] ^= 0xFF
    info = parse_transport(
        IPPROTO_TCP, bytes(segment), src_ip=SRC, dst_ip=DST, declared_length=len(segment)
    ).info
    assert info.checksum_valid is False


def test_tcp_data_offset_below_five_is_malformed():
    raw = bytearray(TCP_DATA[14:][20:])
    raw[12:14] = (0x4018).to_bytes(2, "big")
    with pytest.raises(ParseError) as caught:
        parse_transport(IPPROTO_TCP, bytes(raw), src_ip=SRC, dst_ip=DST)
    assert caught.value.code == "malformed_header"
    assert caught.value.context == {"data_offset": 4}


def test_tcp_header_shorter_than_twenty_bytes():
    with pytest.raises(ParseError) as caught:
        parse_transport(IPPROTO_TCP, b"\x00" * 10, src_ip=SRC, dst_ip=DST)
    assert caught.value.code == "truncated_packet"
    assert caught.value.context == {"declared": 20, "captured": 10}


def test_tcp_options_cut_by_the_capture_are_truncated():
    raw = bytearray(TCP_DATA[14:][20:40])
    raw[12] = 0x60
    with pytest.raises(ParseError) as caught:
        parse_transport(IPPROTO_TCP, bytes(raw), src_ip=SRC, dst_ip=DST)
    assert caught.value.code == "truncated_packet"
    assert caught.value.context == {"declared": 24, "captured": 20}


def test_udp_length_below_eight_is_malformed():
    header = bytes.fromhex("9c40") + bytes.fromhex("9c40") + bytes.fromhex("0004") + b"\x00\x00"
    with pytest.raises(ParseError) as caught:
        parse_transport(IPPROTO_UDP, header, src_ip=SRC, dst_ip=DST)
    assert caught.value.code == "malformed_header"
    assert caught.value.context == {"length": 4}


def test_udp_declared_length_longer_than_capture_is_flagged():
    header = bytes.fromhex("9c40") + bytes.fromhex("9c40") + bytes.fromhex("0064") + b"\x00\x00"
    result = parse_transport(IPPROTO_UDP, header + b"only12bytes!", src_ip=SRC, dst_ip=DST)
    assert result.info.captured_truncated is True
    assert result.info.declared_payload_length == 92
    assert result.info.payload_length == 12
    assert result.payload == b"only12bytes!"


def test_non_first_fragment_has_no_transport_header():
    with pytest.raises(ParseError) as caught:
        parse_transport(IPPROTO_TCP, b"\x00" * 20, src_ip=SRC, dst_ip=DST, fragment_offset=8)
    assert caught.value.code == "unsupported_protocol"
    assert caught.value.context == {"fragment_offset": 8}


def test_other_ip_protocols_are_unsupported():
    with pytest.raises(ParseError) as caught:
        parse_transport(1, b"\x08\x00" + b"\x00" * 6, src_ip=SRC, dst_ip=DST)
    assert caught.value.code == "unsupported_protocol"
    assert caught.value.context == {"protocol_number": 1}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_transport.py -q`
Expected: collection error `ImportError: cannot import name 'TransportResult' from 'ids.parsers.transport'`.

- [ ] **Step 3: Write the implementation**

Replace `ids/parsers/transport.py` with:

```python
from __future__ import annotations

import struct
from collections.abc import Callable
from dataclasses import dataclass
from ipaddress import IPv4Address

from ..issues import ParseError
from ..model import TcpFlags, TcpInfo, TcpOption, UdpInfo
from .checksum import internet_checksum, pseudo_header
from .network import IPPROTO_TCP, IPPROTO_UDP

TCP_MIN_HEADER = 20
TCP_MAX_HEADER = 60
UDP_HEADER = 8

TCP_OPTION_NAMES = {
    0: "EOL",
    1: "NOP",
    2: "MSS",
    3: "WScale",
    4: "SACK-Permitted",
    5: "SACK",
    8: "Timestamps",
    28: "UTO",
    29: "AO",
    30: "MPTCP",
    34: "FASTOPEN",
}

TCP_FLAG_BITS = (
    (0x0001, "fin", "F"),
    (0x0002, "syn", "S"),
    (0x0004, "rst", "R"),
    (0x0008, "psh", "P"),
    (0x0010, "ack", "A"),
    (0x0020, "urg", "U"),
    (0x0040, "ece", "E"),
    (0x0080, "cwr", "W"),
    (0x0100, "ns", "N"),
)


@dataclass(frozen=True, slots=True)
class TransportResult:
    info: TcpInfo | UdpInfo
    payload: bytes


def tcp_options(raw: bytes) -> list[TcpOption]:
    options: list[TcpOption] = []
    offset = 0
    while offset < len(raw):
        kind = raw[offset]
        if kind == 0:
            options.append(TcpOption(type=0, name="EOL"))
            break
        if kind == 1:
            options.append(TcpOption(type=1, name="NOP"))
            offset += 1
            continue
        name = TCP_OPTION_NAMES.get(kind, f"UNKNOWN({kind})")
        if offset + 2 > len(raw):
            options.append(TcpOption(type=kind, name=name, malformed=True))
            break
        length = raw[offset + 1]
        if length < 2 or offset + length > len(raw):
            options.append(
                TcpOption(
                    type=kind,
                    name=name,
                    malformed=True,
                    declared_length=length,
                    available=len(raw) - offset,
                )
            )
            break
        value = raw[offset + 2 : offset + length]
        option = TcpOption(type=kind, name=name, length=length)
        if kind == 2 and length == 4:
            option.mss = int.from_bytes(value, "big")
        elif kind == 3 and length == 3:
            option.shift = value[0]
        elif kind == 8 and length == 10:
            option.tsval = int.from_bytes(value[0:4], "big")
            option.tsecr = int.from_bytes(value[4:8], "big")
        elif kind == 5 and length >= 10:
            option.blocks = [
                [
                    int.from_bytes(value[i : i + 4], "big"),
                    int.from_bytes(value[i + 4 : i + 8], "big"),
                ]
                for i in range(0, len(value) - 7, 8)
            ]
        else:
            option.data = value.hex()
        options.append(option)
        offset += length
    return options


def _checksum_state(
    data: bytes, src_ip: str, dst_ip: str, protocol: int, declared_length: int | None
) -> bool | None:
    if declared_length is None or declared_length != len(data):
        return None
    header = pseudo_header(
        IPv4Address(src_ip).packed, IPv4Address(dst_ip).packed, protocol, declared_length
    )
    return internet_checksum(header + data) == 0


def parse_tcp(
    data: bytes, *, src_ip: str, dst_ip: str, declared_length: int | None = None
) -> TransportResult:
    if len(data) < TCP_MIN_HEADER:
        raise ParseError(
            "truncated_packet",
            "TCP header shorter than 20 bytes",
            declared=TCP_MIN_HEADER,
            captured=len(data),
        )

    src_port, dst_port, seq, ack, offset_flags, window, checksum, urgent = struct.unpack_from(
        "!HHIIHHHH", data, 0
    )
    data_offset = (offset_flags >> 12) & 0x0F
    header_length = data_offset * 4
    if data_offset < 5:
        raise ParseError(
            "malformed_header",
            f"TCP data offset {data_offset} is below the minimum of 5",
            data_offset=data_offset,
        )
    if header_length > TCP_MAX_HEADER:
        raise ParseError(
            "malformed_header",
            f"TCP header length {header_length} exceeds 60 bytes",
            data_offset=data_offset,
        )
    if len(data) < header_length:
        raise ParseError(
            "truncated_packet",
            "TCP header options truncated",
            declared=header_length,
            captured=len(data),
        )

    present = [(name, letter) for bit, name, letter in TCP_FLAG_BITS if offset_flags & bit]
    payload = data[header_length:]
    info = TcpInfo(
        src_port=src_port,
        dst_port=dst_port,
        seq=seq,
        ack=ack,
        header_length=header_length,
        reserved=(offset_flags >> 9) & 0x07,
        flags=TcpFlags(**{name: bool(offset_flags & bit) for bit, name, _ in TCP_FLAG_BITS}),
        flags_list=[name.upper() for name, _ in present],
        flags_string="".join(letter for _, letter in present),
        window=window,
        checksum=f"0x{checksum:04x}",
        checksum_valid=_checksum_state(data, src_ip, dst_ip, IPPROTO_TCP, declared_length),
        urgent_pointer=urgent,
        options=(
            tcp_options(data[TCP_MIN_HEADER:header_length])
            if header_length > TCP_MIN_HEADER
            else []
        ),
        payload_length=len(payload),
    )
    return TransportResult(info, payload)


def parse_udp(
    data: bytes, *, src_ip: str, dst_ip: str, declared_length: int | None = None
) -> TransportResult:
    if len(data) < UDP_HEADER:
        raise ParseError(
            "truncated_packet",
            "UDP header shorter than 8 bytes",
            declared=UDP_HEADER,
            captured=len(data),
        )

    src_port, dst_port, length, checksum = struct.unpack_from("!HHHH", data, 0)
    if length < UDP_HEADER:
        raise ParseError(
            "malformed_header", f"UDP length {length} is below the minimum of 8", length=length
        )

    truncated = length > len(data)
    payload = data[UDP_HEADER:] if truncated else data[UDP_HEADER:length]
    if checksum == 0 or truncated or length != len(data):
        checksum_valid = None
    else:
        checksum_valid = _checksum_state(data, src_ip, dst_ip, IPPROTO_UDP, length)

    info = UdpInfo(
        src_port=src_port,
        dst_port=dst_port,
        length=length,
        checksum=f"0x{checksum:04x}",
        checksum_valid=checksum_valid,
        declared_payload_length=length - UDP_HEADER,
        payload_length=len(payload),
        captured_truncated=truncated,
    )
    return TransportResult(info, payload)


_PARSERS: dict[int, Callable[..., TransportResult]] = {
    IPPROTO_TCP: parse_tcp,
    IPPROTO_UDP: parse_udp,
}


def parse_transport(
    protocol_number: int,
    data: bytes,
    *,
    src_ip: str,
    dst_ip: str,
    declared_length: int | None = None,
    fragment_offset: int = 0,
) -> TransportResult:
    if fragment_offset:
        raise ParseError(
            "unsupported_protocol",
            "non-first IPv4 fragment has no transport header",
            fragment_offset=fragment_offset,
        )
    parser = _PARSERS.get(protocol_number)
    if parser is None:
        raise ParseError(
            "unsupported_protocol",
            f"IP protocol {protocol_number} has no transport parser",
            protocol_number=protocol_number,
        )
    return parser(data, src_ip=src_ip, dst_ip=dst_ip, declared_length=declared_length)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_transport.py -q`
Expected: `18 passed`.

- [ ] **Step 5: Lint**

Run: `uv run ruff check ids/parsers/transport.py tests/test_transport.py && uv run ruff format --check ids/parsers/transport.py tests/test_transport.py`
Expected: `All checks passed!` then `2 files already formatted`.

- [ ] **Step 6: Commit**

```bash
git add ids/parsers/transport.py tests/test_transport.py
git commit -m "refactor: move the transport parsers onto the typed model"
```

---

### Task 4: HTTP parser keeps raw messages and owns its detector score

**Files:**
- Modify (full rewrite): `ids/parsers/http.py`
- Modify: `ids/parsers/detector.py` (transitional: HTTP scoring now comes from `http.score`)
- Test (full rewrite): `tests/test_http.py`
- Test (unchanged, must stay green): `tests/test_detector.py`

**Interfaces:**
- Consumes: `ids.issues.Issues`, `ParseError`; `ids.model.HttpMessage` (with `header(name)` / `header_values(name)`), `HttpHeader`, `HttpBody`.
- Produces:
  - `NAME = "HTTP"`, `PORTS = frozenset((80, 3128, 8000, 8008, 8080, 8081, 8888, 9080))`, `METHODS: frozenset[bytes]`, `MAX_HEADER_BYTES = 65536`.
  - `def score(payload: bytes, tcp: bool) -> tuple[float, str | None]` — tiers `0.95` "HTTP status line", `0.95` "HTTP request line" (known method), `0.8` "HTTP request line without a strict version token", `0.6` "HTTP method token", else `(0.0, None)`.
  - `def parse(payload: bytes, *, tcp: bool, issues: Issues) -> HttpMessage` — fatal: `ParseError("decode_error", …)`; issues: `malformed_header_line` (context `line`), `invalid_content_length`, `truncated_body` (context `declared`, `captured`), `incomplete_message`.
  - `def first_line(data: bytes) -> bytes`.
  - Body bytes for a later stage: `payload[body.offset : body.offset + body.length]`.

- [ ] **Step 1: Write the failing test**

Replace `tests/test_http.py` with:

```python
import pytest
from golden import HTTP_GET, HTTP_POST, HTTP_RESPONSE

from ids.issues import Issue, Issues, ParseError
from ids.model import HttpBody, HttpHeader
from ids.parsers.http import MAX_HEADER_BYTES, first_line, parse, score


def parse_http(payload, issues=None):
    return parse(payload, tcp=True, issues=issues if issues is not None else Issues("application"))


def body_bytes(payload, message):
    return payload[message.body.offset : message.body.offset + message.body.length]


def codes(issues):
    return [issue.code for issue in issues.records]


def test_get_request_fields():
    issues = Issues("application")
    message = parse_http(HTTP_GET, issues)
    assert message.kind == "request"
    assert message.method == "GET"
    assert message.version == "1.1"
    assert message.start_line == "GET /index.html?q=ids&page=1 HTTP/1.1"
    assert message.uri == "/index.html?q=ids&page=1"
    assert message.header("host") == "example.com"
    assert message.header("user-agent") == "test/1.0"
    assert [header.name for header in message.headers] == ["Host", "User-Agent", "Accept"]
    assert message.complete is True
    assert message.body == HttpBody(
        offset=len(HTTP_GET), length=0, transfer_encoding="identity", truncated=False
    )
    assert issues.records == []


def test_post_body_is_cut_at_content_length():
    message = parse_http(HTTP_POST)
    assert message.method == "POST"
    assert message.header("content-type") == "application/x-www-form-urlencoded"
    assert message.body.length == 34
    assert message.body.declared_length == 34
    assert message.body.truncated is False
    assert body_bytes(HTTP_POST, message) == b"username=alice&password=s3cr3t&on="


def test_response_status_and_headers():
    message = parse_http(HTTP_RESPONSE)
    assert message.kind == "response"
    assert message.status_code == 301
    assert message.reason == "Moved Permanently"
    assert message.method is None
    assert message.uri is None
    assert message.header("server") == "nginx/1.24.0"
    assert message.header("location") == "https://example.com/"
    assert body_bytes(HTTP_RESPONSE, message) == b"ok"


def test_status_line_without_reason():
    message = parse_http(b"HTTP/1.0 204\r\n\r\n")
    assert message.status_code == 204
    assert message.reason == ""


def test_request_target_is_kept_raw():
    message = parse_http(b"GET http://example.com/a%20b?x=%41&y=1+2 HTTP/1.1\r\nHost: e\r\n\r\n")
    assert message.uri == "http://example.com/a%20b?x=%41&y=1+2"


def test_header_names_keep_case_and_order_and_lookup_ignores_case():
    message = parse_http(b"GET / HTTP/1.1\r\nhOsT: a\r\nX-Custom: b\r\nACCEPT: c\r\n\r\n")
    assert message.headers == [
        HttpHeader(name="hOsT", value="a"),
        HttpHeader(name="X-Custom", value="b"),
        HttpHeader(name="ACCEPT", value="c"),
    ]
    assert message.header("HOST") == "a"
    assert message.header("accept") == "c"


def test_duplicate_headers_are_kept_in_order():
    message = parse_http(b"GET / HTTP/1.1\r\nX-Tag: one\r\nHost: a\r\nX-Tag: two\r\n\r\n")
    assert [header.name for header in message.headers] == ["X-Tag", "Host", "X-Tag"]
    assert message.header_values("x-tag") == ["one", "two"]
    assert message.header("x-tag") == "two"


def test_folded_header_is_appended_to_the_previous_value():
    message = parse_http(b"GET / HTTP/1.1\r\nHost: a\r\nX-Long: one\r\n  two\r\n\tthree\r\n\r\n")
    assert message.headers == [
        HttpHeader(name="Host", value="a"),
        HttpHeader(name="X-Long", value="one two three"),
    ]


def test_header_without_colon_is_recorded_but_does_not_abort():
    issues = Issues("application")
    message = parse_http(b"GET / HTTP/1.1\r\nnot-a-header\r\nHost: a\r\n\r\n", issues)
    assert message.header("host") == "a"
    assert issues.records == [
        Issue(
            "application",
            "malformed_header_line",
            "HTTP header line has no field name",
            {"line": "not-a-header"},
        )
    ]


def test_leading_continuation_line_is_malformed():
    issues = Issues("application")
    message = parse_http(b"GET / HTTP/1.1\r\n  orphan\r\nHost: a\r\n\r\n", issues)
    assert [header.name for header in message.headers] == ["Host"]
    assert codes(issues) == ["malformed_header_line"]


def test_body_shorter_than_content_length_is_reported():
    issues = Issues("application")
    payload = b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 100\r\n\r\nshort"
    message = parse_http(payload, issues)
    assert message.body.length == 5
    assert message.body.truncated is True
    assert message.body.declared_length == 100
    assert body_bytes(payload, message) == b"short"
    assert codes(issues) == ["truncated_body"]
    assert issues.records[0].context == {"declared": 100, "captured": 5}


def test_missing_header_terminator_is_reported():
    issues = Issues("application")
    payload = b"GET / HTTP/1.1\r\nHost: a"
    message = parse_http(payload, issues)
    assert codes(issues) == ["incomplete_message"]
    assert message.complete is False
    assert message.header("host") == "a"
    assert message.body == HttpBody(
        offset=len(payload), length=0, transfer_encoding="identity", truncated=False
    )


def test_lf_only_message_locates_the_body():
    payload = b"POST /x HTTP/1.0\nHost: a\nContent-Length: 3\n\nabcdef"
    message = parse_http(payload)
    assert message.complete is True
    assert message.header("host") == "a"
    assert message.body.offset == payload.index(b"\n\n") + 2
    assert body_bytes(payload, message) == b"abc"


def test_header_block_beyond_the_limit_is_incomplete():
    issues = Issues("application")
    payload = b"GET / HTTP/1.1\r\nX-Pad: " + b"a" * MAX_HEADER_BYTES + b"\r\n\r\nbody"
    message = parse_http(payload, issues)
    assert message.complete is False
    assert message.header("x-pad") == "a" * (MAX_HEADER_BYTES - len(b"GET / HTTP/1.1\r\nX-Pad: "))
    assert message.body.offset == len(payload)
    assert message.body.length == 0
    assert codes(issues) == ["incomplete_message"]


def test_invalid_content_length_is_reported():
    issues = Issues("application")
    message = parse_http(b"POST / HTTP/1.1\r\nContent-Length: abc\r\n\r\nxx", issues)
    assert codes(issues) == ["invalid_content_length"]
    assert message.body.declared_length is None
    assert message.body.length == 2


def test_negative_content_length_is_invalid_not_incomplete():
    issues = Issues("application")
    message = parse_http(b"POST / HTTP/1.1\r\nContent-Length: -5\r\nHost: a", issues)
    assert codes(issues) == ["invalid_content_length"]
    assert message.body.declared_length is None


def test_last_content_length_wins():
    payload = b"POST / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 3\r\n\r\nabcdef"
    message = parse_http(payload)
    assert body_bytes(payload, message) == b"abc"


def test_chunked_body_is_flagged_not_decoded():
    issues = Issues("application")
    payload = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
    message = parse_http(payload, issues)
    assert message.body.transfer_encoding == "chunked"
    assert message.body.declared_length is None
    assert body_bytes(payload, message) == b"5\r\nhello\r\n0\r\n\r\n"
    assert issues.records == []


@pytest.mark.parametrize(
    "payload",
    [b"", b"\x16\x03\x01\x00\x10garbage", b"NOT-HTTP\r\n\r\n", b"\x00\x01\x02\x03", b"\r\n\r\n"],
)
def test_non_http_payloads_raise_decode_error(payload):
    with pytest.raises(ParseError) as caught:
        parse_http(payload)
    assert caught.value.code == "decode_error"


def test_first_line_helper():
    assert first_line(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n") == b"GET / HTTP/1.1"
    assert first_line(b"GET / HTTP/1.1\nHost: x") == b"GET / HTTP/1.1"
    assert first_line(b"no terminator") == b"no terminator"


@pytest.mark.parametrize(
    "payload,expected",
    [
        (HTTP_RESPONSE, (0.95, "HTTP status line")),
        (HTTP_GET, (0.95, "HTTP request line")),
        (b"PROPFIND /dav HTTP/1.1\r\n\r\n", (0.95, "HTTP request line")),
        (b"FETCH /x HTTP/1.1\r\n\r\n", (0.8, "HTTP request line without a strict version token")),
        (b"GET /index.html\r\n", (0.6, "HTTP method token")),
        (b"hello world\r\n", (0.0, None)),
        (b"\x16\x03\x01\x00\x10", (0.0, None)),
    ],
)
def test_score_tiers(payload, expected):
    assert score(payload, True) == expected


def test_scored_unknown_method_still_parses_as_a_request():
    assert parse_http(b"FETCH /x HTTP/1.1\r\n\r\n").method == "FETCH"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_http.py -q`
Expected: collection error `ImportError: cannot import name 'score' from 'ids.parsers.http'`.

- [ ] **Step 3: Write the implementation**

Replace `ids/parsers/http.py` with:

```python
from __future__ import annotations

import re

from ..issues import Issues, ParseError
from ..model import HttpBody, HttpHeader, HttpMessage

NAME = "HTTP"
PORTS = frozenset((80, 3128, 8000, 8008, 8080, 8081, 8888, 9080))

METHODS = frozenset(b"GET POST PUT DELETE HEAD OPTIONS PATCH TRACE CONNECT PROPFIND".split())
METHODS |= frozenset(b"PROPPATCH MKCOL COPY MOVE LOCK UNLOCK".split())

REQUEST_LINE = re.compile(rb"^([A-Z]{3,12})[ \t]+(\S+)[ \t]+HTTP/(\d+\.\d+)$")
STATUS_LINE = re.compile(rb"^HTTP/(\d+\.\d+)[ \t]+(\d{3})(?:[ \t]+(.*))?$")
HEADER_LINE = re.compile(rb"^([!-9;-~]+):[ \t]*(.*)$")
CONTINUATION = re.compile(rb"^[ \t]+(.*)$")

KNOWN_REQUEST_PREFIX = re.compile(
    rb"^(?:" + rb"|".join(sorted(METHODS)) + rb")[ \t]+\S+[ \t]+HTTP/\d\.\d"
)
STATUS_PREFIX = re.compile(rb"^HTTP/\d\.\d[ \t]+\d{3}")
METHOD_TOKEN = re.compile(rb"^[A-Z]{3,12}[ \t]+\S")
VERSION_TOKEN = re.compile(rb"HTTP/\d\.\d")

MAX_HEADER_BYTES = 65536
SCORE_WINDOW = 512
SEPARATORS = (b"\r\n\r\n", b"\n\n")


def first_line(data: bytes) -> bytes:
    end = data.find(b"\r\n")
    newline = data.find(b"\n")
    if end < 0 or (0 <= newline < end):
        end = newline
    return data if end < 0 else data[:end]


def score(payload: bytes, tcp: bool) -> tuple[float, str | None]:
    window = payload[:SCORE_WINDOW]
    line = first_line(window)
    if STATUS_PREFIX.match(line):
        return 0.95, "HTTP status line"
    if KNOWN_REQUEST_PREFIX.match(line):
        return 0.95, "HTTP request line"
    if METHOD_TOKEN.match(line):
        if VERSION_TOKEN.search(window):
            return 0.8, "HTTP request line without a strict version token"
        return 0.6, "HTTP method token"
    return 0.0, None


def _split(payload: bytes) -> tuple[int, int, bool]:
    """Return (header block end, body offset, terminator found)."""
    for separator in SEPARATORS:
        index = payload.find(separator, 0, MAX_HEADER_BYTES + len(separator))
        if index >= 0:
            return index, index + len(separator), True
    return min(len(payload), MAX_HEADER_BYTES), len(payload), False


def _headers(lines: list[bytes], issues: Issues) -> list[HttpHeader]:
    headers: list[HttpHeader] = []
    for raw in lines:
        if not raw:
            continue
        continuation = CONTINUATION.match(raw)
        if continuation and headers:
            last = headers[-1]
            last.value = f"{last.value} {continuation.group(1).decode('latin-1').strip()}"
            continue
        match = HEADER_LINE.match(raw)
        if not match:
            issues.add(
                "malformed_header_line",
                "HTTP header line has no field name",
                line=raw[:120].decode("latin-1"),
            )
            continue
        headers.append(
            HttpHeader(
                name=match.group(1).decode("latin-1"),
                value=match.group(2).decode("latin-1").strip(),
            )
        )
    return headers


def _int_or_none(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value.strip())
    except ValueError:
        return None


def _body(
    message: HttpMessage, offset: int, available: int, complete: bool, issues: Issues
) -> HttpBody:
    transfer = message.header("transfer-encoding")
    if transfer and "chunked" in transfer.lower():
        return HttpBody(
            offset=offset, length=available, transfer_encoding="chunked", truncated=False
        )

    declared = message.header("content-length")
    declared_length = _int_or_none(declared)
    length = available
    truncated = False
    if declared is not None and declared_length is None:
        issues.add("invalid_content_length", f"Content-Length {declared!r} is not an integer")
    if declared_length is not None:
        if declared_length < 0:
            issues.add("invalid_content_length", f"Content-Length {declared_length} is negative")
            declared_length = None
        elif declared_length > available:
            truncated = True
            issues.add(
                "truncated_body",
                "HTTP body is shorter than Content-Length",
                declared=declared_length,
                captured=available,
            )
        else:
            length = declared_length
    elif not complete:
        issues.add(
            "incomplete_message",
            "HTTP message header terminator not found in the captured bytes",
        )
    return HttpBody(
        offset=offset,
        length=length,
        declared_length=declared_length,
        transfer_encoding="identity",
        truncated=truncated,
    )


def parse(payload: bytes, *, tcp: bool, issues: Issues) -> HttpMessage:
    if not payload:
        raise ParseError("decode_error", "HTTP payload is empty")

    block_end, body_offset, complete = _split(payload)
    lines = payload[:block_end].splitlines()
    if not lines:
        raise ParseError("decode_error", "HTTP message has no start line")

    start = lines[0]
    message = HttpMessage(start_line=start.decode("latin-1"), complete=complete)
    request = REQUEST_LINE.match(start)
    if request:
        message.kind = "request"
        message.method = request.group(1).decode("ascii")
        message.uri = request.group(2).decode("latin-1")
        message.version = request.group(3).decode("ascii")
    else:
        status = STATUS_LINE.match(start)
        if not status:
            raise ParseError(
                "decode_error",
                "payload does not start with an HTTP request or status line",
                start_line=start[:120].decode("latin-1"),
            )
        message.kind = "response"
        message.version = status.group(1).decode("ascii")
        message.status_code = int(status.group(2))
        reason = status.group(3)
        message.reason = reason.decode("latin-1").strip() if reason else ""

    message.headers = _headers(lines[1:], issues)
    message.body = _body(message, body_offset, len(payload) - body_offset, complete, issues)
    return message
```

- [ ] **Step 4: Point the legacy detector at `http.score`**

The legacy detector called `http.first_line` and kept its own copy of the HTTP grammar. Replace `ids/parsers/detector.py` with this transitional version (HTTP regexes and `http_score` removed; DNS and SMTP scoring untouched until Tasks 5 and 6):

```python
from __future__ import annotations

import re
from collections import namedtuple

from ..errors import PacketParseError
from . import dns, http, smtp

STANDARD_PORTS = {
    53: "DNS",
    80: "HTTP",
    465: "SMTP",
    587: "SMTP",
    2525: "SMTP",
    3128: "HTTP",
    8000: "HTTP",
    8008: "HTTP",
    8080: "HTTP",
    8081: "HTTP",
    8888: "HTTP",
    9080: "HTTP",
    5353: "DNS",
    25: "SMTP",
}

PROTOCOLS = ("HTTP", "DNS", "SMTP")
PORT_BOOST = 0.25
MIN_CONFIDENCE = 0.5
PORT_ONLY_CONFIDENCE = 0.3

SMTP_CODES = frozenset(
    (
        211,
        214,
        220,
        221,
        250,
        251,
        252,
        354,
        421,
        450,
        451,
        452,
        455,
        500,
        501,
        502,
        503,
        504,
        530,
        532,
        550,
        551,
        552,
        553,
        554,
        555,
    )
)

SMTP_HELLO = re.compile(rb"^(?:HELO|EHLO)[ \t]+\S", re.IGNORECASE)
SMTP_PATH = re.compile(rb"^(?:MAIL|RCPT)[ \t]+(?:FROM|TO)[ \t]*:", re.IGNORECASE)
SMTP_VERB = re.compile(
    rb"^(?:DATA|QUIT|RSET|NOOP|VRFY|EXPN|HELP|AUTH|STARTTLS|BDAT|ETRN)(?:[ \t]|$)", re.IGNORECASE
)
SMTP_STATUS_LINE = re.compile(rb"^([2-5]\d{2})([ -]|$)")

PLAUSIBLE_LABEL = re.compile(rb"^[A-Za-z0-9_-]{1,63}$")

Detection = namedtuple(
    "Detection", "protocol method confidence port_matched port_hint evidence scores"
)


def _plausible_name(name: str) -> bool:
    if not name or name == ".":
        return False
    labels = name.rstrip(".").split(".")
    return all(
        PLAUSIBLE_LABEL.match(label.encode("latin-1", "replace")) for label in labels if label
    )


def dns_score(payload: bytes, tcp: bool) -> tuple[float, str | None]:
    if tcp:
        if len(payload) < 14:
            return 0.0, None
        declared = int.from_bytes(payload[:2], "big")
        if declared < 12 or declared + 2 > len(payload):
            return 0.0, None
    elif len(payload) < 12:
        return 0.0, None

    try:
        message = dns.parse(payload, tcp=tcp)
    except PacketParseError:
        return 0.0, None

    if message["opcode"] not in dns.OPCODES:
        return 0.2, "DNS header with an unknown opcode"

    score = 0.45
    evidence = ["DNS header"]
    questions = message["questions"]
    if questions:
        question = questions[0]
        if _plausible_name(question["name"]):
            score += 0.25
            evidence.append("plausible question name")
        if question["type"] in dns.QTYPES:
            score += 0.15
            evidence.append(f"known qtype {question['type_name']}")
        if question["class"] in dns.QCLASSES:
            score += 0.05
    if message["kind"] == "response" and message["counts"]["answers"]:
        score += 0.10
        evidence.append("response with answers")
    return min(score, 1.0), ", ".join(evidence)


def smtp_score(payload: bytes) -> tuple[float, str | None]:
    line = smtp.first_line(payload[:512])
    if SMTP_HELLO.match(line):
        return 0.95, "SMTP HELO/EHLO command"
    if SMTP_PATH.match(line):
        return 0.95, "SMTP MAIL/RCPT path"
    status = SMTP_STATUS_LINE.match(line)
    if status:
        code = int(status.group(1))
        if status.group(2) == b"-" or code in SMTP_CODES:
            return 0.85, f"SMTP status code {code}"
        return 0.45, f"numeric status line {code}"
    if SMTP_VERB.match(line):
        return 0.7, "SMTP verb"
    return 0.0, None


def detect(payload: bytes, *, src_port=None, dst_port=None, tcp: bool = False) -> Detection:
    if not payload:
        return Detection("UNKNOWN", "none", 0.0, False, None, "no payload to inspect", {})

    scores: dict[str, float] = {}
    evidence: dict[str, str | None] = {}
    for name, (score, why) in (
        ("HTTP", http.score(payload, tcp)),
        ("DNS", dns_score(payload, tcp)),
        ("SMTP", smtp_score(payload)),
    ):
        scores[name] = score
        evidence[name] = why

    hints = [STANDARD_PORTS[port] for port in (src_port, dst_port) if port in STANDARD_PORTS]
    port_hint = hints[0] if hints else None
    if port_hint:
        scores[port_hint] = min(scores[port_hint] + PORT_BOOST, 1.0)

    best = max(PROTOCOLS, key=lambda name: scores[name])
    payload_matched = evidence[best] is not None
    port_matched = port_hint == best

    if scores[best] >= MIN_CONFIDENCE:
        if payload_matched and port_matched:
            method = "port+payload"
        elif payload_matched:
            method = "payload"
        else:
            method = "port"
        return Detection(
            best,
            method,
            round(scores[best], 2),
            port_matched,
            port_hint,
            evidence[best],
            {name: round(value, 2) for name, value in scores.items()},
        )

    if port_hint:
        return Detection(
            port_hint,
            "port",
            PORT_ONLY_CONFIDENCE,
            True,
            port_hint,
            "standard port with no recognisable signature",
            {name: round(value, 2) for name, value in scores.items()},
        )

    return Detection(
        "UNKNOWN",
        "none",
        0.0,
        False,
        None,
        "no signature matched and no standard port",
        {name: round(value, 2) for name, value in scores.items()},
    )
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_http.py tests/test_detector.py -q`
Expected: `55 passed`.

- [ ] **Step 6: Lint**

Run: `uv run ruff check ids/parsers/http.py ids/parsers/detector.py tests/test_http.py && uv run ruff format --check ids/parsers/http.py ids/parsers/detector.py tests/test_http.py`
Expected: `All checks passed!` then `3 files already formatted`.

- [ ] **Step 7: Commit**

```bash
git add ids/parsers/http.py ids/parsers/detector.py tests/test_http.py
git commit -m "refactor: keep raw http messages in the typed model and move http scoring into the parser"
```

---

### Task 5: DNS parser on the typed model with its own detector score

**Files:**
- Modify (full rewrite): `ids/parsers/dns.py`
- Modify: `ids/parsers/detector.py` (transitional: DNS scoring now comes from `dns.score`)
- Test (full rewrite): `tests/test_dns.py`
- Test (unchanged, must stay green): `tests/test_detector.py`

**Interfaces:**
- Consumes: `ids.issues.Issue`, `Issues`, `ParseError`, `jsonable`; `ids.model.DnsMessage`, `DnsFlags`, `DnsCounts`, `DnsQuestion`, `DnsRecord` (`class_` field).
- Produces:
  - `NAME = "DNS"`, `PORTS = frozenset((53, 5353))`, `QTYPES`, `QCLASSES`, `RCODES`, `OPCODES`, `MAX_POINTER_JUMPS = 64`.
  - `def parse(payload: bytes, *, tcp: bool, issues: Issues) -> DnsMessage` — `tcp=True` strips the 2-byte length prefix; fatal `ParseError` codes `truncated_packet` / `decode_error`; rdata problems become `DnsRecord.rdata_error = Issue(issues.stage, code, message, context)` with hex `rdata` and are not added to `issues`.
  - `def score(payload: bytes, tcp: bool) -> tuple[float, str | None]` — parses with a throwaway `Issues("detect")`; `0.45` base + `0.25` plausible name + `0.15` known qtype + `0.05` known class + `0.10` response with answers, capped at `1.0`; `0.2` for an unknown opcode; `(0.0, None)` when parsing fails.
  - `def read_name(data: bytes, offset: int) -> tuple[str, int]`, `def read_rdata(data: bytes, offset: int, rtype: int, rdlength: int) -> object`, `type_name`, `class_name`.

- [ ] **Step 1: Write the failing test**

Replace `tests/test_dns.py` with:

```python
import struct

import pytest
from golden import DNS_ANSWER, DNS_POINTER_LOOP, DNS_QUERY, dns_name

from ids.issues import Issue, Issues, ParseError
from ids.model import DnsCounts, DnsQuestion
from ids.parsers.dns import parse, read_name, score


def record_bytes(name, rtype, rdata, ttl=60, rclass=1):
    return dns_name(name) + struct.pack("!HHIH", rtype, rclass, ttl, len(rdata)) + rdata


def message(identifier, flags, questions=(), answers=(), authorities=(), additionals=()):
    body = b""
    for name, rtype in questions:
        body += dns_name(name) + struct.pack("!HH", rtype, 1)
    for section in (answers, authorities, additionals):
        for item in section:
            body += record_bytes(*item)
    header = struct.pack(
        "!HHHHHH",
        identifier,
        flags,
        len(questions),
        len(answers),
        len(authorities),
        len(additionals),
    )
    return header + body


def parse_udp(payload, issues=None):
    return parse(payload, tcp=False, issues=issues if issues is not None else Issues("application"))


def test_query_question_and_flags():
    issues = Issues("application")
    info = parse_udp(DNS_QUERY, issues)
    assert info.kind == "query"
    assert info.id == 0x1234
    assert info.flags.rd is True
    assert info.flags.qr is False
    assert info.opcode_name == "QUERY"
    assert info.rcode_name == "NOERROR"
    assert info.counts == DnsCounts(questions=1, answers=0, authorities=0, additionals=0)
    assert info.questions == [
        DnsQuestion(name="example.com", type=1, type_name="A", class_=1, class_name="IN")
    ]
    assert info.answers == []
    assert info.tcp is False
    assert issues.records == []


def test_response_with_one_answer():
    info = parse_udp(DNS_ANSWER)
    assert info.kind == "response"
    assert info.flags.qr is True
    assert info.flags.ra is True
    assert info.counts.answers == 1
    answer = info.answers[0]
    assert answer.name == "example.com"
    assert answer.type_name == "A"
    assert answer.class_name == "IN"
    assert answer.ttl == 300
    assert answer.rdlength == 4
    assert answer.value == "93.184.216.34"
    assert answer.rdata is None


def test_name_compression_pointer_is_followed():
    raw = dns_name("example.com")
    name, offset = read_name(raw, 0)
    assert name == "example.com"
    assert offset == len(raw)
    compressed = raw + b"\xc0\x00"
    assert read_name(compressed, len(raw)) == ("example.com", len(raw) + 2)


def test_root_name_reads_as_a_dot():
    assert read_name(b"\x00", 0) == (".", 1)


@pytest.mark.parametrize(
    "rtype,rdata,expected",
    [
        (
            28,
            bytes.fromhex("26062800022000012481893525c81946"),
            "2606:2800:220:1:2481:8935:25c8:1946",
        ),
        (5, dns_name("target.example.com"), "target.example.com"),
        (12, dns_name("host.example.com"), "host.example.com"),
        (2, dns_name("ns1.example.com"), "ns1.example.com"),
    ],
)
def test_name_and_address_rdata(rtype, rdata, expected):
    info = parse_udp(message(1, 0x8180, [("q.example.com", 1)], [("q.example.com", rtype, rdata)]))
    assert info.answers[0].value == expected


def test_mx_rdata():
    rdata = struct.pack("!H", 10) + dns_name("mail.example.com")
    info = parse_udp(message(1, 0x8180, [("example.com", 15)], [("example.com", 15, rdata)]))
    assert info.answers[0].value == {"preference": 10, "exchange": "mail.example.com"}


def test_srv_rdata():
    rdata = struct.pack("!HHH", 10, 60, 5060) + dns_name("sip.example.com")
    info = parse_udp(
        message(1, 0x8180, [("_sip._tcp.example.com", 33)], [("_sip._tcp.example.com", 33, rdata)])
    )
    assert info.answers[0].value == {
        "priority": 10,
        "weight": 60,
        "port": 5060,
        "target": "sip.example.com",
    }


def test_txt_rdata():
    rdata = bytes([11]) + b"v=spf1 -all" + bytes([3]) + b"two"
    info = parse_udp(message(1, 0x8180, [("t.example.com", 16)], [("t.example.com", 16, rdata)]))
    assert info.answers[0].value == ["v=spf1 -all", "two"]


def test_soa_rdata():
    rdata = (
        dns_name("ns.example.com")
        + dns_name("hostmaster.example.com")
        + struct.pack("!IIIII", 1, 2, 3, 4, 5)
    )
    info = parse_udp(message(1, 0x8180, [("example.com", 6)], [("example.com", 6, rdata)]))
    assert info.answers[0].value == {
        "mname": "ns.example.com",
        "rname": "hostmaster.example.com",
        "serial": 1,
        "refresh": 2,
        "retry": 3,
        "expire": 4,
        "minimum": 5,
    }


def test_unknown_rdata_is_hex_encoded():
    info = parse_udp(
        message(1, 0x8180, [("x.example.com", 99)], [("x.example.com", 99, b"\xde\xad\xbe\xef")])
    )
    assert info.answers[0].rdata == "deadbeef"
    assert info.answers[0].value is None
    assert info.answers[0].type_name == "SPF"


def test_bad_rdata_is_kept_on_the_record_and_parsing_continues():
    issues = Issues("application")
    raw = message(
        1,
        0x8180,
        [("a.example.com", 1)],
        [("a.example.com", 1, b"\x01\x02\x03"), ("a.example.com", 1, b"\x0a\x00\x00\x01")],
    )
    info = parse_udp(raw, issues)
    bad, good = info.answers
    assert bad.value is None
    assert bad.rdata == "010203"
    assert bad.rdata_error == Issue(
        "application", "decode_error", "A record has rdlength 3, expected 4", {}
    )
    assert good.value == "10.0.0.1"
    assert good.rdata_error is None
    assert issues.records == []


def test_opt_record_reports_the_udp_payload_size():
    opt = b"\x00" + struct.pack("!HHIH", 41, 4096, 0, 0)
    raw = message(1, 0x0100, [("example.com", 1)])
    raw = raw[:10] + (1).to_bytes(2, "big") + raw[12:] + opt
    record = parse_udp(raw).additionals[0]
    assert record.name == "."
    assert record.type_name == "OPT"
    assert record.udp_payload_size == 4096
    assert record.rdata == ""


def test_unknown_opcode_and_rcode_are_named():
    info = parse_udp(message(1, 0x1800 | 0x000B, [("example.com", 1)]))
    assert info.opcode == 3
    assert info.opcode_name == "OPCODE3"
    assert info.rcode_name == "RCODE11"


def test_rcode_is_named():
    info = parse_udp(message(1, 0x8183, [("missing.example.com", 1)]))
    assert info.rcode == 3
    assert info.rcode_name == "NXDOMAIN"


def test_over_tcp_uses_the_length_prefix():
    message_bytes = message(0x2222, 0x0100, [("example.com", 1)])
    prefixed = len(message_bytes).to_bytes(2, "big") + message_bytes + b"next"
    info = parse(prefixed, tcp=True, issues=Issues("application"))
    assert info.tcp is True
    assert info.id == 0x2222
    assert info.questions[0].name == "example.com"


def test_tcp_length_prefix_longer_than_capture():
    with pytest.raises(ParseError) as caught:
        parse(b"\x00\xff" + message(1, 0x0100, [("example.com", 1)]), tcp=True, issues=Issues("a"))
    assert caught.value.code == "truncated_packet"
    assert caught.value.context == {"declared": 255, "captured": 29}


def test_tcp_length_prefix_below_the_header_size():
    with pytest.raises(ParseError) as caught:
        parse(b"\x00\x05" + b"\x00" * 12, tcp=True, issues=Issues("a"))
    assert caught.value.code == "decode_error"


def test_compression_pointer_loop_is_detected():
    with pytest.raises(ParseError) as caught:
        parse_udp(DNS_POINTER_LOOP)
    assert caught.value.code == "decode_error"
    assert "pointer loop" in caught.value.message


@pytest.mark.parametrize(
    "payload,code",
    [
        (b"", "truncated_packet"),
        (b"\x12\x34\x01", "truncated_packet"),
        (b"\x00" * 12, "decode_error"),
    ],
)
def test_malformed_messages(payload, code):
    with pytest.raises(ParseError) as caught:
        parse_udp(payload)
    assert caught.value.code == code


def test_truncated_question_is_reported():
    with pytest.raises(ParseError) as caught:
        parse_udp(DNS_QUERY[:-1])
    assert caught.value.code == "truncated_packet"


def test_record_rdata_beyond_the_message_is_reported():
    raw = message(1, 0x8180, [("a.example.com", 1)], [("a.example.com", 1, b"\x01\x02\x03\x04")])
    with pytest.raises(ParseError) as caught:
        parse_udp(raw[:-3])
    assert caught.value.code == "truncated_packet"
    assert caught.value.context == {"declared": 4, "available": 1}


def test_score_rewards_a_plausible_query():
    confidence, evidence = score(DNS_QUERY, False)
    assert confidence == pytest.approx(0.9)
    assert evidence == "DNS header, plausible question name, known qtype A"


def test_score_caps_a_response_with_answers_at_one():
    confidence, evidence = score(DNS_ANSWER, False)
    assert confidence == 1.0
    assert evidence.endswith("response with answers")


def test_score_flags_an_unknown_opcode():
    assert score(message(1, 0x1800, [("example.com", 1)]), False) == (
        0.2,
        "DNS header with an unknown opcode",
    )


@pytest.mark.parametrize(
    "payload,tcp",
    [
        (b"\x00" * 11, False),
        (b"\x00" * 12, False),
        (DNS_QUERY, True),
        (DNS_POINTER_LOOP, False),
    ],
)
def test_score_is_zero_when_the_message_does_not_parse(payload, tcp):
    assert score(payload, tcp) == (0.0, None)


def test_score_over_tcp_needs_the_length_prefix():
    prefixed = len(DNS_QUERY).to_bytes(2, "big") + DNS_QUERY
    assert score(prefixed, True)[0] == pytest.approx(0.9)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_dns.py -q`
Expected: collection error `ImportError: cannot import name 'score' from 'ids.parsers.dns'`.

- [ ] **Step 3: Write the implementation**

Replace `ids/parsers/dns.py` with:

```python
from __future__ import annotations

import re
import struct
from ipaddress import ip_address

from ..issues import Issue, Issues, ParseError, jsonable
from ..model import DnsCounts, DnsFlags, DnsMessage, DnsQuestion, DnsRecord

NAME = "DNS"
PORTS = frozenset((53, 5353))

HEADER_LENGTH = 12
MAX_POINTER_JUMPS = 64

QTYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    13: "HINFO",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    35: "NAPTR",
    41: "OPT",
    43: "DS",
    46: "RRSIG",
    47: "NSEC",
    48: "DNSKEY",
    64: "SVCB",
    65: "HTTPS",
    99: "SPF",
    251: "IXFR",
    252: "AXFR",
    255: "ANY",
}

QCLASSES = {1: "IN", 3: "CH", 4: "HS", 254: "NONE", 255: "ANY"}

RCODES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
    6: "YXDOMAIN",
    7: "YXRRSET",
    8: "NXRRSET",
    9: "NOTAUTH",
    10: "NOTZONE",
    16: "BADVERS",
}

OPCODES = {0: "QUERY", 1: "IQUERY", 2: "STATUS", 4: "NOTIFY", 5: "UPDATE"}

NAME_TYPES = frozenset((2, 5, 12))
ADDRESS_TYPES = {1: 4, 28: 16}
TYPE_OPT = 41

PLAUSIBLE_LABEL = re.compile(rb"^[A-Za-z0-9_-]{1,63}$")


def type_name(value: int) -> str:
    return QTYPES.get(value, f"TYPE{value}")


def class_name(value: int) -> str:
    return QCLASSES.get(value, f"CLASS{value}")


def read_name(data: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    jumps = 0
    end = None
    while True:
        if offset >= len(data):
            raise ParseError(
                "decode_error",
                "DNS name extends past the end of the message",
                offset=offset,
                length=len(data),
            )
        length = data[offset]
        if length == 0:
            offset += 1
            if end is None:
                end = offset
            break
        if length & 0xC0 == 0xC0:
            if offset + 2 > len(data):
                raise ParseError("decode_error", "truncated DNS compression pointer", offset=offset)
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if end is None:
                end = offset + 2
            jumps += 1
            if jumps > MAX_POINTER_JUMPS:
                raise ParseError("decode_error", "DNS compression pointer loop", offset=offset)
            offset = pointer
            continue
        if length & 0xC0:
            raise ParseError(
                "decode_error",
                "invalid DNS label length byte",
                offset=offset,
                value=hex(length),
            )
        if offset + 1 + length > len(data):
            raise ParseError(
                "decode_error", "truncated DNS label", offset=offset, label_length=length
            )
        labels.append(data[offset + 1 : offset + 1 + length].decode("latin-1"))
        offset += 1 + length
    return ".".join(labels) if labels else ".", end


def _character_strings(data: bytes, offset: int, end: int) -> list[str]:
    strings = []
    while offset < end:
        length = data[offset]
        offset += 1
        strings.append(data[offset : offset + length].decode("latin-1"))
        offset += length
    return strings


def read_rdata(data: bytes, offset: int, rtype: int, rdlength: int) -> object:
    if rtype in ADDRESS_TYPES:
        expected = ADDRESS_TYPES[rtype]
        if rdlength != expected:
            raise ParseError(
                "decode_error",
                f"{type_name(rtype)} record has rdlength {rdlength}, expected {expected}",
            )
        return str(ip_address(data[offset : offset + rdlength]))
    if rtype in NAME_TYPES:
        return read_name(data, offset)[0]
    if rtype == 15:
        if rdlength < 3:
            raise ParseError("decode_error", "MX record is too short", rdlength=rdlength)
        return {
            "preference": struct.unpack_from("!H", data, offset)[0],
            "exchange": read_name(data, offset + 2)[0],
        }
    if rtype == 33:
        if rdlength < 7:
            raise ParseError("decode_error", "SRV record is too short", rdlength=rdlength)
        priority, weight, port = struct.unpack_from("!HHH", data, offset)
        return {
            "priority": priority,
            "weight": weight,
            "port": port,
            "target": read_name(data, offset + 6)[0],
        }
    if rtype == 16:
        return _character_strings(data, offset, offset + rdlength)
    if rtype == 6:
        mname, cursor = read_name(data, offset)
        rname, cursor = read_name(data, cursor)
        if cursor + 20 > len(data):
            raise ParseError("decode_error", "SOA record is too short", rdlength=rdlength)
        serial, refresh, retry, expire, minimum = struct.unpack_from("!IIIII", data, cursor)
        return {
            "mname": mname,
            "rname": rname,
            "serial": serial,
            "refresh": refresh,
            "retry": retry,
            "expire": expire,
            "minimum": minimum,
        }
    return None


def _read_record(data: bytes, offset: int, stage: str) -> tuple[DnsRecord, int]:
    name, offset = read_name(data, offset)
    if offset + 10 > len(data):
        raise ParseError(
            "truncated_packet",
            "DNS resource record header truncated",
            offset=offset,
            captured=len(data),
        )
    rtype, rclass, ttl, rdlength = struct.unpack_from("!HHIH", data, offset)
    offset += 10
    if offset + rdlength > len(data):
        raise ParseError(
            "truncated_packet",
            "DNS resource record rdata truncated",
            declared=rdlength,
            available=len(data) - offset,
        )
    record = DnsRecord(
        name=name,
        type=rtype,
        type_name=type_name(rtype),
        class_=rclass,
        class_name=class_name(rclass),
        ttl=ttl,
        rdlength=rdlength,
    )
    try:
        record.value = read_rdata(data, offset, rtype, rdlength)
    except ParseError as error:
        record.rdata_error = Issue(stage, error.code, error.message, jsonable(error.context))
    if record.value is None:
        record.rdata = data[offset : offset + rdlength].hex()
    if rtype == TYPE_OPT:
        record.udp_payload_size = rclass
    return record, offset + rdlength


def _unwrap_tcp(data: bytes) -> bytes:
    if len(data) < 2:
        raise ParseError("truncated_packet", "DNS over TCP message has no length prefix")
    declared = struct.unpack_from("!H", data, 0)[0]
    if declared < HEADER_LENGTH:
        raise ParseError(
            "decode_error", f"DNS over TCP length prefix {declared} is below the header size"
        )
    if declared > len(data) - 2:
        raise ParseError(
            "truncated_packet",
            "DNS over TCP message truncated",
            declared=declared,
            captured=len(data) - 2,
        )
    return data[2 : 2 + declared]


def parse(payload: bytes, *, tcp: bool, issues: Issues) -> DnsMessage:
    data = _unwrap_tcp(payload) if tcp else payload
    if len(data) < HEADER_LENGTH:
        raise ParseError(
            "truncated_packet",
            "DNS header shorter than 12 bytes",
            declared=HEADER_LENGTH,
            captured=len(data),
        )

    identifier, flags, qdcount, ancount, nscount, arcount = struct.unpack_from("!HHHHHH", data, 0)
    if qdcount + ancount + nscount + arcount == 0:
        raise ParseError("decode_error", "DNS message declares no sections")

    opcode = (flags >> 11) & 0x0F
    rcode = flags & 0x0F
    message = DnsMessage(
        kind="response" if flags & 0x8000 else "query",
        id=identifier,
        flags=DnsFlags(
            qr=bool(flags & 0x8000),
            opcode=opcode,
            aa=bool(flags & 0x0400),
            tc=bool(flags & 0x0200),
            rd=bool(flags & 0x0100),
            ra=bool(flags & 0x0080),
            z=bool(flags & 0x0040),
            ad=bool(flags & 0x0020),
            cd=bool(flags & 0x0010),
            rcode=rcode,
        ),
        opcode=opcode,
        opcode_name=OPCODES.get(opcode, f"OPCODE{opcode}"),
        rcode=rcode,
        rcode_name=RCODES.get(rcode, f"RCODE{rcode}"),
        counts=DnsCounts(
            questions=qdcount, answers=ancount, authorities=nscount, additionals=arcount
        ),
        tcp=tcp,
    )

    offset = HEADER_LENGTH
    for _ in range(qdcount):
        name, offset = read_name(data, offset)
        if offset + 4 > len(data):
            raise ParseError("truncated_packet", "DNS question truncated", offset=offset)
        qtype, qclass = struct.unpack_from("!HH", data, offset)
        offset += 4
        message.questions.append(
            DnsQuestion(
                name=name,
                type=qtype,
                type_name=type_name(qtype),
                class_=qclass,
                class_name=class_name(qclass),
            )
        )

    for section, count in (
        (message.answers, ancount),
        (message.authorities, nscount),
        (message.additionals, arcount),
    ):
        for _ in range(count):
            record, offset = _read_record(data, offset, issues.stage)
            section.append(record)
    return message


def _plausible_name(name: str | None) -> bool:
    if not name or name == ".":
        return False
    return all(
        PLAUSIBLE_LABEL.match(label.encode("latin-1", "replace"))
        for label in name.rstrip(".").split(".")
        if label
    )


def score(payload: bytes, tcp: bool) -> tuple[float, str | None]:
    if tcp:
        if len(payload) < HEADER_LENGTH + 2:
            return 0.0, None
        declared = int.from_bytes(payload[:2], "big")
        if declared < HEADER_LENGTH or declared + 2 > len(payload):
            return 0.0, None
    elif len(payload) < HEADER_LENGTH:
        return 0.0, None

    try:
        message = parse(payload, tcp=tcp, issues=Issues("detect"))
    except ParseError:
        return 0.0, None

    if message.opcode not in OPCODES:
        return 0.2, "DNS header with an unknown opcode"

    confidence = 0.45
    evidence = ["DNS header"]
    if message.questions:
        question = message.questions[0]
        if _plausible_name(question.name):
            confidence += 0.25
            evidence.append("plausible question name")
        if question.type in QTYPES:
            confidence += 0.15
            evidence.append(f"known qtype {question.type_name}")
        if question.class_ in QCLASSES:
            confidence += 0.05
    if message.kind == "response" and message.counts.answers:
        confidence += 0.10
        evidence.append("response with answers")
    return min(confidence, 1.0), ", ".join(evidence)
```

- [ ] **Step 4: Point the legacy detector at `dns.score`**

`dns.parse` now needs `issues` and returns a dataclass, so the legacy `dns_score` cannot stay. Replace `ids/parsers/detector.py` with:

```python
from __future__ import annotations

import re
from collections import namedtuple

from . import dns, http, smtp

STANDARD_PORTS = {
    53: "DNS",
    80: "HTTP",
    465: "SMTP",
    587: "SMTP",
    2525: "SMTP",
    3128: "HTTP",
    8000: "HTTP",
    8008: "HTTP",
    8080: "HTTP",
    8081: "HTTP",
    8888: "HTTP",
    9080: "HTTP",
    5353: "DNS",
    25: "SMTP",
}

PROTOCOLS = ("HTTP", "DNS", "SMTP")
PORT_BOOST = 0.25
MIN_CONFIDENCE = 0.5
PORT_ONLY_CONFIDENCE = 0.3

SMTP_CODES = frozenset(
    (
        211,
        214,
        220,
        221,
        250,
        251,
        252,
        354,
        421,
        450,
        451,
        452,
        455,
        500,
        501,
        502,
        503,
        504,
        530,
        532,
        550,
        551,
        552,
        553,
        554,
        555,
    )
)

SMTP_HELLO = re.compile(rb"^(?:HELO|EHLO)[ \t]+\S", re.IGNORECASE)
SMTP_PATH = re.compile(rb"^(?:MAIL|RCPT)[ \t]+(?:FROM|TO)[ \t]*:", re.IGNORECASE)
SMTP_VERB = re.compile(
    rb"^(?:DATA|QUIT|RSET|NOOP|VRFY|EXPN|HELP|AUTH|STARTTLS|BDAT|ETRN)(?:[ \t]|$)", re.IGNORECASE
)
SMTP_STATUS_LINE = re.compile(rb"^([2-5]\d{2})([ -]|$)")

Detection = namedtuple(
    "Detection", "protocol method confidence port_matched port_hint evidence scores"
)


def smtp_score(payload: bytes) -> tuple[float, str | None]:
    line = smtp.first_line(payload[:512])
    if SMTP_HELLO.match(line):
        return 0.95, "SMTP HELO/EHLO command"
    if SMTP_PATH.match(line):
        return 0.95, "SMTP MAIL/RCPT path"
    status = SMTP_STATUS_LINE.match(line)
    if status:
        code = int(status.group(1))
        if status.group(2) == b"-" or code in SMTP_CODES:
            return 0.85, f"SMTP status code {code}"
        return 0.45, f"numeric status line {code}"
    if SMTP_VERB.match(line):
        return 0.7, "SMTP verb"
    return 0.0, None


def detect(payload: bytes, *, src_port=None, dst_port=None, tcp: bool = False) -> Detection:
    if not payload:
        return Detection("UNKNOWN", "none", 0.0, False, None, "no payload to inspect", {})

    scores: dict[str, float] = {}
    evidence: dict[str, str | None] = {}
    for name, (score, why) in (
        ("HTTP", http.score(payload, tcp)),
        ("DNS", dns.score(payload, tcp)),
        ("SMTP", smtp_score(payload)),
    ):
        scores[name] = score
        evidence[name] = why

    hints = [STANDARD_PORTS[port] for port in (src_port, dst_port) if port in STANDARD_PORTS]
    port_hint = hints[0] if hints else None
    if port_hint:
        scores[port_hint] = min(scores[port_hint] + PORT_BOOST, 1.0)

    best = max(PROTOCOLS, key=lambda name: scores[name])
    payload_matched = evidence[best] is not None
    port_matched = port_hint == best

    if scores[best] >= MIN_CONFIDENCE:
        if payload_matched and port_matched:
            method = "port+payload"
        elif payload_matched:
            method = "payload"
        else:
            method = "port"
        return Detection(
            best,
            method,
            round(scores[best], 2),
            port_matched,
            port_hint,
            evidence[best],
            {name: round(value, 2) for name, value in scores.items()},
        )

    if port_hint:
        return Detection(
            port_hint,
            "port",
            PORT_ONLY_CONFIDENCE,
            True,
            port_hint,
            "standard port with no recognisable signature",
            {name: round(value, 2) for name, value in scores.items()},
        )

    return Detection(
        "UNKNOWN",
        "none",
        0.0,
        False,
        None,
        "no signature matched and no standard port",
        {name: round(value, 2) for name, value in scores.items()},
    )
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_dns.py tests/test_detector.py -q`
Expected: `57 passed`.

- [ ] **Step 6: Lint**

Run: `uv run ruff check ids/parsers/dns.py ids/parsers/detector.py tests/test_dns.py && uv run ruff format --check ids/parsers/dns.py ids/parsers/detector.py tests/test_dns.py`
Expected: `All checks passed!` then `3 files already formatted`.

- [ ] **Step 7: Commit**

```bash
git add ids/parsers/dns.py ids/parsers/detector.py tests/test_dns.py
git commit -m "refactor: move the dns parser and its detector score onto the typed model"
```

---

### Task 6: SMTP parser on the typed model, one command set for parse and score

**Files:**
- Modify (full rewrite): `ids/parsers/smtp.py`
- Modify: `ids/parsers/detector.py` (transitional: SMTP scoring now comes from `smtp.score`)
- Test (full rewrite): `tests/test_smtp.py`
- Test (unchanged, must stay green): `tests/test_detector.py`

**Interfaces:**
- Consumes: `ids.issues.Issues`, `ParseError`; `ids.model.SmtpSession`, `SmtpCommand`, `SmtpReply`.
- Produces:
  - `NAME = "SMTP"`, `PORTS = frozenset((25, 465, 587, 2525))`, `COMMANDS: frozenset[str]` (includes `TURN`), `REPLY_CODES`, `MAX_LINE = 4096`, `MAX_UNPARSED = 10`.
  - `def parse(payload: bytes, *, tcp: bool, issues: Issues) -> SmtpSession` — empty payload → `ParseError("decode_error", …)`; otherwise never raises; `kind` ∈ `"command"`, `"response"`, `"mixed"`, `"data"`; `incomplete_reply` added via `issues` when the last reply is a continuation.
  - `def score(payload: bytes, tcp: bool) -> tuple[float, str | None]` — `0.95` HELO/EHLO with argument, `0.95` MAIL/RCPT path, `0.85` known code or continuation line (200–599), `0.45` other 200–599 code, `0.7` any `COMMANDS` verb, else `(0.0, None)`.
  - `def first_line(data: bytes) -> bytes`.

- [ ] **Step 1: Write the failing test**

Replace `tests/test_smtp.py` with:

```python
import pytest
from golden import (
    SMTP_EHLO,
    SMTP_GREETING,
    SMTP_MAIL_FROM,
    SMTP_MULTILINE,
    SMTP_RCPT_TO,
    SMTP_REJECT,
)

from ids.issues import Issue, Issues, ParseError
from ids.model import SmtpReply
from ids.parsers.smtp import COMMANDS, MAX_UNPARSED, first_line, parse, score


def parse_smtp(payload, issues=None):
    return parse(payload, tcp=True, issues=issues if issues is not None else Issues("application"))


def test_ehlo_command():
    session = parse_smtp(SMTP_EHLO)
    assert session.kind == "command"
    assert session.command == "EHLO"
    assert session.commands[0].verb == "EHLO"
    assert session.commands[0].arguments == "client.example.test"
    assert session.commands[0].domain == "client.example.test"
    assert session.replies == []
    assert session.status_code is None


def test_helo_is_accepted_like_ehlo():
    session = parse_smtp(b"helo relay.test\r\n")
    assert session.commands[0].verb == "HELO"
    assert session.commands[0].domain == "relay.test"


def test_mail_from_extracts_address_and_parameters():
    session = parse_smtp(SMTP_MAIL_FROM)
    assert session.command == "MAIL"
    assert session.mail_from == "alice@example.test"
    assert session.commands[0].parameters == ["SIZE=1024"]
    assert session.commands[0].path == "<alice@example.test> SIZE=1024"


def test_mail_from_without_angle_brackets():
    session = parse_smtp(b"MAIL FROM: alice@example.test BODY=8BITMIME\r\n")
    assert session.mail_from == "alice@example.test"
    assert session.commands[0].parameters == ["BODY=8BITMIME"]


def test_mail_from_with_empty_reverse_path():
    assert parse_smtp(b"MAIL FROM:<>\r\n").mail_from == ""


def test_rcpt_to_extracts_address():
    session = parse_smtp(SMTP_RCPT_TO)
    assert session.command == "RCPT"
    assert session.rcpt_to == ["bob@example.test"]


def test_rcpt_without_a_path_adds_no_recipient():
    session = parse_smtp(b"RCPT bob\r\n")
    assert session.commands[0].verb == "RCPT"
    assert session.commands[0].address is None
    assert session.rcpt_to == []


def test_pipelined_commands_in_one_segment():
    session = parse_smtp(
        b"MAIL FROM:<a@b.test>\r\nRCPT TO:<c@d.test>\r\nRCPT TO:<e@f.test>\r\nDATA\r\n"
    )
    assert [command.verb for command in session.commands] == ["MAIL", "RCPT", "RCPT", "DATA"]
    assert session.mail_from == "a@b.test"
    assert session.rcpt_to == ["c@d.test", "e@f.test"]


def test_greeting_status_code():
    session = parse_smtp(SMTP_GREETING)
    assert session.kind == "response"
    assert session.status_code == 220
    assert session.replies[0].text == "mail.example.test ESMTP Postfix"
    assert session.last_status_code == 220
    assert session.command is None


def test_reply_without_text_is_accepted():
    session = parse_smtp(b"250\r\n")
    assert session.kind == "response"
    assert session.replies == [SmtpReply(code=250, text="", lines=[""], continuation=False)]


def test_multiline_reply_is_joined_into_one_reply():
    issues = Issues("application")
    session = parse_smtp(SMTP_MULTILINE, issues)
    assert len(session.replies) == 1
    assert session.status_code == 250
    reply = session.replies[0]
    assert reply.continuation is False
    assert reply.lines == ["mail.example.test", "PIPELINING", "SIZE 10240000", "AUTH LOGIN PLAIN"]
    assert reply.text == "mail.example.test\nPIPELINING\nSIZE 10240000\nAUTH LOGIN PLAIN"
    assert issues.records == []


def test_first_and_last_status_codes_differ_across_replies():
    session = parse_smtp(b"250 ok\r\n354 go ahead\r\n")
    assert [reply.code for reply in session.replies] == [250, 354]
    assert session.status_code == 250
    assert session.last_status_code == 354


def test_rejection_status_code():
    session = parse_smtp(SMTP_REJECT)
    assert session.status_code == 550
    assert "Recipient address rejected" in session.replies[0].text


def test_command_and_reply_in_one_payload_is_mixed():
    session = parse_smtp(b"220 hi\r\nEHLO me\r\n")
    assert session.kind == "mixed"
    assert session.command == "EHLO"
    assert session.status_code == 220


def test_incomplete_multiline_reply_is_reported():
    issues = Issues("application")
    session = parse_smtp(b"250-first\r\n250-second\r\n", issues)
    assert session.replies[0].continuation is True
    assert session.replies[0].lines == ["first", "second"]
    assert issues.records == [
        Issue(
            "application",
            "incomplete_reply",
            "last SMTP reply uses a continuation code with no terminating line",
            {},
        )
    ]


def test_auth_mechanism_is_captured():
    session = parse_smtp(b"AUTH plain AGFsaWNlAHNlY3JldA==\r\n")
    assert session.commands[0].mechanism == "PLAIN"
    assert session.commands[0].credentials_present is True


def test_auth_without_initial_response_has_no_credentials():
    session = parse_smtp(b"AUTH LOGIN\r\n")
    assert session.commands[0].mechanism == "LOGIN"
    assert session.commands[0].credentials_present is None


def test_message_body_lines_are_collected_as_unparsed():
    session = parse_smtp(b"220 hi\r\nSubject: test\r\n\r\nbody line\r\n")
    assert session.status_code == 220
    assert session.unparsed_lines == ["Subject: test", "body line"]


def test_unknown_verb_is_unparsed_not_an_error():
    session = parse_smtp(b"220 ok\r\nFROBNICATE now\r\n")
    assert session.status_code == 220
    assert session.unparsed_lines == ["FROBNICATE now"]


def test_turn_is_a_command():
    session = parse_smtp(b"TURN\r\n")
    assert session.kind == "command"
    assert session.command == "TURN"


def test_data_phase_content_is_kind_data():
    issues = Issues("application")
    payload = b"Subject: hi\r\nMIME-Version: 1.0\r\n\r\nHello Bob\r\n.\r\n"
    session = parse_smtp(payload, issues)
    assert session.kind == "data"
    assert session.commands == []
    assert session.replies == []
    assert session.unparsed_lines == ["Subject: hi", "MIME-Version: 1.0", "Hello Bob", "."]
    assert issues.records == []


def test_unparsed_lines_are_capped():
    payload = b"".join(b"line %d\r\n" % index for index in range(MAX_UNPARSED + 5))
    session = parse_smtp(payload)
    assert session.kind == "data"
    assert len(session.unparsed_lines) == MAX_UNPARSED
    assert session.unparsed_lines[-1] == f"line {MAX_UNPARSED - 1}"


@pytest.mark.parametrize("payload", [b"\x00\x01\x02\x03", b"random text here", b"999 nope\r\n"])
def test_non_smtp_payloads_are_data_not_errors(payload):
    session = parse_smtp(payload)
    assert session.kind == "data"
    assert session.commands == []
    assert session.replies == []
    assert session.unparsed_lines == [payload.rstrip(b"\r\n").decode("latin-1")]


def test_empty_payload_raises_decode_error():
    with pytest.raises(ParseError) as caught:
        parse_smtp(b"")
    assert caught.value.code == "decode_error"


def test_first_line_helper():
    assert first_line(SMTP_EHLO) == b"EHLO client.example.test"
    assert first_line(b"220 hi") == b"220 hi"


@pytest.mark.parametrize(
    "payload,expected",
    [
        (SMTP_EHLO, (0.95, "SMTP HELO/EHLO command")),
        (SMTP_MAIL_FROM, (0.95, "SMTP MAIL/RCPT path")),
        (SMTP_GREETING, (0.85, "SMTP status code 220")),
        (b"299-first\r\n", (0.85, "SMTP status code 299")),
        (b"299 numeric\r\n", (0.45, "numeric status line 299")),
        (b"199 too low\r\n", (0.0, None)),
        (b"QUIT\r\n", (0.7, "SMTP verb")),
        (b"hello world\r\n", (0.0, None)),
    ],
)
def test_score_tiers(payload, expected):
    assert score(payload, True) == expected


@pytest.mark.parametrize("verb", sorted(COMMANDS))
def test_every_parsed_verb_scores_as_smtp(verb):
    payload = verb.encode() + b"\r\n"
    assert score(payload, True)[0] >= 0.7
    assert parse_smtp(payload).command == verb
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_smtp.py -q`
Expected: collection error `ImportError: cannot import name 'score' from 'ids.parsers.smtp'`.

- [ ] **Step 3: Write the implementation**

Replace `ids/parsers/smtp.py` with:

```python
from __future__ import annotations

import re

from ..issues import Issues, ParseError
from ..model import SmtpCommand, SmtpReply, SmtpSession

NAME = "SMTP"
PORTS = frozenset((25, 465, 587, 2525))

COMMANDS = frozenset(
    (
        "HELO",
        "EHLO",
        "MAIL",
        "RCPT",
        "DATA",
        "QUIT",
        "RSET",
        "NOOP",
        "VRFY",
        "EXPN",
        "HELP",
        "AUTH",
        "STARTTLS",
        "BDAT",
        "TURN",
        "ETRN",
    )
)

REPLY_CODES = frozenset(
    (
        211,
        214,
        220,
        221,
        250,
        251,
        252,
        354,
        421,
        450,
        451,
        452,
        455,
        500,
        501,
        502,
        503,
        504,
        530,
        532,
        550,
        551,
        552,
        553,
        554,
        555,
    )
)

REPLY_LINE = re.compile(rb"^(\d{3})(?:([ -])(.*))?$")
COMMAND_LINE = re.compile(rb"^([A-Za-z]{3,10})(?:[ \t]+(.*))?$")
HELLO_LINE = re.compile(rb"^(?:HELO|EHLO)[ \t]+\S", re.IGNORECASE)
PATH_LINE = re.compile(rb"^(MAIL|RCPT)[ \t]+(?:FROM|TO)[ \t]*:[ \t]*(.*)$", re.IGNORECASE)
AUTH_LINE = re.compile(rb"^AUTH[ \t]+(\S+)(?:[ \t]+(.*))?$", re.IGNORECASE)
VERB_LINE = re.compile(
    rb"^(?:" + rb"|".join(sorted(verb.encode("ascii") for verb in COMMANDS)) + rb")(?:[ \t]|$)",
    re.IGNORECASE,
)
ADDRESS = re.compile(rb"<([^>]*)>")

MAX_LINE = 4096
MAX_UNPARSED = 10
SCORE_WINDOW = 512


def first_line(data: bytes) -> bytes:
    index = data.find(b"\n")
    line = data if index < 0 else data[:index]
    return line.rstrip(b"\r")


def score(payload: bytes, tcp: bool) -> tuple[float, str | None]:
    line = first_line(payload[:SCORE_WINDOW])
    if HELLO_LINE.match(line):
        return 0.95, "SMTP HELO/EHLO command"
    if PATH_LINE.match(line):
        return 0.95, "SMTP MAIL/RCPT path"
    reply = REPLY_LINE.match(line)
    if reply:
        code = int(reply.group(1))
        if 200 <= code <= 599:
            if reply.group(2) == b"-" or code in REPLY_CODES:
                return 0.85, f"SMTP status code {code}"
            return 0.45, f"numeric status line {code}"
    if VERB_LINE.match(line):
        return 0.7, "SMTP verb"
    return 0.0, None


def _lines(data: bytes) -> list[bytes]:
    lines = []
    for raw in data.split(b"\n"):
        raw = raw.rstrip(b"\r")
        if raw:
            lines.append(raw[:MAX_LINE])
    return lines


def _command(verb: str, arguments: str, raw: bytes) -> SmtpCommand:
    command = SmtpCommand(verb=verb, arguments=arguments)
    path = PATH_LINE.match(raw)
    if path:
        address = ADDRESS.search(raw)
        if address:
            command.address = address.group(1).decode("latin-1")
            tail = raw[address.end() :].decode("latin-1").strip()
            command.parameters = tail.split() if tail else []
        else:
            tokens = path.group(2).decode("latin-1").split()
            command.address = tokens[0] if tokens else ""
            command.parameters = tokens[1:]
        command.path = path.group(2).decode("latin-1").strip()
    elif verb in ("HELO", "EHLO"):
        command.domain = arguments
    elif verb == "AUTH":
        auth = AUTH_LINE.match(raw)
        if auth:
            command.mechanism = auth.group(1).decode("latin-1").upper()
            if auth.group(2):
                command.credentials_present = True
    return command


def parse(payload: bytes, *, tcp: bool, issues: Issues) -> SmtpSession:
    if not payload:
        raise ParseError("decode_error", "SMTP payload is empty")

    session = SmtpSession()
    for raw in _lines(payload):
        reply = REPLY_LINE.match(raw)
        if reply and 100 <= int(reply.group(1)) <= 599:
            code = int(reply.group(1))
            text = (reply.group(3) or b"").decode("latin-1")
            continuation = reply.group(2) == b"-"
            if session.replies and session.replies[-1].continuation:
                last = session.replies[-1]
                last.lines.append(text)
                last.code = code
                last.continuation = continuation
            else:
                session.replies.append(
                    SmtpReply(code=code, lines=[text], continuation=continuation)
                )
            continue
        command = COMMAND_LINE.match(raw)
        if command:
            verb = command.group(1).decode("latin-1").upper()
            if verb in COMMANDS:
                arguments = (command.group(2) or b"").decode("latin-1").strip()
                session.commands.append(_command(verb, arguments, raw))
                continue
        if len(session.unparsed_lines) < MAX_UNPARSED:
            session.unparsed_lines.append(raw.decode("latin-1"))

    for reply in session.replies:
        reply.text = "\n".join(reply.lines)

    if session.commands and session.replies:
        session.kind = "mixed"
    elif session.commands:
        session.kind = "command"
    elif session.replies:
        session.kind = "response"
    else:
        session.kind = "data"

    if session.commands:
        session.command = session.commands[0].verb
    if session.replies:
        session.status_code = session.replies[0].code
        session.last_status_code = session.replies[-1].code
        if session.replies[-1].continuation:
            issues.add(
                "incomplete_reply",
                "last SMTP reply uses a continuation code with no terminating line",
            )

    for command in session.commands:
        if command.address is None:
            continue
        if command.verb == "MAIL":
            session.mail_from = command.address
        elif command.verb == "RCPT":
            session.rcpt_to.append(command.address)
    return session
```

- [ ] **Step 4: Point the legacy detector at `smtp.score`**

Replace `ids/parsers/detector.py` with this last transitional version (all scoring now lives in the protocol modules; Task 7 replaces the namedtuple and the port table):

```python
from __future__ import annotations

from collections import namedtuple

from . import dns, http, smtp

STANDARD_PORTS = {
    53: "DNS",
    80: "HTTP",
    465: "SMTP",
    587: "SMTP",
    2525: "SMTP",
    3128: "HTTP",
    8000: "HTTP",
    8008: "HTTP",
    8080: "HTTP",
    8081: "HTTP",
    8888: "HTTP",
    9080: "HTTP",
    5353: "DNS",
    25: "SMTP",
}

PROTOCOLS = ("HTTP", "DNS", "SMTP")
PORT_BOOST = 0.25
MIN_CONFIDENCE = 0.5
PORT_ONLY_CONFIDENCE = 0.3

Detection = namedtuple(
    "Detection", "protocol method confidence port_matched port_hint evidence scores"
)


def detect(payload: bytes, *, src_port=None, dst_port=None, tcp: bool = False) -> Detection:
    if not payload:
        return Detection("UNKNOWN", "none", 0.0, False, None, "no payload to inspect", {})

    scores: dict[str, float] = {}
    evidence: dict[str, str | None] = {}
    for name, (score, why) in (
        ("HTTP", http.score(payload, tcp)),
        ("DNS", dns.score(payload, tcp)),
        ("SMTP", smtp.score(payload, tcp)),
    ):
        scores[name] = score
        evidence[name] = why

    hints = [STANDARD_PORTS[port] for port in (src_port, dst_port) if port in STANDARD_PORTS]
    port_hint = hints[0] if hints else None
    if port_hint:
        scores[port_hint] = min(scores[port_hint] + PORT_BOOST, 1.0)

    best = max(PROTOCOLS, key=lambda name: scores[name])
    payload_matched = evidence[best] is not None
    port_matched = port_hint == best

    if scores[best] >= MIN_CONFIDENCE:
        if payload_matched and port_matched:
            method = "port+payload"
        elif payload_matched:
            method = "payload"
        else:
            method = "port"
        return Detection(
            best,
            method,
            round(scores[best], 2),
            port_matched,
            port_hint,
            evidence[best],
            {name: round(value, 2) for name, value in scores.items()},
        )

    if port_hint:
        return Detection(
            port_hint,
            "port",
            PORT_ONLY_CONFIDENCE,
            True,
            port_hint,
            "standard port with no recognisable signature",
            {name: round(value, 2) for name, value in scores.items()},
        )

    return Detection(
        "UNKNOWN",
        "none",
        0.0,
        False,
        None,
        "no signature matched and no standard port",
        {name: round(value, 2) for name, value in scores.items()},
    )
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_smtp.py tests/test_detector.py -q`
Expected: `74 passed`.

- [ ] **Step 6: Lint**

Run: `uv run ruff check ids/parsers/smtp.py ids/parsers/detector.py tests/test_smtp.py && uv run ruff format --check ids/parsers/smtp.py ids/parsers/detector.py tests/test_smtp.py`
Expected: `All checks passed!` then `3 files already formatted`.

- [ ] **Step 7: Commit**

```bash
git add ids/parsers/smtp.py ids/parsers/detector.py tests/test_smtp.py
git commit -m "refactor: move the smtp parser onto the typed model and share its grammar with the detector"
```

---

### Task 7: Protocol registry and typed detector

**Files:**
- Create: `ids/parsers/registry.py`
- Modify (full rewrite): `ids/parsers/detector.py`
- Test (full rewrite): `tests/test_detector.py`
- Test (create): `tests/test_registry.py`

**Interfaces:**
- Consumes: Tasks 4–6 module attributes `NAME`, `PORTS`, `score(payload, tcp)`, `parse(payload, *, tcp, issues)` of `ids.parsers.http`, `dns`, `smtp`; `ids.model.Detection`; `ids.model.event.UNKNOWN`.
- Produces:
  - `@dataclass(frozen=True, slots=True) class AppProtocol: name: str; ports: frozenset[int]; score: Callable[[bytes, bool], tuple[float, str | None]]; parse: Callable[..., HttpMessage | DnsMessage | SmtpSession]`
  - `PROTOCOLS: tuple[AppProtocol, ...]` in order HTTP, DNS, SMTP; `STANDARD_PORTS: dict[int, str]` derived from `PROTOCOLS`; `def by_name(name: str) -> AppProtocol | None`.
  - `def detect(payload: bytes, *, src_port: int | None, dst_port: int | None, tcp: bool) -> Detection`; `PORT_BOOST = 0.25`, `MIN_CONFIDENCE = 0.5`, `PORT_ONLY_CONFIDENCE = 0.3`. `method` ∈ `"port+payload"`, `"payload"`, `"port"`, `"none"`; `scores` keyed in `PROTOCOLS` order, rounded to 2 decimals (`{}` for an empty payload); the source port's hint wins over the destination port's; ties go to the earlier protocol.
  - Plan 1c's `PacketParser` uses `detect(...)` then `by_name(detection.protocol).parse(payload, tcp=..., issues=issues.scoped("application"))`.

- [ ] **Step 1: Write the failing tests**

Replace `tests/test_detector.py` with:

```python
import pytest
from golden import (
    DNS_ANSWER,
    DNS_QUERY,
    HTTP_GET,
    HTTP_RESPONSE,
    SMTP_EHLO,
    SMTP_GREETING,
    SMTP_MAIL_FROM,
)

from ids.model import Detection
from ids.parsers.detector import PORT_ONLY_CONFIDENCE, detect

NOISE = bytes(range(256))
TLS_CLIENT_HELLO = b"\x16\x03\x01\x00\x2c\x01\x00\x00\x28\x03\x03" + bytes(range(32))


def test_http_on_the_standard_port():
    result = detect(HTTP_GET, src_port=51234, dst_port=80, tcp=True)
    assert isinstance(result, Detection)
    assert result.protocol == "HTTP"
    assert result.method == "port+payload"
    assert result.port_matched is True
    assert result.port_hint == "HTTP"
    assert result.confidence == 1.0


def test_http_on_an_alternative_standard_port():
    result = detect(HTTP_GET, src_port=51234, dst_port=8080, tcp=True)
    assert result.protocol == "HTTP"
    assert result.method == "port+payload"


def test_http_on_a_non_standard_port_is_detected_from_the_payload():
    result = detect(HTTP_GET, src_port=51234, dst_port=9999, tcp=True)
    assert result.protocol == "HTTP"
    assert result.method == "payload"
    assert result.port_matched is False
    assert result.port_hint is None
    assert result.confidence >= 0.9
    assert "request line" in result.evidence


def test_http_response_on_a_non_standard_port():
    result = detect(HTTP_RESPONSE, src_port=44321, dst_port=51234, tcp=True)
    assert result.protocol == "HTTP"
    assert result.method == "payload"


def test_bare_method_token_is_a_weaker_http_signal():
    result = detect(b"GET /index.html\r\n", src_port=51234, dst_port=9999, tcp=True)
    assert result.protocol == "HTTP"
    assert 0.5 <= result.confidence < 0.9


def test_dns_query_on_the_standard_port():
    result = detect(DNS_QUERY, src_port=40000, dst_port=53, tcp=False)
    assert result.protocol == "DNS"
    assert result.method == "port+payload"
    assert result.confidence == 1.0


def test_dns_query_on_a_non_standard_port():
    result = detect(DNS_QUERY, src_port=40000, dst_port=15353, tcp=False)
    assert result.protocol == "DNS"
    assert result.method == "payload"
    assert result.confidence == 0.9
    assert "plausible question name" in result.evidence
    assert "known qtype A" in result.evidence


def test_dns_response_reports_answers_as_evidence():
    result = detect(DNS_ANSWER, src_port=53, dst_port=40000, tcp=False)
    assert result.protocol == "DNS"
    assert "response with answers" in result.evidence


def test_dns_over_tcp_needs_the_length_prefix():
    prefixed = len(DNS_QUERY).to_bytes(2, "big") + DNS_QUERY
    assert detect(prefixed, src_port=40000, dst_port=5353, tcp=True).protocol == "DNS"
    assert detect(DNS_QUERY, src_port=40000, dst_port=5353, tcp=True).method == "port"


def test_smtp_commands_and_replies():
    assert detect(SMTP_EHLO, src_port=40000, dst_port=25, tcp=True).protocol == "SMTP"
    assert detect(SMTP_GREETING, src_port=25, dst_port=40000, tcp=True).protocol == "SMTP"
    mail = detect(SMTP_MAIL_FROM, src_port=40000, dst_port=2526, tcp=True)
    assert mail.protocol == "SMTP"
    assert mail.method == "payload"


def test_numeric_status_line_without_a_known_code():
    result = detect(b"299 numeric\r\n", src_port=40000, dst_port=25, tcp=True)
    assert result.protocol == "SMTP"
    assert result.confidence == 0.7


def test_weak_numeric_status_line_needs_the_port_hint():
    assert detect(b"299 numeric\r\n", src_port=40000, dst_port=4444, tcp=True).protocol == "UNKNOWN"
    strong = detect(b"250 ok\r\n", src_port=40000, dst_port=4444, tcp=True)
    assert strong.protocol == "SMTP"
    assert strong.method == "payload"


def test_turn_is_detected_like_every_other_smtp_verb():
    result = detect(b"TURN\r\n", src_port=40000, dst_port=4444, tcp=True)
    assert result.protocol == "SMTP"
    assert result.method == "payload"
    assert result.confidence == 0.7


def test_random_bytes_on_http_port_are_only_a_port_guess():
    result = detect(NOISE, src_port=51234, dst_port=80, tcp=True)
    assert result.protocol == "HTTP"
    assert result.method == "port"
    assert result.confidence == PORT_ONLY_CONFIDENCE
    assert result.evidence == "standard port with no recognisable signature"
    assert result.scores["HTTP"] == 0.25


def test_source_port_hint_wins_over_destination_port_hint():
    result = detect(b"hello world\r\n", src_port=53, dst_port=80, tcp=False)
    assert result.port_hint == "DNS"
    assert result.protocol == "DNS"
    assert result.method == "port"


def test_payload_signature_beats_a_port_hint_for_another_protocol():
    result = detect(SMTP_EHLO, src_port=40000, dst_port=80, tcp=True)
    assert result.protocol == "SMTP"
    assert result.method == "payload"
    assert result.port_matched is False
    assert result.port_hint == "HTTP"


def test_random_bytes_on_an_unknown_port_stay_unknown():
    result = detect(NOISE, src_port=51234, dst_port=9999, tcp=True)
    assert result.protocol == "UNKNOWN"
    assert result.method == "none"
    assert result.port_hint is None
    assert result.evidence == "no signature matched and no standard port"


def test_missing_ports_fall_back_to_payload_only():
    result = detect(NOISE, src_port=None, dst_port=None, tcp=False)
    assert result.protocol == "UNKNOWN"
    assert result.port_hint is None


def test_empty_payload_is_never_attributed_to_a_protocol():
    result = detect(b"", src_port=51234, dst_port=80, tcp=True)
    assert result.protocol == "UNKNOWN"
    assert result.method == "none"
    assert result.confidence == 0.0
    assert result.evidence == "no payload to inspect"
    assert result.scores == {}


def test_tls_on_443_is_not_mistaken_for_http():
    result = detect(TLS_CLIENT_HELLO, src_port=51234, dst_port=443, tcp=True)
    assert result.protocol == "UNKNOWN"


def test_plain_text_on_an_unknown_port_is_unknown():
    assert (
        detect(b"hello world\r\n", src_port=40000, dst_port=40001, tcp=True).protocol == "UNKNOWN"
    )


@pytest.mark.parametrize("payload", [NOISE, b"\x00" * 64, b"\xff" * 64, DNS_QUERY, HTTP_GET])
def test_scores_and_evidence_are_always_exposed(payload):
    result = detect(payload, src_port=1234, dst_port=5678, tcp=True)
    assert list(result.scores) == ["HTTP", "DNS", "SMTP"]
    assert all(0.0 <= score <= 1.0 for score in result.scores.values())
    assert result.protocol in {"HTTP", "DNS", "SMTP", "UNKNOWN"}
```

Create `tests/test_registry.py`:

```python
import pytest

from ids.issues import Issues
from ids.parsers.registry import PROTOCOLS, STANDARD_PORTS, by_name


def test_protocol_order_is_http_dns_smtp():
    assert [protocol.name for protocol in PROTOCOLS] == ["HTTP", "DNS", "SMTP"]


def test_standard_ports_cover_every_protocol_port_once():
    assert sum(len(protocol.ports) for protocol in PROTOCOLS) == len(STANDARD_PORTS)
    assert set(STANDARD_PORTS.values()) == {"HTTP", "DNS", "SMTP"}


@pytest.mark.parametrize(
    "port,name",
    [
        (80, "HTTP"),
        (8080, "HTTP"),
        (3128, "HTTP"),
        (53, "DNS"),
        (5353, "DNS"),
        (25, "SMTP"),
        (587, "SMTP"),
    ],
)
def test_well_known_ports(port, name):
    assert STANDARD_PORTS[port] == name


def test_by_name_returns_a_protocol_that_parses_its_payload():
    smtp = by_name("SMTP")
    assert smtp is not None
    session = smtp.parse(b"EHLO client.test\r\n", tcp=True, issues=Issues("application"))
    assert session.kind == "command"
    assert smtp.score(b"EHLO client.test\r\n", True)[0] == 0.95


@pytest.mark.parametrize("name", ["FTP", "http", "", "UNKNOWN"])
def test_by_name_rejects_unknown_names(name):
    assert by_name(name) is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_detector.py tests/test_registry.py -q`
Expected: collection error `ModuleNotFoundError: No module named 'ids.parsers.registry'`.

- [ ] **Step 3: Write the registry**

Create `ids/parsers/registry.py`:

```python
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
```

- [ ] **Step 4: Rewrite the detector**

Replace `ids/parsers/detector.py` with:

```python
from __future__ import annotations

from ..model import Detection
from ..model.event import UNKNOWN
from .registry import PROTOCOLS, STANDARD_PORTS

PORT_BOOST = 0.25
MIN_CONFIDENCE = 0.5
PORT_ONLY_CONFIDENCE = 0.3


def _rounded(scores: dict[str, float]) -> dict[str, float]:
    return {name: round(value, 2) for name, value in scores.items()}


def detect(payload: bytes, *, src_port: int | None, dst_port: int | None, tcp: bool) -> Detection:
    if not payload:
        return Detection(
            protocol=UNKNOWN,
            method="none",
            confidence=0.0,
            port_matched=False,
            evidence="no payload to inspect",
        )

    scores: dict[str, float] = {}
    evidence: dict[str, str | None] = {}
    for protocol in PROTOCOLS:
        scores[protocol.name], evidence[protocol.name] = protocol.score(payload, tcp)

    port_hint = STANDARD_PORTS.get(src_port) or STANDARD_PORTS.get(dst_port)
    if port_hint:
        scores[port_hint] = min(scores[port_hint] + PORT_BOOST, 1.0)

    best = max(scores, key=scores.__getitem__)
    if scores[best] >= MIN_CONFIDENCE:
        payload_matched = evidence[best] is not None
        port_matched = port_hint == best
        if payload_matched and port_matched:
            method = "port+payload"
        elif payload_matched:
            method = "payload"
        else:
            method = "port"
        return Detection(
            protocol=best,
            method=method,
            confidence=round(scores[best], 2),
            port_matched=port_matched,
            port_hint=port_hint,
            evidence=evidence[best],
            scores=_rounded(scores),
        )

    if port_hint:
        return Detection(
            protocol=port_hint,
            method="port",
            confidence=PORT_ONLY_CONFIDENCE,
            port_matched=True,
            port_hint=port_hint,
            evidence="standard port with no recognisable signature",
            scores=_rounded(scores),
        )

    return Detection(
        protocol=UNKNOWN,
        method="none",
        confidence=0.0,
        port_matched=False,
        evidence="no signature matched and no standard port",
        scores=_rounded(scores),
    )
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_detector.py tests/test_registry.py -q`
Expected: `40 passed`.

- [ ] **Step 6: Run every parser test file this plan owns**

Run: `uv run pytest tests/test_link.py tests/test_network.py tests/test_transport.py tests/test_http.py tests/test_dns.py tests/test_smtp.py tests/test_detector.py tests/test_registry.py -q`
Expected: `218 passed`.

- [ ] **Step 7: Lint**

Run: `uv run ruff check ids/parsers/registry.py ids/parsers/detector.py tests/test_detector.py tests/test_registry.py && uv run ruff format --check ids/parsers/registry.py ids/parsers/detector.py tests/test_detector.py tests/test_registry.py`
Expected: `All checks passed!` then `4 files already formatted`.

- [ ] **Step 8: Commit**

```bash
git add ids/parsers/registry.py ids/parsers/detector.py tests/test_detector.py tests/test_registry.py
git commit -m "feat: add the application protocol registry and typed detector"
```
