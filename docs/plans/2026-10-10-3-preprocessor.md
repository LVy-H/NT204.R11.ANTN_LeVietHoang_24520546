# Preprocessor Implementation Plan (plan 3)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `ids/preprocess/` — normalization, validation and the `PreprocessorStage` with `--invalid-policy` / `--unsupported-policy` — so every packet and message record leaves the runner with `normalized`, `preprocess_status`, `processing_action` and `reason` filled in.

**Architecture:** `normalize.py` holds pure functions that turn raw values into canonical ones and return normalization notes; `validate.py` applies the spec §8.1 rule table to a `PacketEvent` plus its `Normalized` and returns `(status, reasons, unsupported)`; `stage.py` combines the two, maps status to an action through the configured policies, grades `MessageEvent`s (spec §9.7) and is appended after the `DecoderStage` in `ids/cli.py:build_stages`. Raw fields are never written; only `normalized`, `preprocess_status`, `processing_action` and `reason` are set.

**Tech Stack:** Python ≥ 3.10 stdlib only (`ipaddress`, `encodings.idna` via `str.encode("idna")`, `datetime`, `urllib.parse`, `re`), pytest, ruff, uv.

**Spec:** `docs/specs/2026-10-10-decoder-preprocessor-flow-tracker.md` (§8, §9.7 last paragraph, §10.4, §11.3 T05/T06/T14) and `docs/plans/2026-10-10-interfaces.md` (§2 issues, §3.4 `Normalized*`, §3.6 events/enums, §5 codec, §7 `EventsSource`, §8 runner, §9 CLI, §10 `PreprocessConfig`/`PreprocessorStage`).

## Global Constraints

- `requires-python >= 3.10`; no 3.11+ APIs (`datetime.UTC`, `typing.Self`, `fromisoformat` accepting `Z` is 3.11+, so `Z` is replaced by hand).
- No new runtime dependencies; stdlib only.
- Every module starts with `from __future__ import annotations`.
- Names, types and signatures from the interfaces file are used verbatim: `Normalized`, `NormalizedHttp`, `NormalizedDns`, `NormalizedSmtp`, `PreprocessStatus`, `ProcessingAction`, `PacketEvent`, `MessageEvent`, `Issue`, `PreprocessConfig(invalid_policy="mark", unsupported_policy="mark", clock=time.time)`, `PreprocessorStage(config=None)` with `name = "preprocess"`.
- The Decoder and Preprocessor never change raw fields; results go to `event.normalized`, `event.preprocess_status`, `event.processing_action`, `event.reason`.
- `reason` is `[]` when the status is `valid`; every reason makes the status at least `partial`.
- `status`: invalid if any invalid rule fired, else partial if any partial rule fired, else valid (spec §8.1).
- Actions (spec §8.3): valid → `forward`; partial → `mark`; invalid → `--invalid-policy` `mark` (default) | `drop`; unsupported protocol → `--unsupported-policy` `mark` (default) | `drop`; `ProcessingAction.DROP` makes the Runner count the record as dropped and not write it.
- TCP/UDP events with application `UNKNOWN` are not unsupported; only `--unknown-policy skip` (plan 1c) suppresses their packet record.
- Stage order in `build_stages`: `[DecoderStage, PreprocessorStage, FlowTrackerStage]`.
- Lint: line length 100, ruff rules `E,F,W,I,UP,B,C4,SIM,RUF`, ignore `SIM108,SIM115,BLE001`.
- One task = one commit; commit messages lower-case conventional style.
- Green rule: `uv run pytest -q` passes after every commit of this plan.

## Contract details this plan relies on (confirmed with plans 1a/1c/2)

- `ids.codec.iso_timestamp(value: float | None) -> str | None` (plan 1a) = `datetime.fromtimestamp(value, timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")`, `None` for `None` or out-of-range values. `normalized.timestamp_iso` uses it so it never differs from the top-level `timestamp_iso`.
- `decode_packet` (plan 1a) converts a top-level ISO-8601 `timestamp` string to an epoch float (no issue), loads numbers unchanged (no ms scaling), and reports wrong types as `Issue("load", "invalid_type", …, {"field": <path>, "expected": …, "got": …})` with the field reset to its default. Paths: `packet_id`, `timestamp`, `network.src_ip`, `network.dst_ip`, `transport.src_port`, `transport.dst_port`; flat fallbacks `src_ip`, `dst_ip`, `src_port`, `dst_port`. Flat fallback: `Ipv4Info(protocol="IPv4", src_ip, dst_ip, protocol_name=<top-level "protocol">)` when `network` is absent and at least one of `src_ip`/`dst_ip` loads; `TcpInfo`/`UdpInfo(src_port, dst_port)` when `transport` is absent and `protocol` casefolds to tcp/udp. Union tags match case-insensitively and keep the raw text (`{"protocol": "tcp"}` → `TcpInfo(protocol="tcp")`).
- `EventsSource` (plan 1c) appends the load issues to `event.issues`, resets `normalized`, `preprocess_status`, `processing_action`, `reason`, `decoded`, `flow`; a non-JSON line becomes `PacketEvent(packet_id=<line number>)` with `Issue("load", "invalid_json", …)`.
- `DecoderStage` (plan 2): an HTTP event gets `DecodedHttp` with `uri` set for requests (`uri.path` is the percent-decoded path with any absolute-form `scheme://authority` removed, `""` when empty), `form`/`body` when present, each with a `status`. A MIME result has `DecodedMime.status` (worst part status).
- `ids/cli.py` after plan 2 imports `from .decoder import DecoderConfig, DecoderStage` and has
  `def build_stages(args): return [DecoderStage(DecoderConfig(max_decoded_bytes=args.max_decoded_bytes))]`.
- `Stats.to_dict()` (plan 1c) has integer keys `dropped` and `skipped`.

## Decisions taken in this plan

| Topic | Decision |
|---|---|
| Protocol names outside the canonical set | `canonical_protocol` returns them stripped and upper-cased (`icmp` → `ICMP`); empty/non-string → `None`. |
| `normalized.protocol` | Taken from the transport type (`TcpInfo` → `TCP`, `UdpInfo` → `UDP`); the codec already chose the type by a case-insensitive tag, so `tcp`/`Tcp`/`TCP` all give `TCP`. |
| `normalized.network_protocol` | `canonical_protocol(network.protocol)`, `IPv4` when the text is missing; `None` without a network layer. |
| Leading-zero IPv4 | Each of 4 parts must be 1–3 ASCII digits ≤ 255; read as decimal (`010` → 10, never octal); note `ip_normalized`. Surrounding whitespace is trimmed silently. Hex, octal prefixes, IPv6 and anything else → `None`. |
| Domain label rule | After lowercasing, stripping one trailing dot and IDNA encoding: each label must match `_?[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?`, total ≤ 253 chars. A single **leading** underscore is accepted for DNS service/attribute labels (RFC 8552: `_sip._tcp`, `_dmarc`); an underscore anywhere else is invalid. Invalid names keep the best-effort lowercase value and add `invalid_domain`. The root name `.` is kept as `.`. |
| HTTP `Host` | Absolute-form request-target authority wins over the `Host` header (RFC 9112 §3.2.2); with duplicate `Host` headers the last one is used (same as `HttpMessage.header`), all values stay in `headers["host"]`. Bracketed IPv6 literals and bare IPv6 → host `None`, note `invalid_host`. A port must be 1–5 ASCII digits ≤ 65535 (no sign, no spaces); otherwise port `None` + `invalid_host`, host still normalized. `host:` (empty port) → port `None`, no note. Port is only set when explicit (no scheme default). |
| HTTP scheme / method | `scheme` lowercased, only from an absolute-form URI, else `None`. `method` copied as sent (methods are case-sensitive, RFC 9110 §9.1). |
| Path | Source: `event.decoded.uri.path` when `event.decoded` is `DecodedHttp` with a `uri`; else the raw origin-form uri up to `?`/`#`, or the path of an absolute-form uri; authority-form/asterisk-form → `None`. Repeated `/` are collapsed **first**, then RFC 3986 §5.2.4 `remove_dot_segments` runs (so `/a//../b` → `/b`, matching servers that merge slashes). Case kept; `\` kept and flagged `backslash_in_path`. |
| Timestamps | Numbers > `1e11` are milliseconds → divided by 1000, note `timestamp_scaled`. ISO strings: trailing `Z`/`z` → `+00:00`, naive → UTC. Non-finite / bool / unparsable → `None`. |
| Normalization notes | `ip_normalized`, `timestamp_scaled`, `invalid_domain`, `invalid_host`, `backslash_in_path` are reasons: appended after the validation reasons and turning `valid` into `partial` (never `invalid`). |
| Wrong-type required fields | A load issue whose `field` is a required path makes the field invalid: `invalid_field:packet_id`, `invalid_timestamp`, `invalid_ip:<field>`, `invalid_port:<field>` (not `missing_field`). The load issue also gives its own `load/invalid_type` reason. |
| No network and no transport | Partial + `unsupported_protocol:<link.ethertype_name or unknown>` (IPv6, ARP, unknown linktype, non-JSON stub). Transport without network → `missing_field:src_ip`, `missing_field:dst_ip` (invalid). Network without transport → `unsupported_protocol:fragment` for a non-first fragment (`fragment_offset` ≠ 0), else `unsupported_protocol:<network.protocol_name or unknown>`. |
| Invalid and unsupported together | Invalid wins: `--invalid-policy` decides the action. |
| `MessageEvent` | Reasons in order `message_incomplete` (`complete is not True`), `message_truncated`, `message_gap`, `decode_partial:mime` / `decode_failed:mime`, then one `<stage>/<code>` per issue; partial → `mark`, else valid → `forward`. Policies never drop a message. |
| T14 `schema_version: 9` / unknown `record_type` | Partial with `load/unsupported_schema` (the record still loads; spec §6.4). A T14 line is invalid only when it also breaks a required field. |
| Policy validation | `PreprocessConfig.__post_init__` raises `ValueError` for a policy outside `PREPROCESS_POLICIES = ("mark", "drop")`; the CLI uses argparse `choices` (exit 2). |

### Reason vocabulary and order

Validation reasons in check order: `missing_field:packet_id` | `invalid_field:packet_id`; `missing_field:timestamp` | `invalid_timestamp`; `missing_field:src_ip` | `invalid_ip:src_ip`; same for `dst_ip`; `missing_field:src_port` | `invalid_port:src_port` | `reserved_port:src_port`; same for `dst_port`; `unsupported_protocol:<name>`; one `<stage>/<code>` per `event.issues` entry in order; `decode_partial:<uri|form|body|mime>` / `decode_failed:<…>`. Then normalization notes in first-seen order. Duplicates are dropped, first occurrence kept.

## Review Focus

1. Path traversal hidden by percent-encoding (`/static/%2e%2e/admin`): the normalized path must be resolved from the decoded path (`/admin`), not the raw one — `test_review_dot_segments_hidden_by_percent_encoding_resolve_from_the_decoded_path` (Task 1).
2. Two conflicting `Host` headers (request smuggling / virtual-host confusion): both values stay visible in `headers["host"]` and the chosen host is deterministic (last) — `test_review_duplicate_host_headers_keep_both_values_and_the_last_one_wins` (Task 1).
3. Control characters (NUL) inside DNS/Host names: IDNA passes plain ASCII through, so the LDH check must still flag them instead of emitting a clean-looking domain — `test_review_control_characters_in_domains_are_flagged` (Task 1).
4. Port text with a sign, a space or non-ASCII digits (`a.com:+80`, `a.com:٨٠`): `int()` would accept them, the normalizer must not — `test_review_signed_spaced_or_non_ascii_port_digits_are_rejected` (Task 1).
5. Absurd epoch values (`1e20`) in hand-written events: ISO conversion overflows; the event must come out `invalid_timestamp` with `timestamp_iso = None`, not an internal error — `test_review_absurd_timestamp_is_invalid_and_has_no_iso_form` (Task 2).

---

## File structure

| File | Task | Responsibility |
|---|---|---|
| `ids/preprocess/__init__.py` | 1 (create), 3 (exports) | package; re-exports `PREPROCESS_POLICIES`, `PreprocessConfig`, `PreprocessorStage` |
| `ids/preprocess/normalize.py` | 1 | canonical protocol/IP/domain/host/path/timestamp/address values; `normalize(event)` |
| `ids/preprocess/validate.py` | 2 | spec §8.1 rule table; `validate(event, normalized, *, now)`; `issue_reason(issue)` |
| `ids/preprocess/stage.py` | 3 | `PreprocessConfig`, `PreprocessorStage`, message grading, policy → action |
| `ids/cli.py` | 3 | `--invalid-policy`, `--unsupported-policy`, stage appended in `build_stages` |
| `tests/test_preprocess_normalize.py` | 1 | normalization rules, T05 variants |
| `tests/test_preprocess_validate.py` | 2 | rule table rows, T06, T14 shapes through `EventsSource` |
| `tests/test_preprocess_stage.py` | 3 | policy matrix, message grading, Runner + `JsonlSink` drop, CLI runs |

---

### Task 1: Normalization

**Files:**
- Create: `ids/preprocess/__init__.py`
- Create: `ids/preprocess/normalize.py`
- Test: `tests/test_preprocess_normalize.py`

**Interfaces:**
- Consumes: `ids.model` — `PacketEvent`, `Ipv4Info`, `TcpInfo`, `UdpInfo`, `ApplicationInfo`, `HttpMessage`, `HttpHeader`, `DnsMessage`, `DnsQuestion`, `DnsRecord`, `SmtpSession`, `SmtpCommand`, `DecodedHttp`, `DecodedUri`, `Normalized`, `NormalizedHttp`, `NormalizedDns`, `NormalizedSmtp` (interfaces §3); `HttpMessage.header(name) -> str | None`; `PacketEvent.application_protocol -> str`; `ids.codec.iso_timestamp(value: float | None) -> str | None` (plan 1a).
- Produces (module `ids.preprocess.normalize`):
  - `canonical_protocol(name: object) -> str | None`
  - `normalize_ip(value: object) -> tuple[str | None, list[str]]`
  - `normalize_domain(value: object) -> tuple[str | None, list[str]]`
  - `split_host(value: object) -> tuple[str | None, int | None, list[str]]`
  - `remove_dot_segments(path: str) -> str`
  - `normalize_path(path: str) -> tuple[str, list[str]]`
  - `normalize_timestamp(value: object) -> tuple[float | None, str | None, list[str]]`
  - `normalize_address(value: str | None) -> tuple[str | None, list[str]]`
  - `normalize(event: PacketEvent) -> tuple[Normalized, list[str]]` — never mutates `event`; notes de-duplicated in first-seen order.
  - note constants `IP_NORMALIZED`, `TIMESTAMP_SCALED`, `INVALID_DOMAIN`, `INVALID_HOST`, `BACKSLASH_IN_PATH`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_preprocess_normalize.py`:

```python
from __future__ import annotations

import pytest

from ids.model import (
    ApplicationInfo,
    DecodedHttp,
    DecodedUri,
    DnsMessage,
    DnsQuestion,
    DnsRecord,
    HttpHeader,
    HttpMessage,
    Ipv4Info,
    PacketEvent,
    SmtpCommand,
    SmtpSession,
    TcpInfo,
    UdpInfo,
)
from ids.preprocess.normalize import (
    canonical_protocol,
    normalize,
    normalize_domain,
    normalize_ip,
    normalize_path,
    normalize_timestamp,
    remove_dot_segments,
    split_host,
)

BASE = 1759000000.0
BASE_ISO = "2025-09-27T19:06:40.000000Z"


def http_event(
    *headers: tuple[str, str], uri: str | None = "/", decoded: DecodedHttp | None = None
) -> PacketEvent:
    message = HttpMessage(
        kind="request",
        method="GET",
        uri=uri,
        headers=[HttpHeader(name, value) for name, value in headers],
    )
    return PacketEvent(
        packet_id=1,
        timestamp=BASE,
        network=Ipv4Info(protocol="IPv4", src_ip="10.0.0.1", dst_ip="10.0.0.2"),
        transport=TcpInfo(src_port=40000, dst_port=80),
        application=ApplicationInfo(protocol="HTTP", message=message),
        decoded=decoded,
    )


@pytest.mark.parametrize("name", ["Tcp", "tcp", "TCP", " tcp "])
def test_protocol_names_are_canonical_whatever_the_case(name):
    assert canonical_protocol(name) == "TCP"


@pytest.mark.parametrize(
    ("name", "expected"),
    [("ipv4", "IPv4"), ("Http", "HTTP"), ("dns", "DNS"), ("smtp", "SMTP"), ("unknown", "UNKNOWN")],
)
def test_every_canonical_name_is_matched(name, expected):
    assert canonical_protocol(name) == expected


def test_names_outside_the_canonical_set_are_upper_cased_and_empty_names_are_none():
    assert canonical_protocol("icmp") == "ICMP"
    assert canonical_protocol("  ") is None
    assert canonical_protocol(None) is None


def test_transport_protocol_text_case_does_not_change_the_normalized_protocol():
    variants = [TcpInfo(protocol=p, src_port=1, dst_port=2) for p in ("Tcp", "tcp", "TCP")]
    normalized = [normalize(PacketEvent(transport=t))[0].protocol for t in variants]
    assert normalized == ["TCP", "TCP", "TCP"]
    assert normalize(PacketEvent(transport=UdpInfo(protocol="udp")))[0].protocol == "UDP"


def test_leading_zero_quads_are_read_as_decimal_octets():
    assert normalize_ip("010.000.000.001") == ("10.0.0.1", ["ip_normalized"])
    assert normalize_ip("010.000.000.001")[0] == normalize_ip("10.0.0.1")[0]


def test_ip_is_trimmed_without_a_note():
    assert normalize_ip(" 10.0.0.1 ") == ("10.0.0.1", [])


@pytest.mark.parametrize(
    "text", ["256.1.1.1", "1.2.3", "1.2.3.4.5", "0x0a.0.0.1", "0010.0.0.1", "::1", "", "a.b.c.d"]
)
def test_anything_that_is_not_a_dotted_quad_is_invalid(text):
    assert normalize_ip(text) == (None, [])


def test_non_string_ip_is_invalid():
    assert normalize_ip(167772161) == (None, [])


def test_domain_is_lowercased_and_loses_its_trailing_dot():
    assert normalize_domain("Example.COM.") == ("example.com", [])
    assert normalize_domain("example.com") == ("example.com", [])


def test_root_name_is_kept():
    assert normalize_domain(".") == (".", [])


def test_non_ascii_labels_are_idna_encoded():
    assert normalize_domain("Bücher.de") == ("xn--bcher-kva.de", [])


def test_leading_underscore_service_labels_are_valid():
    assert normalize_domain("_sip._tcp.Example.com") == ("_sip._tcp.example.com", [])


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("a..b", "a..b"),
        ("x" * 64 + ".com", "x" * 64 + ".com"),
        ("-bad.com", "-bad.com"),
        ("bad-.com", "bad-.com"),
        ("in_side.com", "in_side.com"),
        ("sp ace.com", "sp ace.com"),
    ],
)
def test_names_outside_ldh_rules_keep_a_best_effort_value_and_are_flagged(text, expected):
    assert normalize_domain(text) == (expected, ["invalid_domain"])


def test_names_longer_than_253_characters_are_flagged():
    name = ".".join(["a" * 63] * 4)
    assert normalize_domain(name) == (name, ["invalid_domain"])


def test_host_header_is_split_into_host_and_port():
    assert split_host("Example.COM:8080") == ("example.com", 8080, [])
    assert split_host("example.com") == ("example.com", None, [])
    assert split_host("example.com:") == ("example.com", None, [])


@pytest.mark.parametrize("text", ["[::1]:80", "[::1]", "::1", "example.com:http", "a.com:65536"])
def test_unsupported_or_broken_host_forms_are_flagged_not_raised(text):
    _, port, notes = split_host(text)
    assert port is None
    assert notes[0] == "invalid_host"


def test_host_with_bad_port_keeps_the_host():
    assert split_host("Example.com:99999") == ("example.com", None, ["invalid_host"])


def test_empty_host_is_absent_not_invalid():
    assert split_host("  ") == (None, None, [])


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/a/b/c/./../../g", "/a/g"),
        ("mid/content=5/../6", "mid/6"),
        ("/../a", "/a"),
        ("/a/..", "/"),
        ("/a/.", "/a/"),
        ("../../a", "a"),
        (".", ""),
        ("/a/b/..", "/a/"),
        ("/.hidden/..x", "/.hidden/..x"),
    ],
)
def test_remove_dot_segments_follows_rfc_3986(path, expected):
    assert remove_dot_segments(path) == expected


def test_path_collapses_slashes_before_removing_dot_segments_and_keeps_case():
    assert normalize_path("/a/./b/../c//d") == ("/a/c/d", [])
    assert normalize_path("/A//../B") == ("/B", [])


def test_backslashes_are_flagged_and_kept():
    assert normalize_path("/a\\..\\b") == ("/a\\..\\b", ["backslash_in_path"])


def test_epoch_iso_and_milliseconds_give_the_same_timestamp():
    expected = (BASE, BASE_ISO)
    assert normalize_timestamp(BASE)[:2] == expected
    assert normalize_timestamp(1759000000)[:2] == expected
    assert normalize_timestamp("2025-09-27T19:06:40Z") == (BASE, BASE_ISO, [])
    assert normalize_timestamp("2025-09-27T19:06:40+00:00") == (BASE, BASE_ISO, [])
    assert normalize_timestamp("2025-09-27T19:06:40") == (BASE, BASE_ISO, [])
    assert normalize_timestamp(1759000000000) == (BASE, BASE_ISO, ["timestamp_scaled"])


def test_the_millisecond_threshold_is_1e11():
    assert normalize_timestamp(1e11)[2] == []
    assert normalize_timestamp(1e11 + 1)[2] == ["timestamp_scaled"]


def test_iso_with_offset_is_converted_to_utc():
    assert normalize_timestamp("2025-09-28T02:06:40+07:00")[:2] == (BASE, BASE_ISO)


@pytest.mark.parametrize("value", ["yesterday", "", float("nan"), float("inf"), True, None, [1]])
def test_unusable_timestamps_normalize_to_none(value):
    assert normalize_timestamp(value) == (None, None, [])


def test_header_names_are_trimmed_and_lowercased_with_values_grouped_in_order():
    upper = http_event(("CONTENT-TYPE", "text/plain"), ("Accept", "a"), (" accept ", "b"))
    lower = http_event(("content-type", "text/plain"), ("accept", "a"), ("accept", "b"))
    upper_http = normalize(upper)[0].http
    assert upper_http.headers == {"content-type": ["text/plain"], "accept": ["a", "b"]}
    assert upper_http == normalize(lower)[0].http


def test_http_host_variants_normalize_identically():
    a = normalize(http_event(("Host", "Example.COM.:8080")))[0].http
    b = normalize(http_event(("host", "example.com:8080")))[0].http
    assert (a.host, a.port) == (b.host, b.port) == ("example.com", 8080)


def test_absolute_form_authority_wins_over_the_host_header_and_sets_the_scheme():
    event = http_event(("Host", "other.org"), uri="HTTP://User@Example.COM:81/a/../b?q=1")
    http = normalize(event)[0].http
    assert (http.scheme, http.host, http.port, http.path) == ("http", "example.com", 81, "/b")


def test_path_comes_from_the_decoded_uri_when_present():
    decoded = DecodedHttp(uri=DecodedUri(path="/search page/./x"))
    event = http_event(uri="/search%20page/./x?q=1", decoded=decoded)
    assert normalize(event)[0].http.path == "/search page/x"


def test_path_falls_back_to_the_raw_uri_without_query_or_fragment():
    assert normalize(http_event(uri="/a/./b/../c//d?x=/../y#f"))[0].http.path == "/a/c/d"


def test_origin_form_has_no_scheme_and_method_is_kept_as_sent():
    http = normalize(http_event(uri="/"))[0].http
    assert http.scheme is None
    assert http.method == "GET"


def test_dns_names_come_from_questions_then_answers_without_duplicates():
    message = DnsMessage(
        kind="response",
        questions=[DnsQuestion(name="WWW.Example.com.")],
        answers=[DnsRecord(name="www.example.com"), DnsRecord(name="Edge.CDN.net")],
    )
    event = PacketEvent(application=ApplicationInfo(protocol="DNS", message=message))
    assert normalize(event)[0].dns.names == ["www.example.com", "edge.cdn.net"]


def test_smtp_domains_are_lowercased_and_local_parts_kept():
    session = SmtpSession(
        kind="command",
        commands=[SmtpCommand(verb="EHLO", domain="Mail.Example.COM")],
        mail_from="Alice@Example.COM",
        rcpt_to=["Bob@Example.ORG.", "postmaster"],
    )
    event = PacketEvent(application=ApplicationInfo(protocol="SMTP", message=session))
    smtp = normalize(event)[0].smtp
    assert smtp.helo == "mail.example.com"
    assert smtp.mail_from == "Alice@example.com"
    assert smtp.rcpt_to == ["Bob@example.org", "postmaster"]


def test_smtp_helo_address_literal_is_kept():
    session = SmtpSession(commands=[SmtpCommand(verb="HELO", domain="[192.0.2.1]")])
    event = PacketEvent(application=ApplicationInfo(protocol="SMTP", message=session))
    assert normalize(event)[0].smtp.helo == "[192.0.2.1]"


def test_t05_variants_yield_identical_normalized_core_values():
    def event(protocol: str, src: str, stamp: object) -> PacketEvent:
        return PacketEvent(
            packet_id=1,
            timestamp=stamp,
            network=Ipv4Info(src_ip=src, dst_ip="10.0.0.2"),
            transport=TcpInfo(protocol=protocol, src_port=40000, dst_port=80),
        )

    plain = normalize(event("TCP", "10.0.0.1", BASE))
    padded = normalize(event("Tcp", "010.000.000.001", "2025-09-27T19:06:40Z"))
    scaled = normalize(event("tcp", "10.0.0.1", 1759000000000))
    assert plain[0] == padded[0] == scaled[0]
    assert (plain[1], padded[1], scaled[1]) == ([], ["ip_normalized"], ["timestamp_scaled"])


def test_notes_are_reported_once():
    event = PacketEvent(network=Ipv4Info(src_ip="010.0.0.1", dst_ip="010.0.0.2"))
    assert normalize(event)[1] == ["ip_normalized"]


def test_raw_fields_are_not_mutated():
    event = http_event(("CONTENT-TYPE", "x"), ("Host", "Example.COM"), uri="/A/./b")
    event.network.src_ip = "010.000.000.001"
    normalize(event)
    assert event.network.src_ip == "010.000.000.001"
    assert event.application.message.uri == "/A/./b"
    assert event.application.message.headers[0].name == "CONTENT-TYPE"
    assert event.normalized is None


def test_event_with_nothing_parsed_normalizes_to_empty_values():
    normalized, notes = normalize(PacketEvent())
    assert normalized.application_protocol == "UNKNOWN"
    assert (normalized.src_ip, normalized.protocol, normalized.timestamp) == (None, None, None)
    assert (normalized.http, normalized.dns, normalized.smtp) == (None, None, None)
    assert notes == []


def test_review_dot_segments_hidden_by_percent_encoding_resolve_from_the_decoded_path():
    decoded = DecodedHttp(uri=DecodedUri(path="/static/../admin"))
    event = http_event(uri="/static/%2e%2e/admin", decoded=decoded)
    assert normalize(event)[0].http.path == "/admin"


def test_review_duplicate_host_headers_keep_both_values_and_the_last_one_wins():
    http = normalize(http_event(("Host", "good.example"), ("HOST", "Evil.Example")))[0].http
    assert http.headers["host"] == ["good.example", "Evil.Example"]
    assert http.host == "evil.example"


def test_review_control_characters_in_domains_are_flagged():
    assert normalize_domain("ex\x00ample.com") == ("ex\x00ample.com", ["invalid_domain"])


@pytest.mark.parametrize("text", ["a.com:+80", "a.com:\u0668\u0660", "a.com: 80"])
def test_review_signed_spaced_or_non_ascii_port_digits_are_rejected(text):
    assert split_host(text) == ("a.com", None, ["invalid_host"])
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_preprocess_normalize.py -q`
Expected: collection error `ModuleNotFoundError: No module named 'ids.preprocess'`.

- [ ] **Step 3: Write the implementation**

Create `ids/preprocess/__init__.py`:

```python
"""Preprocessor (spec §8): normalization, validation and the policy stage."""

from __future__ import annotations
```

Create `ids/preprocess/normalize.py`:

```python
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
        if port_text.isascii() and port_text.isdigit() and int(port_text) <= MAX_PORT:
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
            parts = urlsplit(uri)
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


def _port(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_preprocess_normalize.py -q`
Expected: all tests pass.

Run: `uv run ruff check ids/preprocess tests/test_preprocess_normalize.py && uv run ruff format --check ids/preprocess tests/test_preprocess_normalize.py`
Expected: `All checks passed!` and `3 files already formatted`.

Run: `uv run pytest -q`
Expected: full suite passes.

- [ ] **Step 5: Commit**

```bash
git add ids/preprocess/__init__.py ids/preprocess/normalize.py tests/test_preprocess_normalize.py
git commit -m "feat: add preprocessor normalization"
```

---

### Task 2: Validation

**Files:**
- Create: `ids/preprocess/validate.py`
- Test: `tests/test_preprocess_validate.py`

**Interfaces:**
- Consumes: `ids.preprocess.normalize.normalize(event) -> tuple[Normalized, list[str]]` (Task 1); `ids.issues.Issue`; `ids.model` — `PacketEvent`, `Normalized`, `PreprocessStatus`, `DecodeStatus`, `DecodedHttp`, `DecodedMime`, `DecodedUri`, `DecodedForm`, `DecodedText`, `Ipv4Info`, `LinkInfo`, `TcpInfo`, `UdpInfo`; `ids.capture.EventsSource(path, *, count=None)` with `.items()` / `.close()` (plan 1c).
- Produces (module `ids.preprocess.validate`):
  - `validate(event: PacketEvent, normalized: Normalized, *, now: float) -> tuple[PreprocessStatus, list[str], bool]` — third item is `True` when an `unsupported_protocol:<name>` reason fired. Returns a fresh reason list the caller may extend.
  - `issue_reason(issue: Issue) -> str` — `"<stage>/<code>"`, `unknown` for a missing part.
  - constants `FUTURE_TOLERANCE = 86400.0`, `REQUIRED_FIELD_PATHS: dict[str, str]`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_preprocess_validate.py`:

```python
from __future__ import annotations

import json
from pathlib import Path

import pytest

from ids.capture import EventsSource
from ids.issues import Issue
from ids.model import (
    DecodedForm,
    DecodedHttp,
    DecodedMime,
    DecodedText,
    DecodedUri,
    DecodeStatus,
    Ipv4Info,
    LinkInfo,
    PacketEvent,
    PreprocessStatus,
    TcpInfo,
    UdpInfo,
)
from ids.preprocess.normalize import normalize
from ids.preprocess.validate import validate

NOW = 1759000100.0
VALID, PARTIAL, INVALID = PreprocessStatus.VALID, PreprocessStatus.PARTIAL, PreprocessStatus.INVALID


def event(**overrides: object) -> PacketEvent:
    fields: dict[str, object] = {
        "packet_id": 1,
        "timestamp": 1759000000.0,
        "network": Ipv4Info(src_ip="10.0.0.1", dst_ip="10.0.0.2"),
        "transport": TcpInfo(src_port=40000, dst_port=80),
    }
    fields.update(overrides)
    return PacketEvent(**fields)


def check(record: PacketEvent) -> tuple[PreprocessStatus, list[str], bool]:
    return validate(record, normalize(record)[0], now=NOW)


def test_t06_minimal_flat_event_without_optional_fields_is_valid():
    assert check(event()) == (VALID, [], False)


def test_udp_is_supported():
    assert check(event(transport=UdpInfo(src_port=5353, dst_port=53))) == (VALID, [], False)


@pytest.mark.parametrize(
    ("packet_id", "reason"),
    [
        (None, "missing_field:packet_id"),
        (0, "invalid_field:packet_id"),
        (-3, "invalid_field:packet_id"),
        (True, "invalid_field:packet_id"),
        ("7", "invalid_field:packet_id"),
    ],
)
def test_packet_id_must_be_a_positive_int(packet_id, reason):
    assert check(event(packet_id=packet_id)) == (INVALID, [reason], False)


def test_packet_id_one_is_the_lower_bound():
    assert check(event(packet_id=1))[0] is VALID


def test_missing_timestamp():
    assert check(event(timestamp=None)) == (INVALID, ["missing_field:timestamp"], False)


@pytest.mark.parametrize("stamp", [0.0, -1.0, float("nan"), float("inf"), "yesterday"])
def test_timestamp_must_be_finite_and_positive(stamp):
    assert check(event(timestamp=stamp)) == (INVALID, ["invalid_timestamp"], False)


def test_timestamp_may_be_up_to_one_day_ahead_of_now():
    assert check(event(timestamp=NOW + 86400))[0] is VALID
    assert check(event(timestamp=NOW + 86400.5)) == (INVALID, ["invalid_timestamp"], False)


def test_millisecond_timestamps_are_bounded_after_scaling():
    assert check(event(timestamp=1759000000000))[0] is VALID


@pytest.mark.parametrize("field", ["src_ip", "dst_ip"])
def test_missing_ip(field):
    network = Ipv4Info(src_ip="10.0.0.1", dst_ip="10.0.0.2")
    setattr(network, field, None)
    assert check(event(network=network)) == (INVALID, [f"missing_field:{field}"], False)


def test_ip_validity_uses_the_normalized_value():
    padded = event(network=Ipv4Info(src_ip="010.000.000.001", dst_ip="10.0.0.2"))
    assert check(padded) == (VALID, [], False)
    broken = event(network=Ipv4Info(src_ip="10.0.0.1", dst_ip="10.0.0.300"))
    assert check(broken) == (INVALID, ["invalid_ip:dst_ip"], False)


def test_transport_without_network_reports_both_ips_missing():
    assert check(event(network=None)) == (
        INVALID,
        ["missing_field:src_ip", "missing_field:dst_ip"],
        False,
    )


@pytest.mark.parametrize(
    ("ports", "status", "reasons"),
    [
        ((65535, 1), VALID, []),
        ((0, 80), PARTIAL, ["reserved_port:src_port"]),
        ((40000, 0), PARTIAL, ["reserved_port:dst_port"]),
        ((40000, 70000), INVALID, ["invalid_port:dst_port"]),
        ((-1, 80), INVALID, ["invalid_port:src_port"]),
        ((None, 80), INVALID, ["missing_field:src_port"]),
        ((40000, True), INVALID, ["invalid_port:dst_port"]),
    ],
)
def test_port_rules(ports, status, reasons):
    transport = TcpInfo(src_port=ports[0], dst_port=ports[1])
    assert check(event(transport=transport)) == (status, reasons, False)


def test_no_transport_layer_is_unsupported_and_named_after_the_ip_protocol():
    icmp = event(network=Ipv4Info(src_ip="10.0.0.1", dst_ip="10.0.0.2", protocol_name="ICMP"))
    icmp.transport = None
    assert check(icmp) == (PARTIAL, ["unsupported_protocol:ICMP"], True)


def test_non_first_fragment_is_unsupported_as_fragment():
    fragment = event(
        network=Ipv4Info(
            src_ip="10.0.0.1", dst_ip="10.0.0.2", protocol_name="TCP", fragment_offset=185
        ),
        transport=None,
    )
    assert check(fragment) == (PARTIAL, ["unsupported_protocol:fragment"], True)


def test_no_ipv4_layer_is_unsupported_and_named_after_the_ethertype():
    ipv6 = event(network=None, transport=None, link=LinkInfo(ethertype_name="IPv6"))
    assert check(ipv6) == (PARTIAL, ["unsupported_protocol:IPv6"], True)
    assert check(event(network=None, transport=None)) == (
        PARTIAL,
        ["unsupported_protocol:unknown"],
        True,
    )


def test_each_issue_adds_one_stage_code_reason_in_order_without_duplicates():
    issues = [
        Issue("application", "truncated_body", "x"),
        Issue("network", "truncated_packet", "y"),
        Issue("application", "truncated_body", "z"),
    ]
    assert check(event(issues=issues)) == (
        PARTIAL,
        ["application/truncated_body", "network/truncated_packet"],
        False,
    )


def test_load_issue_on_an_optional_field_is_partial():
    issue = Issue("load", "invalid_type", "bad", {"field": "network.ttl"})
    assert check(event(issues=[issue])) == (PARTIAL, ["load/invalid_type"], False)


def test_unsupported_schema_alone_is_partial():
    issue = Issue("load", "unsupported_schema", "schema_version 9")
    assert check(event(issues=[issue])) == (PARTIAL, ["load/unsupported_schema"], False)


@pytest.mark.parametrize(
    ("path", "overrides", "reason"),
    [
        ("packet_id", {"packet_id": None}, "invalid_field:packet_id"),
        ("timestamp", {"timestamp": None}, "invalid_timestamp"),
        ("network.src_ip", {"network": Ipv4Info(dst_ip="10.0.0.2")}, "invalid_ip:src_ip"),
        ("dst_ip", {"network": Ipv4Info(src_ip="10.0.0.1")}, "invalid_ip:dst_ip"),
        ("transport.src_port", {"transport": TcpInfo(dst_port=80)}, "invalid_port:src_port"),
        ("dst_port", {"transport": TcpInfo(src_port=1)}, "invalid_port:dst_port"),
    ],
)
def test_load_issue_on_a_required_field_is_invalid(path, overrides, reason):
    issue = Issue("load", "invalid_type", "wrong type", {"field": path})
    record = event(issues=[issue], **overrides)
    assert check(record) == (INVALID, [reason, "load/invalid_type"], False)


def test_load_issue_on_src_ip_without_any_layer_is_invalid_not_unsupported():
    issue = Issue("load", "invalid_type", "wrong type", {"field": "src_ip"})
    record = event(network=None, transport=None, issues=[issue])
    status, reasons, _ = check(record)
    assert status is INVALID
    assert reasons[:2] == ["invalid_ip:src_ip", "missing_field:dst_ip"]


@pytest.mark.parametrize(
    ("decoded", "reasons"),
    [
        (DecodedHttp(uri=DecodedUri(status=DecodeStatus.PARTIAL)), ["decode_partial:uri"]),
        (DecodedHttp(form=DecodedForm(status=DecodeStatus.FAILED)), ["decode_failed:form"]),
        (
            DecodedHttp(
                uri=DecodedUri(status=DecodeStatus.DECODED),
                body=DecodedText(status=DecodeStatus.PARTIAL),
            ),
            ["decode_partial:body"],
        ),
        (DecodedMime(status=DecodeStatus.FAILED), ["decode_failed:mime"]),
        (DecodedMime(status=DecodeStatus.PARTIAL), ["decode_partial:mime"]),
    ],
)
def test_partial_or_failed_decoding_marks_the_event_partial(decoded, reasons):
    assert check(event(decoded=decoded)) == (PARTIAL, reasons, False)


def test_unchanged_and_decoded_parts_add_nothing():
    decoded = DecodedHttp(
        uri=DecodedUri(status=DecodeStatus.UNCHANGED),
        body=DecodedText(status=DecodeStatus.DECODED),
        status=DecodeStatus.DECODED,
    )
    assert check(event(decoded=decoded)) == (VALID, [], False)


def test_invalid_wins_over_partial_and_reasons_follow_check_order():
    record = event(
        timestamp=None,
        transport=TcpInfo(src_port=0, dst_port=70000),
        issues=[Issue("application", "decode_error", "x")],
        decoded=DecodedHttp(uri=DecodedUri(status=DecodeStatus.PARTIAL)),
    )
    assert check(record) == (
        INVALID,
        [
            "missing_field:timestamp",
            "reserved_port:src_port",
            "invalid_port:dst_port",
            "application/decode_error",
            "decode_partial:uri",
        ],
        False,
    )


def test_review_absurd_timestamp_is_invalid_and_has_no_iso_form():
    record = event(timestamp=1e20)
    normalized = normalize(record)[0]
    assert normalized.timestamp_iso is None
    assert validate(record, normalized, now=NOW) == (INVALID, ["invalid_timestamp"], False)


MISSING = object()
FLAT = {
    "packet_id": 1,
    "timestamp": 1759000000.0,
    "src_ip": "10.0.0.1",
    "dst_ip": "10.0.0.2",
    "protocol": "TCP",
    "src_port": 40000,
    "dst_port": 80,
}


def flat(**changes: object) -> str:
    fields = {**FLAT, **changes}
    return json.dumps({key: value for key, value in fields.items() if value is not MISSING})


def load_line(tmp_path: Path, line: str) -> PacketEvent:
    path = tmp_path / "events.jsonl"
    path.write_text(line + "\n", encoding="utf-8")
    source = EventsSource(path)
    try:
        (loaded,) = list(source.items())
    finally:
        source.close()
    return loaded


@pytest.mark.parametrize(
    ("line", "status", "reasons"),
    [
        (flat(), VALID, []),
        (flat(timestamp="2025-09-27T19:06:40Z"), VALID, []),
        (
            "not json at all",
            INVALID,
            ["missing_field:timestamp", "unsupported_protocol:unknown", "load/invalid_json"],
        ),
        (flat(src_port="abc"), INVALID, ["invalid_port:src_port", "load/invalid_type"]),
        (flat(packet_id="one"), INVALID, ["invalid_field:packet_id", "load/invalid_type"]),
        (flat(timestamp="yesterday"), INVALID, ["invalid_timestamp", "load/invalid_type"]),
        (flat(dst_port=70000), INVALID, ["invalid_port:dst_port"]),
        (flat(src_ip=MISSING), INVALID, ["missing_field:src_ip"]),
        (flat(schema_version=9), PARTIAL, ["load/unsupported_schema"]),
        (flat(record_type="bogus"), PARTIAL, ["load/unsupported_schema"]),
    ],
    ids=[
        "flat-valid",
        "iso-timestamp",
        "non-json",
        "wrong-type-port",
        "wrong-type-packet-id",
        "wrong-type-timestamp",
        "port-70000",
        "missing-src-ip",
        "schema-version-9",
        "unknown-record-type",
    ],
)
def test_t14_loaded_event_shapes(tmp_path, line, status, reasons):
    loaded = load_line(tmp_path, line)
    assert validate(loaded, normalize(loaded)[0], now=NOW)[:2] == (status, reasons)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_preprocess_validate.py -q`
Expected: collection error `ModuleNotFoundError: No module named 'ids.preprocess.validate'`.

- [ ] **Step 3: Write the implementation**

Create `ids/preprocess/validate.py`:

```python
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

FUTURE_TOLERANCE = 86400.0
MAX_PORT = 65535
LOAD_STAGE = "load"
IP_FIELDS = frozenset(("src_ip", "dst_ip"))

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
            name = REQUIRED_FIELD_PATHS.get(str(issue.context.get("field")))
            if name is not None:
                failed.add(name)
    return failed


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _check_packet_id(event: PacketEvent, failed: set[str], verdict: _Verdict) -> None:
    value = event.packet_id
    if value is None and "packet_id" not in failed:
        verdict.add("missing_field:packet_id", invalid=True)
    elif not _is_int(value) or value < 1:
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
    elif not _is_int(value) or not 0 <= value <= MAX_PORT:
        verdict.add(f"invalid_port:{name}", invalid=True)
    elif value == 0:
        verdict.add(f"reserved_port:{name}")


def _check_layers(
    event: PacketEvent, normalized: Normalized, failed: set[str], verdict: _Verdict
) -> None:
    network = event.network
    transport = event.transport
    if network is not None or transport is not None or failed & IP_FIELDS:
        _check_ip("src_ip", event.src_ip, normalized.src_ip, failed, verdict)
        _check_ip("dst_ip", event.dst_ip, normalized.dst_ip, failed, verdict)
    if transport is not None:
        _check_port("src_port", transport.src_port, failed, verdict)
        _check_port("dst_port", transport.dst_port, failed, verdict)
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
                _decode_reason(verdict, part, value.status)
    elif isinstance(decoded, DecodedMime):
        _decode_reason(verdict, "mime", decoded.status)


def _decode_reason(verdict: _Verdict, part: str, status: DecodeStatus | None) -> None:
    if status is DecodeStatus.PARTIAL:
        verdict.add(f"decode_partial:{part}")
    elif status is DecodeStatus.FAILED:
        verdict.add(f"decode_failed:{part}")


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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_preprocess_validate.py -q`
Expected: all tests pass.

Run: `uv run ruff check ids/preprocess tests/test_preprocess_validate.py && uv run ruff format --check ids/preprocess tests/test_preprocess_validate.py`
Expected: `All checks passed!` and `4 files already formatted`.

Run: `uv run pytest -q`
Expected: full suite passes.

- [ ] **Step 5: Commit**

```bash
git add ids/preprocess/validate.py tests/test_preprocess_validate.py
git commit -m "feat: add preprocessor validation rules"
```

---

### Task 3: Preprocessor stage, policies and CLI wiring

**Files:**
- Create: `ids/preprocess/stage.py`
- Modify: `ids/preprocess/__init__.py` (whole file replaced)
- Modify: `ids/cli.py` (import block, `build_parser`, `build_stages`)
- Test: `tests/test_preprocess_stage.py`

**Interfaces:**
- Consumes: `normalize(event) -> tuple[Normalized, list[str]]` (Task 1); `validate(event, normalized, *, now) -> tuple[PreprocessStatus, list[str], bool]` and `issue_reason(issue) -> str` (Task 2); `ids.pipeline.Emit`, `ids.pipeline.Runner(parser, stages, sink, stats, *, unknown_policy="emit")` with `.run(source)`; `ids.parsers.PacketParser()`; `ids.sink.JsonlSink(path)` as a context manager; `ids.stats.Stats()` with `.to_dict()["dropped"]`, `["skipped"]`; `ids.cli.main(argv) -> int`; `ids.cli.build_stages(args)` as left by plan 2.
- Produces:
  - `ids.preprocess.stage.PREPROCESS_POLICIES: tuple[str, ...] = ("mark", "drop")`
  - `@dataclass(slots=True) class PreprocessConfig: invalid_policy: str = "mark"; unsupported_policy: str = "mark"; clock: Callable[[], float] = time.time` (raises `ValueError` on an unknown policy)
  - `class PreprocessorStage: name = "preprocess"; __init__(self, config: PreprocessConfig | None = None); process(record, emit) -> None; tick(now, emit) -> None; flush(emit) -> None`
  - `ids.preprocess` re-exports `PREPROCESS_POLICIES`, `PreprocessConfig`, `PreprocessorStage`.
  - CLI flags `--invalid-policy {mark,drop}` and `--unsupported-policy {mark,drop}` (default `mark`); `build_stages` returns `[DecoderStage(...), PreprocessorStage(PreprocessConfig(invalid_policy=args.invalid_policy, unsupported_policy=args.unsupported_policy))]`. Plan 4 appends `FlowTrackerStage` after it.
  - Guarantee for plan 4: after this stage every `PacketEvent` has `normalized` set; when the status is `valid`/`partial` and `normalized.protocol` is `TCP`/`UDP`, `normalized.src_ip`/`dst_ip` are canonical dotted quads and `normalized.src_port`/`dst_port` ints in 0–65535.

- [ ] **Step 1: Write the failing test**

Create `tests/test_preprocess_stage.py`:

```python
from __future__ import annotations

import json
from pathlib import Path

import pytest

from ids.cli import main
from ids.issues import Issue
from ids.model import (
    ApplicationInfo,
    DecodedMime,
    DecodeStatus,
    Ipv4Info,
    MessageEvent,
    PacketEvent,
    PreprocessStatus,
    ProcessingAction,
    TcpInfo,
)
from ids.parsers import PacketParser
from ids.pipeline import Runner
from ids.preprocess import PreprocessConfig, PreprocessorStage
from ids.sink import JsonlSink
from ids.stats import Stats

NOW = 1759000100.0
FLAT = {
    "packet_id": 1,
    "timestamp": 1759000000.0,
    "src_ip": "10.0.0.1",
    "dst_ip": "10.0.0.2",
    "protocol": "TCP",
    "src_port": 40000,
    "dst_port": 80,
}
FORWARD, MARK, DROP = ProcessingAction.FORWARD, ProcessingAction.MARK, ProcessingAction.DROP


def packet(packet_id: int = 1, **overrides: object) -> PacketEvent:
    fields: dict[str, object] = {
        "packet_id": packet_id,
        "timestamp": 1759000000.0,
        "network": Ipv4Info(src_ip="10.0.0.1", dst_ip="10.0.0.2", protocol_name="TCP"),
        "transport": TcpInfo(src_port=40000, dst_port=80),
    }
    fields.update(overrides)
    return PacketEvent(**fields)


def run(record, *, invalid: str = "mark", unsupported: str = "mark"):
    config = PreprocessConfig(
        invalid_policy=invalid, unsupported_policy=unsupported, clock=lambda: NOW
    )
    PreprocessorStage(config).process(record, [].append)
    return record


KINDS = {
    "valid": lambda: packet(),
    "partial": lambda: packet(transport=TcpInfo(src_port=0, dst_port=80)),
    "invalid": lambda: packet(transport=TcpInfo(src_port=40000, dst_port=70000)),
    "unsupported": lambda: packet(transport=None),
    "invalid+unsupported": lambda: packet(packet_id=0, transport=None),
}


@pytest.mark.parametrize(
    ("kind", "invalid", "unsupported", "action"),
    [
        ("valid", "drop", "drop", FORWARD),
        ("partial", "drop", "drop", MARK),
        ("invalid", "mark", "drop", MARK),
        ("invalid", "drop", "mark", DROP),
        ("unsupported", "mark", "mark", MARK),
        ("unsupported", "drop", "mark", MARK),
        ("unsupported", "mark", "drop", DROP),
        ("invalid+unsupported", "mark", "drop", MARK),
        ("invalid+unsupported", "drop", "mark", DROP),
    ],
)
def test_policy_matrix(kind, invalid, unsupported, action):
    record = run(KINDS[kind](), invalid=invalid, unsupported=unsupported)
    assert record.processing_action is action


def test_stage_writes_status_reason_and_normalized_values():
    record = run(packet(network=Ipv4Info(src_ip="010.000.000.001", dst_ip="10.0.0.2")))
    assert record.preprocess_status is PreprocessStatus.PARTIAL
    assert record.processing_action is MARK
    assert record.reason == ["ip_normalized"]
    assert record.normalized.src_ip == "10.0.0.1"
    assert record.network.src_ip == "010.000.000.001"


def test_valid_event_has_an_empty_reason_list():
    record = run(packet())
    assert (record.preprocess_status, record.processing_action, record.reason) == (
        PreprocessStatus.VALID,
        FORWARD,
        [],
    )


def test_normalization_notes_follow_validation_reasons_without_duplicates():
    record = run(
        packet(
            timestamp=1759000000000,
            transport=TcpInfo(src_port=0, dst_port=80),
            issues=[Issue("application", "decode_error", "x")],
        )
    )
    assert record.reason == [
        "reserved_port:src_port",
        "application/decode_error",
        "timestamp_scaled",
    ]


def test_the_configured_clock_bounds_future_timestamps():
    record = packet(timestamp=1759000000.0)
    config = PreprocessConfig(clock=lambda: 1759000000.0 - 86401)
    PreprocessorStage(config).process(record, [].append)
    assert record.reason == ["invalid_timestamp"]


def test_unknown_application_on_tcp_is_forwarded():
    record = run(
        packet(application=ApplicationInfo(protocol="UNKNOWN")), invalid="drop", unsupported="drop"
    )
    assert (record.preprocess_status, record.processing_action) == (PreprocessStatus.VALID, FORWARD)


@pytest.mark.parametrize("field", ["invalid_policy", "unsupported_policy"])
def test_config_rejects_unknown_policies(field):
    with pytest.raises(ValueError, match=field):
        PreprocessConfig(**{field: "skip"})


def message(**overrides: object) -> MessageEvent:
    fields: dict[str, object] = {
        "message_id": "f-1",
        "complete": True,
        "truncated": False,
        "gap": False,
        "decoded": DecodedMime(status=DecodeStatus.DECODED),
    }
    fields.update(overrides)
    return MessageEvent(**fields)


@pytest.mark.parametrize(
    ("overrides", "reasons"),
    [
        ({}, []),
        ({"decoded": None}, []),
        ({"decoded": DecodedMime(status=DecodeStatus.UNCHANGED)}, []),
        ({"complete": False}, ["message_incomplete"]),
        ({"truncated": True}, ["message_truncated"]),
        ({"gap": True}, ["message_gap"]),
        ({"decoded": DecodedMime(status=DecodeStatus.PARTIAL)}, ["decode_partial:mime"]),
        ({"decoded": DecodedMime(status=DecodeStatus.FAILED)}, ["decode_failed:mime"]),
        (
            {"complete": False, "gap": True, "issues": [Issue("decoder", "invalid_base64", "x")]},
            ["message_incomplete", "message_gap", "decoder/invalid_base64"],
        ),
    ],
)
def test_message_status_follows_reassembly_and_mime_outcome(overrides, reasons):
    record = run(message(**overrides), invalid="drop", unsupported="drop")
    assert record.reason == reasons
    if reasons:
        assert (record.preprocess_status, record.processing_action) == (
            PreprocessStatus.PARTIAL,
            MARK,
        )
    else:
        assert (record.preprocess_status, record.processing_action) == (
            PreprocessStatus.VALID,
            FORWARD,
        )


INVALID_LINE = {**FLAT, "packet_id": 2, "dst_port": 70000}
ICMP_LINE = {
    "packet_id": 3,
    "timestamp": 1759000002.0,
    "src_ip": "10.0.0.1",
    "dst_ip": "10.0.0.2",
    "protocol": "ICMP",
}


def packet_records(path: Path) -> list[dict[str, object]]:
    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    return [record for record in records if record["record_type"] == "packet"]


def verdicts(path: Path) -> list[tuple[object, ...]]:
    return [
        (r["packet_id"], r["preprocess_status"], r["processing_action"], r["reason"])
        for r in packet_records(path)
    ]


def write_events(tmp_path: Path, *records: dict[str, object]) -> str:
    path = tmp_path / "events.jsonl"
    path.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")
    return str(path)


def test_runner_does_not_write_an_event_the_drop_policy_dropped(tmp_path):
    output = tmp_path / "out.jsonl"
    stats = Stats()
    stage = PreprocessorStage(PreprocessConfig(invalid_policy="drop", clock=lambda: NOW))
    events = [packet(1), packet(2, transport=TcpInfo(src_port=40000, dst_port=70000))]
    with JsonlSink(str(output)) as sink:
        Runner(PacketParser(), [stage], sink, stats).run(events)
    assert verdicts(output) == [(1, "valid", "forward", [])]
    assert stats.to_dict()["dropped"] == 1


def test_unknown_policy_skip_still_skips_rather_than_drops_a_forwarded_unknown_event(tmp_path):
    output = tmp_path / "out.jsonl"
    stats = Stats()
    config = PreprocessConfig(invalid_policy="drop", unsupported_policy="drop", clock=lambda: NOW)
    unknown = packet(1, application=ApplicationInfo(protocol="UNKNOWN"))
    with JsonlSink(str(output)) as sink:
        Runner(PacketParser(), [PreprocessorStage(config)], sink, stats, unknown_policy="skip").run(
            [unknown]
        )
    summary = stats.to_dict()
    assert (summary["skipped"], summary["dropped"]) == (1, 0)
    assert output.read_text(encoding="utf-8") == ""


def test_cli_marks_invalid_and_unsupported_events_by_default(tmp_path):
    events = write_events(tmp_path, FLAT, INVALID_LINE, ICMP_LINE)
    output = tmp_path / "out.jsonl"
    assert main(["--events", events, "-o", str(output), "-q"]) == 0
    assert verdicts(output) == [
        (1, "valid", "forward", []),
        (2, "invalid", "mark", ["invalid_port:dst_port"]),
        (3, "partial", "mark", ["unsupported_protocol:ICMP"]),
    ]


def test_cli_invalid_policy_drop_writes_only_the_valid_event(tmp_path):
    events = write_events(tmp_path, FLAT, INVALID_LINE)
    output = tmp_path / "out.jsonl"
    assert main(["--events", events, "-o", str(output), "-q", "--invalid-policy", "drop"]) == 0
    assert verdicts(output) == [(1, "valid", "forward", [])]


def test_cli_unsupported_policy_drop_writes_only_the_supported_event(tmp_path):
    events = write_events(tmp_path, FLAT, ICMP_LINE)
    output = tmp_path / "out.jsonl"
    argv = ["--events", events, "-o", str(output), "-q", "--unsupported-policy", "drop"]
    assert main(argv) == 0
    assert verdicts(output) == [(1, "valid", "forward", [])]


@pytest.mark.parametrize("flag", ["--invalid-policy", "--unsupported-policy"])
def test_cli_rejects_an_unknown_policy_value(tmp_path, flag):
    with pytest.raises(SystemExit) as caught:
        main(["--events", write_events(tmp_path, FLAT), flag, "skip"])
    assert caught.value.code == 2
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_preprocess_stage.py -q`
Expected: collection error `ImportError: cannot import name 'PreprocessConfig' from 'ids.preprocess'`.

- [ ] **Step 3: Write the stage**

Create `ids/preprocess/stage.py`:

```python
"""Preprocessor stage: normalize + validate packet events, grade message events."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass

from ..model import (
    DecodeStatus,
    MessageEvent,
    PacketEvent,
    PreprocessStatus,
    ProcessingAction,
)
from ..pipeline import Emit
from .normalize import normalize
from .validate import issue_reason, validate

PREPROCESS_POLICIES = ("mark", "drop")


@dataclass(slots=True)
class PreprocessConfig:
    invalid_policy: str = "mark"  # "mark" | "drop"
    unsupported_policy: str = "mark"  # "mark" | "drop"
    clock: Callable[[], float] = time.time

    def __post_init__(self) -> None:
        for name in ("invalid_policy", "unsupported_policy"):
            value = getattr(self, name)
            if value not in PREPROCESS_POLICIES:
                raise ValueError(f"{name} must be one of {PREPROCESS_POLICIES}, got {value!r}")


def _action(policy: str) -> ProcessingAction:
    return ProcessingAction.DROP if policy == "drop" else ProcessingAction.MARK


class PreprocessorStage:
    name = "preprocess"

    def __init__(self, config: PreprocessConfig | None = None) -> None:
        self._config = config if config is not None else PreprocessConfig()

    def process(self, record: PacketEvent | MessageEvent, emit: Emit) -> None:
        if isinstance(record, PacketEvent):
            self._packet(record)
        elif isinstance(record, MessageEvent):
            _message(record)

    def tick(self, now: float, emit: Emit) -> None:
        """Stateless stage: nothing expires."""

    def flush(self, emit: Emit) -> None:
        """Stateless stage: nothing is buffered."""

    def _packet(self, event: PacketEvent) -> None:
        normalized, notes = normalize(event)
        status, reasons, unsupported = validate(event, normalized, now=self._config.clock())
        for note in notes:
            if note not in reasons:
                reasons.append(note)
        if notes and status is PreprocessStatus.VALID:
            status = PreprocessStatus.PARTIAL
        event.normalized = normalized
        event.preprocess_status = status
        event.reason = reasons
        if status is PreprocessStatus.INVALID:
            event.processing_action = _action(self._config.invalid_policy)
        elif unsupported:
            event.processing_action = _action(self._config.unsupported_policy)
        elif status is PreprocessStatus.PARTIAL:
            event.processing_action = ProcessingAction.MARK
        else:
            event.processing_action = ProcessingAction.FORWARD


def _message(message: MessageEvent) -> None:
    """Spec §9.7: a reassembled message is partial when incomplete, cut, gapped or mis-decoded."""
    reasons: list[str] = []
    if message.complete is not True:
        reasons.append("message_incomplete")
    if message.truncated:
        reasons.append("message_truncated")
    if message.gap:
        reasons.append("message_gap")
    status = message.decoded.status if message.decoded is not None else None
    if status is DecodeStatus.PARTIAL:
        reasons.append("decode_partial:mime")
    elif status is DecodeStatus.FAILED:
        reasons.append("decode_failed:mime")
    for issue in message.issues:
        reason = issue_reason(issue)
        if reason not in reasons:
            reasons.append(reason)
    message.reason = reasons
    if reasons:
        message.preprocess_status = PreprocessStatus.PARTIAL
        message.processing_action = ProcessingAction.MARK
    else:
        message.preprocess_status = PreprocessStatus.VALID
        message.processing_action = ProcessingAction.FORWARD
```

Replace `ids/preprocess/__init__.py` with:

```python
from __future__ import annotations

from .stage import PREPROCESS_POLICIES, PreprocessConfig, PreprocessorStage

__all__ = ["PREPROCESS_POLICIES", "PreprocessConfig", "PreprocessorStage"]
```

- [ ] **Step 4: Wire the stage into the CLI**

In `ids/cli.py`, add the import after `from .pipeline import UNKNOWN_POLICIES, Runner, Stage` (ruff isort order: `.parsers`, `.pipeline`, `.preprocess`, `.sink`, `.stats`):

```python
from .preprocess import PREPROCESS_POLICIES, PreprocessConfig, PreprocessorStage
```

In `build_parser`, the plan 1c block below is followed by `parser.add_argument("--stats", …)`:

```python
    parser.add_argument(
        "--unknown-policy",
        choices=UNKNOWN_POLICIES,
        default="emit",
        help="emit packets whose application protocol is UNKNOWN, or skip them",
    )
```

Insert directly after it, before `--stats` (spec §10.4 groups the three policies):

```python
    parser.add_argument(
        "--invalid-policy",
        choices=PREPROCESS_POLICIES,
        default="mark",
        help="invalid events: mark them in the output or drop them (default: mark)",
    )
    parser.add_argument(
        "--unsupported-policy",
        choices=PREPROCESS_POLICIES,
        default="mark",
        help="events without IPv4 + TCP/UDP: mark them or drop them (default: mark)",
    )
```

Replace `build_stages` (plan 2 left it as `return [DecoderStage(DecoderConfig(max_decoded_bytes=args.max_decoded_bytes))]`) with:

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

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_preprocess_stage.py -q`
Expected: all tests pass.

Run: `uv run ruff check ids/preprocess ids/cli.py tests/test_preprocess_stage.py && uv run ruff format --check ids/preprocess ids/cli.py tests/test_preprocess_stage.py`
Expected: `All checks passed!` and `6 files already formatted`.

Run: `uv run pytest -q`
Expected: full suite passes (existing CLI tests run with the default `mark` policies, so no record disappears; only the preprocess fields gain values).

- [ ] **Step 6: Commit**

```bash
git add ids/preprocess/stage.py ids/preprocess/__init__.py ids/cli.py tests/test_preprocess_stage.py
git commit -m "feat: add preprocessor stage with invalid and unsupported policies"
```
