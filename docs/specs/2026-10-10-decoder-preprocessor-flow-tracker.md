# Design: typed rewrite + Decoder, Preprocessor, Flow/Connection Tracker

Date: 2026-10-10. Status: approved in chat, pending written-spec review.

## 1. Goal

Extend the IDS with three intermediate modules placed after Packet Capture & Parser:

```
Capture → Parser → Decoder → Preprocessor → Flow/Connection Tracker → (Feature Extractor, later)
```

The output is decoded, normalized, flow-annotated data for the future Feature Extractor and
Detection Engine. The existing parser is first rewritten onto a typed model (schema v2) so the
new modules build on one consistent representation.

Source requirements: `Bai-tap-02_Decoder_Preprocessor_Flow_Tracker_IDS.pdf` (sections 1-6, 10).
Mandatory behaviour from it:

- Every decode/normalize/track failure is handled safely; one bad packet never stops the run.
- Timeouts, size limits and skip policies are configurable.
- Test cases T01-T14 are reproducible automatically; the lecturer may use hidden PCAP/event
  inputs with the same specification.
- One commit per task and one commit per test case; test results live under `TEST/`.

## 2. Decisions taken

| Topic | Decision |
|---|---|
| Existing codebase | Full typed rewrite onto stdlib dataclasses, schema v2 |
| Package | Rename `pcparser` → `ids`; console script `ids`; `python main.py` keeps working |
| Inputs | `--pcap`, `--interface`, and `--events FILE.jsonl` (schema v2 events) |
| SMTP/MIME | Per-packet decoding plus SMTP DATA reassembly in the Flow Tracker |
| Typed model | `@dataclass(slots=True)` + one codec module; no new runtime dependency |
| Output | One JSONL stream with `record_type` ∈ `packet`, `message`, `flow`; optional `--flows-output` |
| TEST layout | Grouped by module: `TEST/capture-parser/`, `TEST/flow-tracker/` |
| Commits | Assistant commits once per task / test case; the user pushes |

## 3. Non-goals

- TLS, DoH/DoT, or any cryptographic decryption.
- Generic TCP stream reassembly; only SMTP DATA bodies are reassembled.
- HTTP `chunked` transfer decoding, `Content-Encoding` (gzip/deflate), SMTP `BDAT`.
- IPv6 parsing (packets are reported as unsupported, as today).
- Feature extraction and detection (later modules).
- Configuration files; every knob is a CLI flag.

## 4. Problems in the current code that the rewrite fixes

| Problem | Location | Fix in the rewrite |
|---|---|---|
| Payload bytes dropped at the event boundary (preview 256 B + hash only) | `payload.py:36-48`, `http._body` | `Payload.data` kept up to `--max-payload-bytes`, serialized as base64 |
| Two error systems; ~50 redundant `stage=` arguments; dead class-level stage defaults | `errors.py`, `http.py`, `smtp.py`, `pipeline._stage` | Single `Issue` type; stage stamped once by the runner (§6.1) |
| Protocol knowledge in four places, already drifting (`TURN`) | `pipeline.py`, `transport.py`, `detector.py` | `parsers/registry.py` + grammar constants shared by detector and parser |
| Parser half-decodes (`parse_qs` on query, latin-1 form, lowercased headers) | `http.py` | Parser keeps raw values only; decoding → Decoder, normalization → Preprocessor |
| Dynamic key `application[protocol.lower()]`; duplicated 5-tuple / protocol | `event.py` | Fixed `application.message`; top-level fields generated from one source |
| `process()` returns `None` on fallback failure, counted as a policy skip; fake `sha256: ""` | `pipeline.py:39-80`, `cli.py:102` | Every input yields a counted outcome; failure records carry real issues |
| `json.dumps(default=str)` hides non-JSON values | `logger.py:29` | Removed; codec emits JSON types only |
| `--idle-timeout` means "stop capture", collides with flow idle timeout | `cli.py:58-64` | Renamed `--capture-idle-timeout` |
| Dead re-validation in `open_capture`; `getattr(source, "warnings")`; mixed namedtuple/dataclass/dict | `capture/__init__.py`, `cli.py:147` | Removed; `warnings` declared on the source protocol; dataclasses everywhere |
| Live linktype hardcoded to Ethernet | `capture/live.py:45` | Linktype per packet from Scapy `conf.l2types.layer2num`, fallback EN10MB |

## 5. Package layout

```
ids/
  model/
    packet.py      CaptureInfo, LinkInfo, Ipv4Info, TcpInfo, UdpInfo, Payload
    app.py         Detection, HttpMessage, DnsMessage, SmtpSession
    decoded.py     DecodeStatus, DecodedText, DecodedHttp, DecodedMime, MimePart
    flow.py        FlowKey, Endpoint, FlowRef, DirectionStats, TcpFlowState, FlowRecord
    event.py       Issue, PacketEvent, MessageEvent, PreprocessResult, Normalized
  codec.py         schema v2 encode/decode (the only module that knows JSON layout)
  issues.py        Issues collector, ParseError
  capture/         pcap.py, live.py, events.py (JSONL source), base.py
  parsers/         link, network, transport, http, dns, smtp, detector, registry, checksum
  decoder/         text.py, url.py, html.py, mime.py, stage.py
  preprocess/      validate.py, normalize.py, stage.py
  flow/            key.py, tcp.py, table.py, smtp.py, stage.py
  pipeline.py      Runner
  sink.py          JSONL sink(s)
  stats.py
  cli.py
main.py
```

## 6. Model, schema and codec

### 6.1 Error model

- `Issue(stage: str, code: str, message: str, context: dict)`.
- Parsers raise `ParseError(code, message, **context)` for fatal problems; they never name a
  stage. Non-fatal problems go to an `Issues` collector passed in by the caller, already scoped
  to a stage (`issues.scoped("application")`).
- The runner catches `ParseError` and stamps the stage it was running. Any other exception
  becomes `Issue(stage, "internal_error", str(exc), {"exception": type name})`.
- Codes in use: `truncated_packet`, `malformed_header`, `unsupported_protocol`, `decode_error`,
  `truncated_body`, `incomplete_message`, `invalid_content_length`, `malformed_header_line`,
  `incomplete_reply`, `missing_field`, `invalid_type`, `invalid_json`, `unsupported_schema`,
  `internal_error`.

### 6.2 Records

`PacketEvent` (one per captured packet or loaded event):

| Field | Type |
|---|---|
| `packet_id`, `timestamp` | `int \| None`, `float \| None` (None only for loaded broken events) |
| `capture` | `CaptureInfo` (source, origin, linktype, lengths, truncated flag) |
| `link`, `network`, `transport` | `LinkInfo?`, `Ipv4Info?`, `TcpInfo \| UdpInfo?` |
| `detection`, `application` | `Detection?`, `HttpMessage \| DnsMessage \| SmtpSession?` |
| `payload` | `Payload(length, sha256, data, data_truncated, preview, preview_truncated, binary)` |
| `decoded` | `DecodedHttp \| DecodedMime \| None` |
| `normalized` | `Normalized?` |
| `preprocess` | `PreprocessResult(status, action, reason: list[str])?` |
| `flow` | `FlowRef(flow_id, direction, state, flow_packet_index)?` |
| `issues` | `list[Issue]` |

Derived properties (never stored twice): `event_type`, `five_tuple`, `protocol`, `is_tcp`.

`HttpMessage` stores raw data only: `start_line`, `method?`, `uri?` (raw), `version`,
`status_code?`, `reason?`, `headers: list[tuple[str, str]]` in original case and order,
`body: Payload`, `complete`. Convenience accessors (`header("host")`) are case-insensitive.

`SmtpSession` gains `kind = "data"` for DATA-phase content: on a flow detected as SMTP, a
payload with no command or reply line is DATA content, not a decode error.

`MessageEvent`: `message_id`, `flow_id`, `protocol = "SMTP"`, `packet_ids`, `start_time`,
`end_time`, `data: bytes`, `complete`, `truncated`, `gap`, `decoded: DecodedMime?`,
`preprocess?`, `issues`.

`FlowRecord`: see §9.6.

### 6.3 Schema v2 JSON (`codec.encode`)

- Every record has `schema_version: 2` and `record_type`.
- Packet records keep top-level `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`,
  `application_protocol`, `event_type`, `timestamp`, `timestamp_iso`, generated from the
  nested blocks.
- `application = {protocol, detection, message}`; `message.kind` ∈ `request`, `response`,
  `query`, `command`, `mixed`, `data`.
- Bytes are written as base64 under `*_b64` keys (`payload.data_b64`).
- Preprocess fields are top-level: `preprocess_status`, `processing_action`, `reason`.
- Every optional scalar is written as `null` and every optional list as `[]`; the key set of
  a record type never varies.
- Values that are not JSON types raise `TypeError` (bug, not data).

### 6.4 Tolerant decode (`codec.decode_packet`)

- Signature: `decode_packet(obj: object) -> tuple[PacketEvent, list[Issue]]`; never raises.
- Missing key → field default (`None` / `[]`), no issue; the Preprocessor reports missing
  required fields as `missing_field:<name>` reasons.
- Wrong type, bad base64, unparsable number → field `None` + `Issue("load", "invalid_type")`.
- `schema_version != 2` or unknown `record_type` → `Issue("load", "unsupported_schema")`; the
  decoder still extracts what it can.
- The JSONL source turns a non-JSON line into a stub event (`packet_id` = line number,
  `timestamp` None) with `Issue("load", "invalid_json")`.
- Round-trip invariant: `decode_packet(encode(e))` reproduces `e` for any event the parser produces.

## 7. Decoder (`ids/decoder/`)

The Decoder never changes raw fields; results go to `event.decoded`. Each decoded field carries
`status: DecodeStatus` ∈ `decoded`, `unchanged`, `partial`, `failed`, `not_applicable`, plus
issues.

### 7.1 Characters (`text.py`)

`decode_text(data, declared_charset=None) -> DecodedText(text, charset, status,
invalid_byte_count, first_invalid_offset, truncated)`:

1. Declared charset, if Python knows it, strict.
2. Else strict UTF-8 (covers ASCII; `charset` reported as `ascii` when all bytes < 0x80).
3. On failure: UTF-8 with `errors="replace"`, `status = partial`, count of invalid bytes and
   first offset recorded.

Never raises. Output text is capped at `--max-decoded-bytes`; over the cap sets `truncated`.

### 7.2 URL and form (`url.py`)

- URI: raw `uri` stays in `application.message`. `decoded.uri`, `decoded.path`,
  `decoded.query`, `decoded.query_params: list[[name, value]]` are percent-decoded once.
  `+` becomes a space only in the query.
- Invalid escapes (`%G1`, trailing `%`) are kept literally and set `status = partial`.
- `double_encoded = true` when a `%XX` sequence remains after one pass. No second pass, so
  the logical meaning of the data is unchanged.
- Bytes resulting from percent-decoding are turned into text with `decode_text` (UTF-8).
- Form bodies (`application/x-www-form-urlencoded`) decode to ordered
  `decoded.form: list[[name, value]]`, duplicates kept, same rules as the query.

### 7.3 HTML entities (`html.py`)

- Applied with `html.unescape` to HTTP bodies whose Content-Type is `text/html`, `text/xml`,
  `application/xhtml+xml`, `text/plain`, or absent when the body is not binary.
- `decoded.body.text` holds the result; `entity_count` counts replaced entities. Unknown
  entities stay literal.
- URL parameters are not entity-decoded.

### 7.4 MIME (`mime.py`)

Input: an SMTP DATA payload (single packet) or a reassembled `MessageEvent`.

1. Strip the terminating `\r\n.\r\n` and undo dot-stuffing (`..` at line start → `.`).
2. Parse structure with stdlib `email` (`BytesParser`, `policy=email.policy.compat32` to keep
   raw access), walking multipart trees.
3. Decode RFC 2047 encoded words in `Subject`, `From`, `To`, `Cc` with
   `email.header.decode_header`, then `decode_text`.
4. Transfer encodings are decoded by hand so errors are visible:
   - `base64`: drop whitespace, check alphabet and padding, `base64.b64decode(validate=True)`;
     bad characters or padding → decode the valid prefix, `status = partial`, issue
     `invalid_base64`.
   - `quoted-printable`: `quopri.decodestring`; malformed `=XY` sequences recorded as
     `invalid_quoted_printable`, `status = partial`.
   - `7bit`, `8bit`, `binary`, absent → `unchanged`.
   - Anything else → `failed`, issue `unsupported_encoding`.
5. Text parts (`text/*`) go through `decode_text` with the part charset.

`DecodedMime(headers: {subject, from, to, cc, date, message_id}, parts: list[MimePart],
status)`; `MimePart(index, content_type, charset, transfer_encoding, filename, size, sha256,
text?, status, issues)`. Overall `status` is the worst part status.

### 7.5 Stage routing (`stage.py`)

- HTTP → URI, query, form, body charset, HTML entities.
- SMTP → MIME when the payload contains a header block with `MIME-Version`, `Content-Type` or
  `Content-Transfer-Encoding`; `MessageEvent`s always go through MIME.
- Anything else → `decoded = None` (serialized as `null`).

## 8. Preprocessor (`ids/preprocess/`)

### 8.1 Validation (`validate.py`)

| Check | Result on failure |
|---|---|
| `packet_id` int ≥ 1 | invalid, `missing_field:packet_id` / `invalid_field:packet_id` |
| `timestamp` finite, > 0, ≤ now + 86400 | invalid, `invalid_timestamp` |
| `src_ip`, `dst_ip` valid IPv4 after normalization | invalid, `invalid_ip:src_ip` |
| transport protocol ∈ {TCP, UDP} with ports in 0-65535 | invalid, `invalid_port:dst_port` |
| port 0 | partial, `reserved_port:src_port` |
| no IPv4 / no TCP-UDP layer (ICMP, IPv6, non-first fragment) | partial, `unsupported_protocol:<name>` |
| any parser, decoder or load issue | partial, one `stage/code` reason per issue |
| a load issue on a required field | invalid |

`status`: invalid if any invalid rule fired, else partial if any partial rule fired, else valid.

### 8.2 Normalization (`normalize.py`)

`event.normalized` holds canonical values; raw fields stay unchanged.

- Protocol names → canonical set `IPv4`, `TCP`, `UDP`, `HTTP`, `DNS`, `SMTP`, `UNKNOWN`
  (case-insensitive match).
- IPs: trim, `ipaddress` canonical form; dotted quads with leading zeros are read as decimal
  octets, reason `ip_normalized`.
- Domains (HTTP `Host`, DNS question/answer names, SMTP HELO/EHLO, mail address domains):
  lowercase, strip trailing dot, split `host:port` from `Host` into `host` + `port`, IDNA
  encode non-ASCII labels, flag `invalid_domain` for labels outside LDH rules.
- HTTP header names: trimmed + lowercased into `normalized.http.headers: {name: [values]}`.
- URI path: from the decoded path; remove dot segments (RFC 3986 §5.2.4), collapse repeated
  `/`, lowercase scheme and host, keep path case. Backslashes only flagged
  (`backslash_in_path`).
- Timestamp: epoch seconds float + ISO-8601 UTC with `Z`. Loaded events may give an ISO
  string or a number; numbers > 1e11 are milliseconds (`timestamp_scaled`).

### 8.3 Policies and actions

| Status / case | Action |
|---|---|
| valid | `forward` |
| partial | `mark` |
| invalid | `--invalid-policy`: `mark` (default) or `drop` |
| unsupported protocol | `--unsupported-policy`: `mark` (default) or `drop` |
| TCP/UDP with application `UNKNOWN` | tracked always; `--unknown-policy skip` suppresses only the packet record |

Dropped events are counted in stats and not written. Missing optional data is always `null`
or `[]`.

## 9. Flow/Connection Tracker (`ids/flow/`)

### 9.1 Identity

- `FlowKey(proto, lo, hi)`; endpoints `(ip_int, port)` sorted, so A→B and B→A share a key.
- `flow_id = sha1(f"{proto}|{lo_ip}:{lo_port}|{hi_ip}:{hi_port}|{start_time_us}")[:16]` hex:
  deterministic for the same input; a new connection reusing the 5-tuple gets a new id.
- Endpoint A is the initiator: for TCP, the sender of the first SYN without ACK; if the first
  packet seen is SYN-ACK, its destination; otherwise the sender of the first packet.
- `direction` = `forward` (A→B) or `backward` (B→A).
- Each tracked packet gets `flow = {flow_id, direction, state, flow_packet_index}`
  (`flow_packet_index` is 1-based; `state` is `null` for UDP).
- Tracked: events with status valid or partial and a usable 5-tuple. Invalid or dropped
  events get `flow = null`.

### 9.2 TCP states

States: `NEW`, `HANDSHAKE`, `ESTABLISHED`, `CLOSING`, `CLOSED`, `RESET`.

| From | Event | To |
|---|---|---|
| (none) | SYN without ACK | HANDSHAKE |
| (none) | SYN-ACK | HANDSHAKE (A = destination) |
| (none) | any other packet | NEW, `midstream = true` |
| HANDSHAKE | SYN-ACK from B, then ACK (no SYN) from A | ESTABLISHED, `handshake_complete = true` |
| NEW | ACK seen in both directions | ESTABLISHED |
| HANDSHAKE / NEW / ESTABLISHED | FIN | CLOSING (records `fin_seq` for that direction) |
| CLOSING | FIN from both sides and each acknowledged (`ack ≥ fin_seq + 1` from the peer) | CLOSED |
| any | RST | RESET |

Packets without payload update counters and state like any other packet. A packet that would
move a flow backwards (SYN on ESTABLISHED, data after CLOSED) does not change the state; it is
counted and the flow keeps its state.

After CLOSED or RESET the flow moves to the closed lane and lingers
`--tcp-closed-timeout` seconds (default 5) to absorb trailing ACKs and retransmissions. A SYN
without ACK on that key during the linger exports the old flow (`end_reason` closed/reset)
and starts a new flow.

### 9.3 UDP

No connection state (`tcp = null`). Packets with the same key belong to one flow while the
gap between packets stays within `--udp-idle-timeout`.

### 9.4 Time, expiry and limits

- Clock = maximum packet timestamp seen; in live mode also `Tick(now)` from the source about
  once per second while idle. The clock never moves backwards; `last_seen` is a maximum.
- Three `OrderedDict` lanes ordered by last activity: `tcp_open`, `tcp_closed`, `udp`. On
  every packet and tick, flows at the front of each lane whose idle time is strictly greater
  than the lane timeout (`clock - last_activity > timeout`) are exported and removed.
- Defaults: `--tcp-idle-timeout 300`, `--udp-idle-timeout 60`, `--tcp-closed-timeout 5`.
- `--max-flows` (default 100000): when exceeded, the least recently active flow across lanes
  is exported with `end_reason = evicted`.
- End of input: open TCP and UDP flows are exported with `end_reason = end_of_input`; flows
  already in the closed lane keep `closed` / `reset`.

### 9.5 Expiry before the triggering packet

Expiry runs before the new packet is applied, so in the output stream an expired flow's
record appears before the packet that advanced the clock past its timeout.

### 9.6 FlowRecord (`record_type: "flow"`)

| Group | Fields |
|---|---|
| Identity | `flow_id`, `protocol`, `application_protocol`, `endpoint_a {ip, port}`, `endpoint_b {ip, port}` |
| Time | `start_time`, `last_seen`, `duration` (`last_seen - start_time`) |
| Totals | `packet_count`, `byte_count`, `payload_byte_count` |
| Directions | `forward {packet_count, byte_count, payload_byte_count}`, `backward` with the same three fields |
| TCP | `tcp {state, syn_count, ack_count, fin_count, rst_count, handshake_complete, midstream}` or `null` |
| Lifecycle | `end_reason` ∈ `closed`, `reset`, `idle_timeout`, `evicted`, `end_of_input`; `first_packet_id`, `last_packet_id` |

- `byte_count` per packet = IPv4 `total_length`; if absent, `payload.length`.
- Flag counters count packets with the flag set (a SYN-ACK increments both `syn_count` and
  `ack_count`).
- `application_protocol` = the detection with the highest confidence seen on the flow, payload
  evidence ranked above port-only; `UNKNOWN` if none.

### 9.7 SMTP DATA reassembly (`flow/smtp.py`)

Per TCP flow whose `application_protocol` is SMTP:

1. Forward `DATA` command seen → wait for a backward `354` reply.
2. Buffer forward payload in sequence order: segments before the expected sequence number are
   trimmed (retransmission/overlap); a jump ahead sets `gap = true` and continues.
3. Stop at `\r\n.\r\n` → emit a `MessageEvent` (`complete = true`), then wait for the next
   `DATA`.
4. Buffer cap `--max-message-bytes` (default 1 MiB): extra bytes are discarded,
   `truncated = true`, the terminator is still searched for.
5. Flow ends during collection → emit with `complete = false`.

The runner sends each `MessageEvent` through `Decoder.mime` and a Preprocessor pass that sets
status: partial when `complete` is false, `truncated` is true, `gap` is true, or the MIME
status is `partial` / `failed`; otherwise valid.

## 10. Pipeline and I/O

### 10.1 Runner (`pipeline.py`)

```
for item in source:                 # RawPacket | PacketEvent (loaded) | Tick
    if Tick: emit(tracker.expire(item.now)); continue
    event = parse(item) or loaded event
    decoder(event); preprocessor(event)          # each wrapped, failures → Issue
    if action == drop: count, continue
    flows, messages = tracker(event)             # wrapped; failure → Issue, flow = null
    emit(flows); emit(decoded + preprocessed messages)
    emit(event) unless (--unknown-policy skip and application_protocol == UNKNOWN)
emit(tracker.flush())
```

Every stage call is isolated; an exception records an issue and processing continues with the
next stage. Every input item ends as exactly one counted outcome: written, dropped by policy,
or skipped by `--unknown-policy`.

### 10.2 Sources

- `PcapSource`: existing pcap/pcapng reader, unchanged behaviour; `warnings` declared on the
  source protocol.
- `LiveSource`: Scapy, per-packet linktype, emits `Tick` on sniff timeouts.
- `EventsSource`: JSONL (`-` = stdin) via `codec.decode_packet`; only `record_type = packet` lines
  are processed; `flow`/`message` lines are counted and ignored with a warning.

### 10.3 Sinks

`JsonlSink` writes all records to `--output` (default stdout); with `--flows-output FILE`,
flow records go to that file instead.

### 10.4 CLI

| Group | Flags (defaults) |
|---|---|
| Source | `-i/--interface`, `-r/--pcap`, `-e/--events FILE` (`-` stdin), `-L/--list-interfaces` |
| Output | `-o/--output -`, `--flows-output`, `--stats`, `-q/--quiet` |
| Capture | `-c/--count`, `--filter`, `--capture-idle-timeout` |
| Limits | `--max-payload-bytes 65535`, `--preview-limit 256`, `--max-decoded-bytes 1048576`, `--max-message-bytes 1048576`, `--max-flows 100000` |
| Policies | `--invalid-policy mark`, `--unsupported-policy mark`, `--unknown-policy emit` |
| Timeouts | `--tcp-idle-timeout 300`, `--udp-idle-timeout 60`, `--tcp-closed-timeout 5` |

Numeric flags reject negative values at parse time (exit 2). `--stats` adds preprocess
status/action counts, flows by `end_reason`, active flows at exit, messages reassembled.

## 11. Testing

### 11.1 Unit tests (`tests/`)

- The 179 existing tests are migrated to the typed API, keeping their behavioural assertions.
- New tests per module: codec round-trip and tolerant load; text/url/html/mime decoders
  including error paths; validation and normalization rules; flow key symmetry, initiator
  choice, every TCP transition, FIN-ACK acknowledgement math, lane expiry order, eviction,
  SMTP reassembly (retransmission, gap, cap, incomplete).
- `tests/test_cases.py` runs every `TEST/*/fixtures` input through the real `Runner` and
  asserts the expected outcome of each mandatory case.

### 11.2 `TEST/` layout

```
TEST/run_cases.sh                 regenerates every group's artefacts
TEST/capture-parser/              existing 13 cases (git mv, regenerated for schema v2)
  README.md generate_fixtures.py fixtures/ case-01-tcp-handshake/ … case-13-mixed/
TEST/flow-tracker/
  README.md generate_fixtures.py fixtures/ T01-http-url-decode/ … T14-malformed-event/
```

Each case directory: `command.txt`, `output.jsonl`, `flows.jsonl`, `summary.txt`.
Fixtures use fixed timestamps (base `1759000000`) and are generated by Scapy; JSONL fixtures
are handwritten.

### 11.3 Mandatory cases

| ID | Fixture | Expected (asserted) |
|---|---|---|
| T01 | pcap: `GET /search%20page?q=%27%20OR%201%3D1&x=a+b` | `decoded.query_params` has `q = "' OR 1=1"`, `x = "a b"`; `decoded.path = "/search page"`; raw `uri` byte-identical |
| T02 | pcap: `text/html` response `&lt;script&gt;alert(1)&lt;/script&gt; &amp; &#x27; &bogus;` | decoded text `<script>alert(1)</script> & ' &bogus;`, `entity_count = 6`, no issues |
| T03 | pcap: SMTP session, multipart message with a Base64 UTF-8 part and a Quoted-Printable part, split over two segments; plus a single-segment message | `message` record: both parts `status = decoded`, exact text; packet-level MIME decode on the single segment |
| T04 | pcap: HTTP `text/plain; charset=utf-8` body with `\xff\xfe` and a truncated UTF-8 sequence, then a valid packet | `status = partial`, `invalid_byte_count` > 0; following packet decoded normally; exit 0 |
| T05 | pcap (mixed-case headers/Host/DNS name) + JSONL (`tcp`/`Tcp`, `010.000.000.001`, ISO timestamps) | normalized protocol, IP, domain, header names, path, timestamp identical across variants |
| T06 | JSONL: events missing optional fields (link, application, options, headers) | full key set with `null`/`[]`; status valid or partial; no exception |
| T07 | pcap: SYN, SYN-ACK, ACK | one flow; third packet `flow.state = ESTABLISHED`; flow record `tcp.state = ESTABLISHED`, `handshake_complete` |
| T08 | pcap: handshake + data both ways | one `flow_id` on every packet; directions forward/backward match senders |
| T09 | pcap: graceful FIN/ACK close; second connection aborted with RST | `CLOSED` / `closed` and `RESET` / `reset` |
| T10 | pcap: DNS query + response over UDP | one UDP flow, `packet_count = 2`, `byte_count` = sum of IP total lengths, 1 forward / 1 backward |
| T11 | pcap: three interleaved flows (two TCP clients to one server, one UDP) | three flow ids; per-flow counts match |
| T12 | pcap: UDP flow, then a packet of another flow 61 s later | first flow exported `idle_timeout` before the later packet; active table no longer contains it |
| T13 | pcap: TCP session with known packet/flag mix both ways | exact packet, byte, payload byte, flag counts and duration |
| T14 | JSONL: non-JSON line, wrong types, port 70000, missing `src_ip`, `schema_version: 9`, unknown `record_type` | each yields one record with a matching `reason`: `invalid` when a required field is broken, `partial` (`load/unsupported_schema`) for an unknown schema version or record type; run completes, exit 0 |

## 12. Documentation

- `docs/schema.md`: schema v2 reference (records, fields, status values, reasons, end
  reasons); contract for the next module.
- `README.md`: module status, new flags, usage examples for the three sources.
- `TEST/<group>/README.md`: case table, fixture description, expected results.
- AI disclosure: separate entry for this work (tool and model, purpose, files produced); the
  existing entry stays unchanged.

## 13. Delivery order and commits

One commit per task, one per test case. The task-level breakdown lives in
`docs/plans/2026-10-10-*.md` (shared contract: `docs/plans/2026-10-10-interfaces.md`):

| Plan | Content | Commits |
|---|---|---|
| 1a | Rename `pcparser` → `ids`; `Issue`; typed model; `make_payload`; codec encode / decode | 6 |
| 1b | Parser migration, one commit per layer (link, network, transport, http, dns, smtp, registry + detector) | 7 |
| 1c | Capture sources, `PacketParser`, stats, runner, sink, CLI, JSONL events source, move `TEST/` cases to `TEST/capture-parser/` | 8 |
| 2 | Decoder: text, url/form, html, mime, stage | 5 |
| 3 | Preprocessor: normalization, validation, stage + policies | 3 |
| 4 | Flow tracker: key/id, TCP state machine, records, expiry lanes, SMTP DATA reassembly, stage + live `Tick` + CLI | 6 |
| 5 | Flow-tracker fixture generator + harness, T01–T14 (one commit each), regenerate the 13 capture-parser cases (one commit each), outcome guard, docs | 32 |

## 14. Risks

| Risk | Mitigation |
|---|---|
| Large rewrite breaks existing behaviour | Migrated unit tests keep their assertions; capture-parser cases regenerated and diffed for content changes beyond schema shape |
| Hidden PCAPs with mid-stream captures or odd handshakes | `NEW` / `midstream` path, initiator rule for SYN-ACK-first, no state regressions |
| Out-of-order pcap timestamps | Monotonic clock; `last_seen` is a maximum |
| Memory on large captures | `--max-flows` eviction, payload / message / decoded size caps |
| Python 3.10 compatibility (`requires-python >= 3.10`) | No 3.11+ APIs (e.g. `binascii` `strict_mode`); base64 validation done manually |
