# Output schema v2

Reference for the JSON Lines records written by `python main.py` (package `ids`). It is the
input contract for the next module (Feature Extractor). The Python model lives in
`ids/model/`; `ids/codec.py` is the only code that knows the JSON layout.

## 1. General rules

- One UTF-8 JSON object per line. `--output` (default stdout) receives every record;
  with `--flows-output FILE`, `flow` records go to that file instead.
- Every record starts with `schema_version` (always `2`) and `record_type`
  (`packet`, `message` or `flow`).
- The key set of a record type never varies: every optional scalar is written as `null`,
  every optional list as `[]`, every optional map as `{}`. Keys keep the order listed below.
- Bytes are written as standard base64 under a key ending in `_b64` (`payload.data_b64`,
  `data_b64` in message records). The plain key name is never used for bytes.
- Enumerations are written as their string value.
- Times are epoch seconds (float). `timestamp_iso` is the same instant in UTC,
  `YYYY-MM-DDTHH:MM:SS.ffffffZ`.
- Raw fields (`application`, `payload`) are never rewritten. Decoded values are in
  `decoded`, canonical values in `normalized`.
- Records are written in processing order. A `flow` record that expires because a later
  packet advanced the clock is written before that packet; a `message` record is written
  before the packet that completed it.

## 2. Packet record (`record_type: "packet"`)

One per captured packet or loaded event. Top-level keys, in order:

| Key | Type | Meaning |
|---|---|---|
| `schema_version` | int | `2` |
| `record_type` | str | `"packet"` |
| `packet_id` | int \| null | 1-based position in the input (pcap record or JSONL line number); `null` only for loaded events without one |
| `timestamp` | float \| null | Capture time, epoch seconds |
| `timestamp_iso` | str \| null | `timestamp` in UTC ISO-8601 |
| `event_type` | str | How far the packet was understood (§2.1) |
| `src_ip`, `dst_ip` | str \| null | From `network` |
| `src_port`, `dst_port` | int \| null | From `transport` |
| `protocol` | str \| null | Transport protocol: `TCP`, `UDP` or `null` |
| `application_protocol` | str | `HTTP`, `DNS`, `SMTP` or `UNKNOWN` |
| `preprocess_status` | str \| null | `valid`, `partial`, `invalid` (§6.1) |
| `processing_action` | str \| null | `forward`, `mark`, `drop` (§6.2) |
| `reason` | list[str] | Why the status is not `valid` (§6.3) |
| `flow` | object \| null | Flow reference (§2.10); `null` for untracked packets |
| `capture` | object \| null | §2.2 |
| `link` | object \| null | §2.3 |
| `network` | object \| null | §2.4 |
| `transport` | object \| null | §2.5 |
| `application` | object \| null | §2.6; `null` when no transport layer was parsed |
| `payload` | object \| null | §2.7 |
| `decoded` | object \| null | §2.8 |
| `normalized` | object \| null | §2.9 |
| `issues` | list[object] | Problems found by any stage (§7) |

The top-level 5-tuple, `protocol`, `application_protocol`, `event_type` and `timestamp_iso`
are derived from the nested blocks when the record is written; they are not stored twice.

### 2.1 `event_type`

| Value | Meaning |
|---|---|
| `unparsed` | No IPv4 layer (link error, ARP, IPv6, unknown ethertype) |
| `network_only` | IPv4 parsed, no TCP/UDP layer (ICMP, transport error, non-first fragment) |
| `<proto>_<kind>` | Application message parsed: `http_request`, `http_response`, `dns_query`, `dns_response`, `smtp_command`, `smtp_response`, `smtp_mixed`, `smtp_data` |
| `<proto>_unparsed` | Application protocol detected, message not parsed (`http_unparsed`, `dns_unparsed`, `smtp_unparsed`) |
| `unknown_payload` | TCP/UDP payload present, no protocol detected |
| `tcp_segment`, `udp_segment` | TCP/UDP without payload and without a detected protocol |

### 2.2 `capture`

| Key | Type | Meaning |
|---|---|---|
| `source` | str \| null | `pcap`, `live` or `events` |
| `origin` | str \| null | File path or interface name |
| `linktype`, `linktype_name` | int, str \| null | DLT number and name (`1` / `EN10MB`) |
| `captured_length` | int \| null | Bytes present in the capture |
| `original_length` | int \| null | Length on the wire |
| `declared_capture_length` | int \| null | Length the record header declared |
| `truncated_by_capture` | bool \| null | Fewer bytes present than declared |

### 2.3 `link`

`protocol` (`Ethernet`, `LINUX_SLL`, `LINUX_SLL2`, `RAW`, `IPV4`, `IPV6`), `src_mac`, `dst_mac`, `ethertype` (int),
`ethertype_name`, `vlan` (list of `{tpid, pcp, dei, vid}`), `length_field` (802.3),
`llc` (`{dsap, ssap, control}` or `null`), `snap` (`{oui, protocol}` or `null`),
`address_family`, `packet_type`, `address_type`, `address`, `interface_index`
(Linux cooked-capture / loopback fields, otherwise `null`).

### 2.4 `network` (IPv4)

| Key | Type | Meaning |
|---|---|---|
| `protocol` | str \| null | `IPv4` |
| `version`, `header_length` | int \| null | Header fields; `header_length` in bytes |
| `dscp`, `ecn`, `tos` | int \| null | Type-of-service fields |
| `total_length` | int \| null | IPv4 total length; also the flow byte count of this packet |
| `identification` | int \| null | |
| `flags` | object \| null | `{reserved, df, mf}` booleans |
| `fragment_offset` | int \| null | In bytes |
| `fragmented` | bool \| null | `mf` set or offset > 0 |
| `ttl`, `protocol_number` | int \| null | |
| `protocol_name` | str \| null | `TCP`, `UDP`, `ICMP`, ... |
| `header_checksum` | str \| null | Hex |
| `header_checksum_valid` | bool \| null | |
| `src_ip`, `dst_ip` | str \| null | Dotted quad as captured |
| `options` | list[object] | `{type, name, length, data (hex), malformed, declared_length, available}` |
| `captured_truncated` | bool \| null | Fewer bytes captured than `total_length` |
| `declared_payload_length`, `captured_payload_length` | int \| null | |

### 2.5 `transport`

TCP (`protocol: "TCP"`): `src_port`, `dst_port`, `seq`, `ack`, `header_length`,
`reserved`, `flags` (`{fin, syn, rst, psh, ack, urg, ece, cwr, ns}`), `flags_list`
(e.g. `["SYN", "ACK"]`), `flags_string` (e.g. `"SA"`), `window`, `checksum` (hex),
`checksum_valid`, `urgent_pointer`, `options` (list of `{type, name, length, malformed,
declared_length, available, mss, shift, tsval, tsecr, blocks, data}`), `payload_length`.

UDP (`protocol: "UDP"`): `src_port`, `dst_port`, `length`, `checksum`, `checksum_valid`,
`declared_payload_length`, `payload_length`, `captured_truncated`.

### 2.6 `application`

`{protocol, detection, message}`. `protocol` is the detected protocol or `UNKNOWN`.

`detection`: `protocol`, `method` (`port+payload`, `payload`, `port`, `none`),
`confidence` (0–1), `port_matched`, `port_hint`, `evidence` (short text), `scores`
(`{protocol: score}`). Payload evidence decides; the port is a hint only.

`message` is `null` when no message was parsed, otherwise one of:

**HTTP** (`protocol: "HTTP"`), raw values only:

| Key | Meaning |
|---|---|
| `kind` | `request` or `response` |
| `version`, `start_line` | As sent |
| `method`, `uri` | Request only; `uri` is the raw request target, never percent-decoded |
| `status_code`, `reason` | Response only |
| `headers` | List of `{name, value}` in original case and order, duplicates kept |
| `body` | `{offset, length, declared_length, transfer_encoding, truncated}` or `null`; `offset` indexes the application payload |
| `complete` | Header terminator found |

**DNS** (`protocol: "DNS"`): `kind` (`query` / `response`), `id`, `flags`
(`{qr, opcode, aa, tc, rd, ra, z, ad, cd, rcode}`), `opcode`, `opcode_name`, `rcode`,
`rcode_name`, `counts` (`{questions, answers, authorities, additionals}`), `questions`
(list of `{name, type, type_name, class, class_name}`), `answers` / `authorities` /
`additionals` (list of `{name, type, type_name, class, class_name, ttl, rdlength, value,
rdata, rdata_error, udp_payload_size}`; `rdata` is hex when `value` is `null`), `tcp`.

**SMTP** (`protocol: "SMTP"`): `kind` (`command`, `response`, `mixed`, `data`),
`commands` (list of `{verb, arguments, address, parameters, path, domain, mechanism,
credentials_present}`), `replies` (list of `{code, text, lines, continuation}`),
`unparsed_lines`, `command` (first verb), `status_code` (first reply code),
`last_status_code`, `mail_from`, `rcpt_to`. `kind: "data"` marks DATA-phase content on an
SMTP flow (no command or reply line).

### 2.7 `payload`

The deepest bytes reached (application payload for TCP/UDP).

| Key | Meaning |
|---|---|
| `length` | Bytes captured |
| `sha256` | Hex SHA-256 of all captured payload bytes |
| `data_b64` | First `--max-payload-bytes` bytes (default 65535), base64 |
| `data_truncated` | `length` > `--max-payload-bytes` |
| `preview` | First `--preview-limit` bytes (default 256) as text; `.`-masked when binary |
| `preview_truncated` | Preview shorter than the payload |
| `preview_encoding` | `utf-8`, `latin-1` or `binary` |
| `binary` | NUL present or printable ratio < 0.75 |
| `preview_hex` | First 64 bytes in hex, binary payloads only |

### 2.8 `decoded`

`null` unless the Decoder applies. Every part carries a decode status (§5).

**HTTP** (`kind: "http"`): `{kind, uri, form, body, status}`.

- `uri`: `{text, path, query, params, status, double_encoded}`. `text` is the whole target
  percent-decoded once; `path` and `query` are its parts; `params` is
  `[[name, value], ...]` in order, duplicates kept, `+` read as space (query only).
  Invalid escapes stay literal (`partial`). `double_encoded` is `true` when a `%XX`
  sequence remains after the single pass. `null` for responses.
- `form`: `{params, status}` for `application/x-www-form-urlencoded` bodies, else `null`.
- `body`: decoded text `{text, charset, status, invalid_byte_count, first_invalid_offset,
  truncated, entity_count}` or `null` when there is no body. `charset` is the declared one
  (lower case) or `ascii` / `utf-8`. Invalid bytes become U+FFFD (`partial`).
  `entity_count` counts HTML entities replaced (HTML, XML, plain text, or absent
  Content-Type on a non-binary body); unknown entities stay literal. Text is capped at
  `--max-decoded-bytes` (`truncated: true`).
- `status`: worst status of the parts present.

**MIME** (`kind: "mime"`): SMTP DATA content in one packet (when its header block has
`MIME-Version`, `Content-Type` or `Content-Transfer-Encoding`) and every `message` record.
`{kind, headers, parts, status}`.

- The final `.\r\n` of the terminator is removed and dot-stuffing is undone first.
- `headers`: `{subject, from, to, cc, date, message_id}`, RFC 2047 words decoded, `null`
  when absent.
- `parts`: leaf parts only, in tree order: `{index (0-based), content_type (lower case,
  no parameters), charset, transfer_encoding (lower case or null), filename, size (decoded
  bytes), sha256 (of decoded bytes), text (text/* parts), status, truncated}`.
  `base64` and `quoted-printable` are decoded by hand (`decoded`, or `partial` with an
  issue); `7bit`, `8bit`, `binary` or absent → `unchanged`; any other encoding → `failed`
  with `size`, `sha256`, `text` set to `null`.
- `status`: worst part status.

### 2.9 `normalized`

Canonical values computed by the Preprocessor; raw fields keep their spelling.

| Key | Meaning |
|---|---|
| `timestamp` | Epoch seconds; loaded ISO strings converted, numbers > 1e11 read as milliseconds |
| `timestamp_iso` | `YYYY-MM-DDTHH:MM:SS.ffffffZ` |
| `network_protocol` | `IPv4` or `null` |
| `protocol` | `TCP`, `UDP` or `null` (case-insensitive input) |
| `application_protocol` | `HTTP`, `DNS`, `SMTP`, `UNKNOWN` |
| `src_ip`, `dst_ip` | Trimmed, canonical dotted quad; leading zeros read as decimal |
| `src_port`, `dst_port` | |
| `http` | `{method, scheme, host, port, path, headers}` or `null`. `host` lower case without trailing dot (IDNA for non-ASCII), `port` only when explicit, `scheme` only for absolute-form targets. `path` comes from `decoded.uri.path` with repeated `/` collapsed and dot segments removed (RFC 3986 §5.2.4). `headers` maps lower-case names to value lists in order |
| `dns` | `{names}`: question then answer names, lower case, no trailing dot, deduplicated; or `null` |
| `smtp` | `{helo, mail_from, rcpt_to}` with domains lower-cased; or `null` |

### 2.10 `flow` (reference on a packet)

`{flow_id, direction, state, flow_packet_index}`: `flow_id` is 16 hex characters;
`direction` is `forward` (sent by endpoint A, the initiator) or `backward`; `state` is the
TCP state after this packet (§5) or `null` for UDP; `flow_packet_index` is 1-based within
the flow. Packets with status `invalid`, dropped packets and packets without a usable
5-tuple get `flow: null`.

## 3. Message record (`record_type: "message"`)

An SMTP DATA body reassembled from the client segments that follow `DATA` / `354`.

| Key | Type | Meaning |
|---|---|---|
| `schema_version`, `record_type` | | `2`, `"message"` |
| `message_id` | str | `<flow_id>-<n>`, `n` 1-based per flow |
| `flow_id` | str | Flow the message belongs to |
| `protocol` | str | `SMTP` |
| `packet_ids` | list[int] | Packets that contributed bytes |
| `start_time`, `end_time` | float | First and last contributing packet |
| `data_b64` | str | Body bytes as sent, terminator `\r\n.\r\n` included, base64 |
| `complete` | bool | Terminator seen; `false` when the flow ended first |
| `truncated` | bool | More than `--max-message-bytes` (default 1 MiB) arrived; the rest was discarded |
| `gap` | bool | A sequence gap was skipped |
| `decoded` | object | MIME result (§2.8) |
| `preprocess_status`, `processing_action`, `reason` | | `partial` when incomplete, truncated, gapped or MIME status `partial` / `failed`; else `valid` |
| `issues` | list[object] | §7 |

## 4. Flow record (`record_type: "flow"`)

Written once per flow when it ends.

| Key | Type | Meaning |
|---|---|---|
| `schema_version`, `record_type` | | `2`, `"flow"` |
| `flow_id` | str | `sha1("<proto>\|<lo_ip>:<lo_port>\|<hi_ip>:<hi_port>\|<start_time_us>")[:16]`; a new connection on the same 5-tuple gets a new id |
| `protocol` | str | `TCP` or `UDP` |
| `application_protocol` | str | Best detection seen on the flow (payload evidence over port-only, then confidence); `UNKNOWN` if none |
| `endpoint_a`, `endpoint_b` | `{ip, port}` | A is the initiator: sender of the first SYN without ACK, the destination of a first SYN-ACK, else the sender of the first packet |
| `start_time`, `last_seen` | float | Earliest and latest packet time |
| `duration` | float | `last_seen - start_time`, rounded to microseconds |
| `packet_count`, `byte_count`, `payload_byte_count` | int | Totals; `byte_count` sums IPv4 `total_length` (payload length when absent) |
| `forward`, `backward` | object | `{packet_count, byte_count, payload_byte_count}` per direction |
| `tcp` | object \| null | `{state, syn_count, ack_count, fin_count, rst_count, handshake_complete, midstream}`; flag counters count packets with the flag set; `null` for UDP |
| `end_reason` | str | §5 |
| `first_packet_id`, `last_packet_id` | int | |

## 5. Enumerations

| Field | Values |
|---|---|
| `preprocess_status` | `valid`, `partial`, `invalid` |
| `processing_action` | `forward` (valid), `mark` (partial, or invalid / unsupported with policy `mark`), `drop` (never written; counted in `--stats`) |
| decode `status` | `not_applicable`, `unchanged`, `decoded`, `partial`, `failed`; severity increases in that order |
| TCP `state` | `NEW` (first packet not a SYN; `midstream: true`), `HANDSHAKE`, `ESTABLISHED`, `CLOSING` (a FIN seen), `CLOSED` (FIN both ways, each acknowledged), `RESET` |
| `direction` | `forward`, `backward` |
| `end_reason` | `closed`, `reset` (after the `--tcp-closed-timeout` linger, at end of input, or when a new SYN reuses the 5-tuple), `idle_timeout` (no packet for `--tcp-idle-timeout` / `--udp-idle-timeout` seconds; strictly greater than), `evicted` (`--max-flows` exceeded, least recently active first), `end_of_input` |
| `application.message.kind` | `request`, `response`, `query`, `command`, `mixed`, `data` |
| `detection.method` | `port+payload`, `payload`, `port`, `none` |

## 6. Preprocess status, action and reasons

### 6.1 Status

`invalid` if any invalid rule fired, else `partial` if any partial rule fired, else
`valid`.

### 6.2 Action

`valid` → `forward`; `partial` → `mark`; `invalid` → `--invalid-policy` (`mark` default,
or `drop`); unsupported protocol → `--unsupported-policy` (`mark` default, or `drop`).
`--unknown-policy skip` suppresses packet records whose application protocol is `UNKNOWN`;
their flows are still tracked.

### 6.3 Reasons

Listed in this order, duplicates dropped:

| Reason | Status | When |
|---|---|---|
| `missing_field:<name>` | invalid | `packet_id`, `timestamp`, `src_ip`, `dst_ip`, `src_port`, `dst_port` absent |
| `invalid_field:packet_id` | invalid | Not an int ≥ 1 |
| `invalid_timestamp` | invalid | Not finite, ≤ 0, or later than now + 86400 s |
| `invalid_ip:src_ip`, `invalid_ip:dst_ip` | invalid | Not a valid IPv4 address after normalization |
| `invalid_port:src_port`, `invalid_port:dst_port` | invalid | Outside 0–65535 or not an int |
| `reserved_port:src_port`, `reserved_port:dst_port` | partial | Port 0 |
| `unsupported_protocol:<name>` | partial | No IPv4 or no TCP/UDP layer (ICMP, IPv6, non-first fragment, ...) |
| `<stage>/<code>` | partial (invalid for a load issue on a required field) | One per entry in `issues` |
| `decode_partial:<part>`, `decode_failed:<part>` | partial | `<part>` ∈ `uri`, `form`, `body`, `mime` |
| `ip_normalized` | partial | An IP needed rewriting (e.g. `010.000.000.001`) |
| `timestamp_scaled` | partial | A loaded timestamp was in milliseconds |
| `invalid_domain` | partial | A domain label breaks LDH rules |
| `invalid_host` | partial | HTTP `Host` cannot be split into host and port |
| `backslash_in_path` | partial | `\` in the URI path (flagged only) |
| `message_incomplete`, `message_truncated`, `message_gap` | partial | Message records only: no terminator, cut at `--max-message-bytes`, sequence gap skipped (with `decode_partial:mime` / `decode_failed:mime`) |

Message records list their reasons in this order: `message_incomplete`, `message_truncated`,
`message_gap`, the MIME decode reason, then one `<stage>/<code>` per issue.

## 7. Issues

`{stage, code, message, context}`: `message` is human-readable, `context` a JSON object
with details (offsets, lengths, field paths).

Stages: `capture`, `link`, `network`, `transport`, `detect`, `application`, `load`,
`decoder`, `preprocess`, `flow`, `pipeline`.

| Code | Stage(s) |
|---|---|
| `truncated_packet` | capture, link, network, transport, application |
| `malformed_header` | link, network, transport, capture (file header) |
| `unsupported_protocol` | link (linktype), network (IPv6 / other version), transport (other IP protocol, non-first fragment) |
| `decode_error` | application |
| `truncated_body`, `incomplete_message`, `invalid_content_length`, `malformed_header_line` | application (HTTP) |
| `incomplete_reply` | application (SMTP) |
| `invalid_type`, `invalid_json`, `unsupported_schema` | load |
| `invalid_escape`, `invalid_charset_bytes`, `invalid_base64`, `invalid_quoted_printable`, `unsupported_encoding`, `decoded_truncated` | decoder |
| `internal_error` | any stage (unexpected exception; `context.exception` holds the type name) |

A failing stage records an issue and the record continues to the next stage; one bad
packet never stops the run.

## 8. `--events` input

`--events FILE` (`-` = stdin) reads JSON Lines and runs every event through the Decoder,
Preprocessor and Flow Tracker. `decoded`, `normalized`, `preprocess_status`,
`processing_action`, `reason` and `flow` are recomputed.

- Packet records written by this program load back unchanged.
- Blank lines are skipped; line numbers still count them.
- Lines with `record_type` `flow` or `message` are skipped with the warning
  `line <n>: skipped record_type '<type>'`.
- A line that is not JSON becomes a stub packet record: `packet_id` = line number,
  `timestamp: null`, issue `load/invalid_json`, status `invalid`.
- A line that is JSON but not an object (`[1, 2]`, `null`, `42`) also gets `packet_id` =
  line number, with issue `load/invalid_type` whose context carries `line`.
- A missing key loads as `null` / `[]` without an issue; the Preprocessor reports missing
  required fields. A value of the wrong type (or bad base64, unknown enum value) loads as
  `null` with issue `load/invalid_type`. `schema_version` other than `2` or `record_type`
  other than `packet` adds `load/unsupported_schema` and the event is still processed.
- Derived keys (`event_type`, `timestamp_iso`, `application_protocol`) are ignored.
- `timestamp` may be epoch seconds, epoch milliseconds (> 1e11) or an ISO-8601 string
  (`Z` or `+00:00`).

Minimal flat event (no nested blocks):

```json
{"packet_id": 1, "timestamp": 1759000000.0, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "protocol": "TCP", "src_port": 51234, "dst_port": 80}
```

Without a `network` block, `src_ip` / `dst_ip` build one (`protocol: "IPv4"`). Without a
`transport` block, top-level `protocol` (or `transport_protocol`) `TCP` / `UDP`, any case,
builds one from `src_port` / `dst_port`. An `application` block may be added in the packet
record layout (§2.6) to feed the Decoder.

## 9. `--stats` summary

Printed to stderr as one indented JSON object after the progress lines: `packets_seen`,
`records_written` (`{packet, message, flow}`), `dropped`, `skipped`,
`packets_with_issues`, `first_timestamp`, `last_timestamp`, `event_types`, `protocols`,
`application_protocols`, `detection_methods`, `issue_codes` (`"<stage>/<code>"`),
`preprocess_status`, `processing_action`, `flow_end_reasons`, `messages`
(`{complete, incomplete}`), `stage_errors`, `active_flows` (flows still open when input
ended, before the final export), `source` (reader description: format, linktype, snaplen,
...).
