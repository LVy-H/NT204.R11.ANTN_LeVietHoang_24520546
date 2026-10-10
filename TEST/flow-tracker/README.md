# TEST/flow-tracker: Decoder, Preprocessor, Flow Tracker

Fixture và kết quả chạy của 14 test case bắt buộc T01–T14 (Decoder, Preprocessor,
Flow/Connection Tracker).

## Cách tái tạo

```bash
uv sync
uv run python TEST/flow-tracker/generate_fixtures.py   # sinh lại toàn bộ fixture (deterministic)
sh TEST/run_cases.sh                                   # chạy lại mọi case của mọi nhóm
sh TEST/run_cases.sh TEST/flow-tracker/fixtures/T07-tcp-handshake.pcap   # chỉ một fixture
uv run pytest tests/test_cases.py                      # kiểm tra kết quả mong đợi
```

Fixture `.pcap` sinh bằng Scapy, timestamp cố định (`1759000000` cộng offset tính theo ms),
MAC / IP / port cố định, nên chạy lại cho đúng từng byte. Fixture `.jsonl` là event viết tay,
chạy bằng `--events`.

Mỗi thư mục `T<số>-<tên>/` gồm:

| File | Nội dung |
|---|---|
| `command.txt` | Lệnh chính xác đã dùng để sinh kết quả |
| `output.jsonl` | Record `packet` và `message` (schema v2, xem `docs/schema.md`) |
| `flows.jsonl` | Record `flow`, ghi qua `--flows-output` |
| `summary.txt` | stderr: nguồn, warning, thống kê `--stats` |
| `stdout.txt` | stdout khi output ghi ra file (rỗng là đúng) |

`tests/test_cases.py` chạy lại từng fixture qua `ids.cli.main` và kiểm tra giá trị ở bảng
dưới. Khi test, mọi record nằm chung một stream nên kiểm tra được cả thứ tự giữa record
`flow`, `message` và `packet`.

## Danh sách case

| Case | Yêu cầu đề bài | Fixture | Kết quả mong đợi |
|---|---|---|---|
| T01 | URL decode: path, query, `+` | `T01-http-url-decode.pcap` | `decoded.uri.params` = `[["q", "' OR 1=1"], ["x", "a b"]]`, `decoded.uri.path` = `/search page`, `application.message.uri` giữ nguyên |
| T02 | HTML entity | `T02-html-entities.pcap` | `decoded.body.text` = `<script>alert(1)</script> & ' &bogus;`, `entity_count` = 6, `issues` rỗng |
| T03 | SMTP / MIME: Base64 + Quoted-Printable, ghép 2 segment | `T03-smtp-mime.pcap` | 2 record `message` (packet 13+14 và 18), mọi part `status` = `decoded`, text đúng từng ký tự; packet 18 có `decoded.kind` = `mime` |
| T04 | Charset lỗi: byte UTF-8 không hợp lệ, chuỗi bị cắt | `T04-invalid-charset.pcap` | packet 1: `decoded.body.status` = `partial`, `invalid_byte_count` = 4, `preprocess_status` = `partial`; packet 2 decode bình thường; exit 0 |
| T05 | Chuẩn hoá: protocol, IP, domain, header, path, timestamp | `T05-normalize-pcap.pcap`, `T05-normalize-events.jsonl` | khối `normalized` giống hệt nhau giữa packet pcap và 3 biến thể JSONL (`tcp` / `Tcp`, `010.000.000.001`, ISO / mili giây); `host` = `www.example.com`, `port` = 8080, `path` = `/Docs/B/index.html`, DNS `names` = `["www.example.com"]` |
| T06 | Event thiếu field tuỳ chọn (link, application, options, headers) | `T06-missing-fields.jsonl` | đủ bộ key, field thiếu là `null` / `[]`, `preprocess_status` = `valid`, không exception |
| T07 | TCP handshake SYN, SYN/ACK, ACK | `T07-tcp-handshake.pcap` | 1 flow; packet 3 `flow.state` = `ESTABLISHED`; flow `tcp.state` = `ESTABLISHED`, `handshake_complete` = true, SYN 2 / ACK 2 |
| T08 | Handshake + data hai chiều | `T08-tcp-bidirectional.pcap` | 1 `flow_id` trên mọi packet; `direction` = `forward` khi client gửi, `backward` khi server gửi; forward 4 / backward 3 packet |
| T09 | Đóng FIN/ACK và huỷ bằng RST | `T09-tcp-close-reset.pcap` | flow 1 `CLOSED` / `end_reason` = `closed`, flow 2 `RESET` / `reset`; SYN dùng lại 5-tuple của flow 1 khi flow này còn chờ → flow mới, flow 1 được ghi ra trước SYN đó |
| T10 | DNS query + response qua UDP | `T10-udp-dns-flow.pcap` | 1 flow UDP, `packet_count` = 2, `byte_count` = 141 (57 + 84, tổng IPv4 `total_length`), forward 1 / backward 1, `tcp` = `null` |
| T11 | 3 flow xen kẽ (2 client TCP tới một server, 1 UDP) | `T11-interleaved-flows.pcap` | 3 `flow_id`; số packet / byte theo flow: 5 / 218, 4 / 167, 3 / 99 |
| T12 | UDP idle timeout | `T12-udp-idle-timeout.pcap` | khoảng cách đúng 60 s vẫn cùng flow; flow 1 `end_reason` = `idle_timeout`, được ghi ra trước packet 4 (đến sau 61 s); `active_flows` = 1 |
| T13 | Thống kê flow TCP hai chiều | `T13-tcp-flow-stats.pcap` | 11 packet, 790 byte, 350 byte payload; forward 7 / 430, backward 4 / 360; SYN 2 / ACK 10 / FIN 2 / RST 0; `duration` = 2.5 |
| T14 | Event lỗi: không phải JSON, sai kiểu, port 70000, thiếu `src_ip`, `schema_version` 9, `record_type` lạ | `T14-malformed-event.jsonl` | mỗi dòng ra đúng một record kèm `reason` khớp lỗi (chi tiết bên dưới); dòng trống và dòng `flow` bị bỏ qua; exit 0 |

## Chi tiết T14: event lỗi

| Dòng | Nội dung | `preprocess_status` | `reason` |
|---|---|---|---|
| 1 | `this is not json` | `invalid` | `missing_field:timestamp`, `unsupported_protocol:unknown`, `load/invalid_json` |
| 2 | `timestamp` = `"yesterday"` | `invalid` | `invalid_timestamp`, `load/invalid_type` |
| 3 | `src_port` = `"abc"` | `invalid` | `invalid_port:src_port`, `load/invalid_type` |
| 4 | `dst_port` = 70000 | `invalid` | `invalid_port:dst_port` |
| 5 | thiếu `src_ip` | `invalid` | `missing_field:src_ip` |
| 6 | `schema_version` = 9 | `partial` | `load/unsupported_schema` |
| 7 | `record_type` = `"bogus"` | `partial` | `load/unsupported_schema` |
| 8 | dòng trống | bỏ qua | |
| 9 | record `flow` | bỏ qua, warning `line 9: skipped record_type 'flow'` trong `summary.txt` | |
| 10 | JSON bị cắt | `invalid` | như dòng 1 |
| 11 | event hợp lệ | `valid` | |

Dòng không phải JSON vẫn ra một record với `packet_id` = số dòng (tính cả dòng trống).
Dòng 6 và 7 chỉ là `partial`: event vẫn nạp được đầy đủ, lỗi schema không rơi vào field
bắt buộc. Record `invalid` có `flow` = `null`.
