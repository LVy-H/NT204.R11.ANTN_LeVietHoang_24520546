# TEST/capture-parser: kết quả test case bắt buộc

Thư mục này chứa fixture và kết quả chạy của 12 test case bắt buộc của module Packet
Capture & Parser, cộng thêm 1 case kiểm tra định dạng `pcapng`. Kết quả được sinh lại theo
schema v2 (`docs/schema.md`), nên có thêm các khối `decoded`, `normalized`, `flow` và file
`flows.jsonl`.

## Cách tái tạo

```bash
uv sync
uv run python TEST/capture-parser/generate_fixtures.py   # sinh lại toàn bộ fixture (deterministic)
sh TEST/run_cases.sh                                     # chạy lại mọi case của mọi nhóm
sh TEST/run_cases.sh TEST/capture-parser/fixtures/04-http-get.pcap   # chỉ một fixture
```

`run_cases.sh` gọi thẳng interpreter trong `.venv` để phần thống kê chỉ còn output
của chương trình (không lẫn thông báo build của `uv`). Đặt `PYTHON=python3` nếu muốn
dùng interpreter khác. Lệnh tương đương khi đã kích hoạt virtualenv:

```bash
python main.py --pcap TEST/capture-parser/fixtures/01-tcp-handshake.pcap --output out.jsonl --flows-output flows.jsonl --stats
```

Mỗi thư mục `case-<tên>/` gồm:

| File | Nội dung |
|---|---|
| `command.txt` | Lệnh chính xác đã dùng để sinh kết quả |
| `output.jsonl` | Record `packet`, mỗi dòng một JSON |
| `flows.jsonl` | Record `flow`, ghi qua `--flows-output` |
| `summary.txt` | stderr: nguồn, warning, thống kê `--stats` (số packet, record, issue theo stage/code) |
| `stdout.txt` | stdout khi output ghi ra file (rỗng là đúng) |

## Danh sách case

| Case | Yêu cầu đề bài | Fixture | Kết quả mong đợi |
|---|---|---|---|
| 01 | TCP handshake: SYN, SYN/ACK, ACK | `01-tcp-handshake.pcap` | 3 packet, `transport.flags_string` = `S`, `SA`, `A`; 1 flow |
| 02 | TCP data: parse packet có payload | `02-tcp-data.pcap` | 2 packet, `transport.payload_length` = 29, 32 |
| 03 | UDP: parse UDP packet | `03-udp.pcap` | 3 packet, `transport.protocol` = `UDP`, `transport.checksum_valid` = true; 2 flow |
| 04 | HTTP GET: parse request | `04-http-get.pcap` | `http_request`, `application.message.method` = `GET`, header `Host` trong `application.message.headers`, `decoded.uri.params` |
| 05 | HTTP POST: request có body | `05-http-post.pcap` | `http_request`, `application.message.body.length` = 42, `decoded.form.params` tách 3 tham số |
| 06 | HTTP response: status code + header | `06-http-response.pcap` | `http_response`, `application.message.status_code` = 200 và 404, 5 và 2 header, `Server` = `nginx/1.24.0` |
| 07 | DNS query: domain + query type | `07-dns-query.pcap` | `dns_query`, `application.message.questions` A / MX / PTR |
| 08 | DNS response: ít nhất một answer | `08-dns-response.pcap` | `dns_response`, `application.message.answers` CNAME + A, thêm một `rcode_name` = `NXDOMAIN` |
| 09 | SMTP command: HELO/EHLO, MAIL FROM, RCPT TO | `09-smtp-command.pcap` | `smtp_command`, `application.message.mail_from`, `application.message.rcpt_to` |
| 10 | SMTP response: status code | `10-smtp-response.pcap` | `smtp_response`, `application.message.status_code` = 220 / 250 / 354 / 550 |
| 11 | Unknown protocol: không crash | `11-unknown-protocol.pcap` | 6 packet, `event_type` = `unknown_payload` / `network_only` / `unparsed`, không exception |
| 12 | Malformed packet: không crash | `12-malformed.pcap` | 14 packet, lỗi được ghi vào `issues[]` theo từng stage, không exception |
| 13 | (bổ sung) pcapng | `13-mixed.pcapng` | 12 packet, `source.format` = `pcapng` trong `summary.txt` |

## Chi tiết case 12: malformed

Fixture chứa 15 record, mỗi record cố tình vi phạm đúng một quy tắc:

| # | Lỗi | Stage/Code ghi nhận |
|---|---|---|
| 1 | Ethernet frame chỉ 6 byte | `link/truncated_packet` |
| 2 | IPv4 `IHL = 0` | `network/malformed_header` |
| 3 | `total_length` 60 nhưng chỉ bắt 40 byte | `network/truncated_packet` |
| 4 | TCP data offset 4 | `transport/malformed_header` |
| 5 | TCP header chỉ 10/20 byte | `transport/truncated_packet` |
| 6 | UDP `length = 4` (< 8) | `transport/malformed_header` |
| 7 | UDP khai báo 100 byte, chỉ có 20 | `network/truncated_packet` |
| 8 | IPv4 options bị cắt (IHL 8, còn 24 byte) | `network/truncated_packet` |
| 9 | IPv6 (không được hỗ trợ) | `network/unsupported_protocol` |
| 10 | `total_length` 10 < header length | `network/malformed_header` |
| 11 | DNS compression pointer trỏ về chính nó | `application/decode_error` |
| 12 | DNS header chỉ 3 byte | `application/truncated_packet` |
| 13 | HTTP `Content-Length: 5000`, body 3 byte | `application/truncated_body` |
| 14 | Record khai báo 200 byte, file chỉ có 40 | `capture/truncated_packet` + `network/truncated_packet` + `transport/truncated_packet` |
| 15 | Frame rỗng | dừng đọc sau record 14, xem `summary.txt` |

Record 15 nằm sau record 14. Khi record 14 khai báo nhiều byte hơn số byte thực có,
con trỏ file không còn tin cậy được nên reader dừng ở đó, giống `tcpdump`/`tshark`.
Warning được ghi trong `summary.txt`.

## Ghi chú

- Fixture sinh bằng Scapy, còn `ids` đọc và parse bằng code tự viết, nên output
  là kiểm chứng độc lập.
- Timestamp trong fixture là cố định (`1759000000`) để kết quả tái lập được.
- Case 12 chỉ lưu 14/15 record, lý do nêu ở bảng trên.
- `tests/test_cases.py` chạy lại từng fixture và so các bộ đếm kết quả (số record theo loại,
  trạng thái preprocess, lý do kết thúc flow, …) với `summary.txt` đã commit.
