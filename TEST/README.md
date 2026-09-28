# TEST — kết quả test case bắt buộc

Thư mục này chứa fixture và kết quả chạy của 12 test case bắt buộc trong đề bài
(mục 9), cộng thêm 1 case kiểm tra định dạng `pcapng`.

## Cách tái tạo

```bash
uv sync
uv run python TEST/generate_fixtures.py   # sinh lại toàn bộ fixture (deterministic)
sh TEST/run_cases.sh                      # chạy lại toàn bộ case, ghi output.jsonl
```

`run_cases.sh` gọi thẳng interpreter trong `.venv` để phần thống kê chỉ còn output
của chương trình (không lẫn thông báo build của `uv`). Đặt `PYTHON=python3` nếu muốn
dùng interpreter khác. Lệnh tương đương khi đã kích hoạt virtualenv:

```bash
python main.py --pcap TEST/fixtures/01-tcp-handshake.pcap --output out.jsonl --stats
```

Mỗi thư mục `case-<tên>/` gồm:

| File | Nội dung |
|---|---|
| `command.txt` | Lệnh chính xác đã dùng để sinh kết quả |
| `output.jsonl` | Output chuẩn hoá, mỗi dòng là một event JSON |
| `summary.txt` | Thống kê trên stderr: số packet, số event, lỗi theo stage/code |
| `stdout.txt` | stdout khi output ghi ra file (rỗng là đúng) |

## Danh sách case

| Case | Yêu cầu đề bài | Fixture | Kết quả mong đợi |
|---|---|---|---|
| 01 | TCP handshake: SYN, SYN/ACK, ACK | `01-tcp-handshake.pcap` | 3 event, `transport.flags_string` = `S`, `SA`, `A` |
| 02 | TCP data: parse packet có payload | `02-tcp-data.pcap` | 2 event, `transport.payload_length` = 29, 32 |
| 03 | UDP: parse UDP packet | `03-udp.pcap` | 3 event, `transport.protocol` = `UDP`, checksum hợp lệ |
| 04 | HTTP GET: parse request | `04-http-get.pcap` | `http_request`, `method` GET, `host`, `query_params` |
| 05 | HTTP POST: request có body | `05-http-post.pcap` | `http_request`, `body.length` 42, `form` tách 3 tham số |
| 06 | HTTP response: status code + header | `06-http-response.pcap` | `http_response`, `status_code` 200 và 404, `header_count`, `server` |
| 07 | DNS query: domain + query type | `07-dns-query.pcap` | `dns_query`, 3 câu hỏi A / MX / PTR |
| 08 | DNS response: ít nhất một answer | `08-dns-response.pcap` | `dns_response`, answer CNAME + A, thêm một NXDOMAIN |
| 09 | SMTP command: HELO/EHLO, MAIL FROM, RCPT TO | `09-smtp-command.pcap` | `smtp_command`, `mail_from`, `rcpt_to` |
| 10 | SMTP response: status code | `10-smtp-response.pcap` | `smtp_response`, `status_code` 220 / 250 / 354 / 550 |
| 11 | Unknown protocol: không crash | `11-unknown-protocol.pcap` | 6 event, `event_type` = `unknown_payload` / `network_only` / `unparsed`, không exception |
| 12 | Malformed packet: không crash | `12-malformed.pcap` | 14 event, lỗi được ghi vào `errors[]` theo từng stage, không exception |
| 13 | (bổ sung) pcapng | `13-mixed.pcapng` | 12 event, `capture.format` = `pcapng` |

## Chi tiết case 12 — malformed

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

Record 15 nằm sau record 14: khi record 14 khai báo nhiều byte hơn số byte thực có,
con trỏ file không còn tin cậy được nên reader dừng lại và ghi warning — đúng hành vi
của `tcpdump`/`tshark`. Warning được ghi rõ trong `summary.txt`.

## Ghi chú

- Fixture sinh bằng Scapy nhưng **không** dùng Scapy để đọc: `pcparser` parse lại
  bằng code tự viết, nên output là kiểm chứng độc lập.
- Timestamp trong fixture là cố định (`1759000000`) để kết quả tái lập được.
- Case 12 lưu 14/15 record — lý do nêu ở bảng trên.
