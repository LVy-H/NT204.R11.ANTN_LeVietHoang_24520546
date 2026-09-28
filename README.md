# PCP — Packet Capture & Parser cho hệ thống IDS/IPS

Bài tập 1 — module **thu thập và phân tích gói tin** cho hệ thống phát hiện xâm nhập.
Module nhận packet từ **live traffic** hoặc **file PCAP**, phân tích các protocol
được yêu cầu và chuyển mỗi packet thành **một event chuẩn hoá** dạng JSON Lines.

Detection Engine ở các bài tập sau chỉ đọc event này, không cần truy cập packet thô.

```
Raw Packet → Network Parser → Transport Parser → Application Protocol Detector
           → Application Protocol Parser → Normalized IDS Event
```

| Layer | Protocol được hỗ trợ |
|---|---|
| Link | Ethernet, 802.1Q/QinQ VLAN, Linux SLL/SLL2, NULL/LOOP, RAW IP |
| Network | IPv4 (kèm options, kiểm tra checksum, nhận biết fragment) |
| Transport | TCP, UDP (kèm options, kiểm tra checksum) |
| Application | HTTP/1.x, DNS, SMTP |

## 1. Cài đặt

Yêu cầu: Python ≥ 3.10.

```bash
uv sync                    # cách khuyến nghị, tạo .venv và cài đúng phiên bản trong uv.lock
```

Không dùng `uv`:

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
```

Kiểm thử:

```bash
uv run pytest              # 179 unit test
```

## 2. Sử dụng

```bash
# bắt packet trực tiếp từ interface
uv run main.py --interface eth0
uv run main.py --interface wlan0 --filter "tcp port 80" --count 500

# đọc từ file pcap / pcapng
uv run main.py --pcap test.pcap
uv run main.py --pcap test.pcap --output out.jsonl --stats

# liệt kê interface khả dụng
uv run main.py --list-interfaces
```

Sau khi `uv sync` (hoặc kích hoạt virtualenv) có thể gọi trực tiếp
`python main.py ...` hoặc lệnh `pcparser` đã được cài như console script.

| Tham số | Ý nghĩa |
|---|---|
| `--interface`, `-i` | Bắt live traffic từ interface |
| `--pcap`, `-r` | Đọc từ file `.pcap` / `.pcapng` |
| `--list-interfaces`, `-L` | In danh sách interface rồi thoát |
| `--output`, `-o` | File JSON Lines (mặc định `-` = stdout) |
| `--count`, `-c` | Dừng sau N packet |
| `--filter` | BPF filter cho live capture |
| `--idle-timeout` | Dừng live capture sau N giây không có traffic |
| `--unknown-policy` | `emit` (mặc định) hoặc `skip` packet không nhận diện được |
| `--preview-limit` | Số byte payload tối đa giữ trong `payload.preview` |
| `--stats` | In thống kê tổng kết ra stderr |
| `--quiet`, `-q` | Tắt thông báo tiến độ |

Mã thoát: `0` thành công, `1` lỗi runtime (file/interface/quyền), `2` lỗi tham số,
`130` bị Ctrl-C.

> **Live capture cần quyền.** Trên Linux cần `CAP_NET_RAW`; nếu thiếu, chương trình
> báo rõ và thoát với mã 1 thay vì crash. Chạy bằng `sudo` hoặc cấp capability:
> `sudo setcap cap_net_raw+eip "$(readlink -f .venv/bin/python3)"`.

### Output

Mặc định ghi JSON Lines ra stdout: **mỗi dòng một event**, phù hợp để pipe sang
Detection Engine hoặc `--output` ra file rồi nạp lại.

```bash
uv run main.py --pcap TEST/fixtures/04-http-get.pcap --output - | head -1
```

## 3. Kiến trúc

```
pcparser/
├── cli.py              Tham số dòng lệnh, vòng lặp capture, thống kê
├── pipeline.py         Nối các stage, gom lỗi, chọn policy cho packet UNKNOWN
├── event.py            Sinh event chuẩn hoá (schema cố định)
├── logger.py           Ghi JSON Lines
├── stats.py            Đếm packet / event / lỗi theo loại
├── errors.py           Lỗi có thể phục hồi theo từng packet
├── payload.py          Tóm tắt payload: độ dài, sha256, preview
├── capture/
│   ├── base.py         RawPacket + giao diện CaptureSource
│   ├── pcap.py         Đọc .pcap và .pcapng bằng standard library
│   └── live.py         Bắt live traffic qua scapy
└── parsers/
    ├── link.py         Ethernet, VLAN, SLL/SLL2, NULL/LOOP, RAW
    ├── network.py      IPv4
    ├── transport.py    TCP, UDP
    ├── detector.py     Nhận diện HTTP/DNS/SMTP theo port + payload
    ├── http.py         HTTP/1.x request & response
    ├── dns.py          DNS query & response
    └── smtp.py         SMTP command & response
```

**Một parser duy nhất cho cả hai nguồn (yêu cầu 2.1.2).** Scapy chỉ được dùng ở
tầng I/O của live capture: mỗi packet được chuyển ngay thành `bytes` rồi đưa vào
`RawPacket`. File PCAP được đọc bằng reader tự viết (`capture/pcap.py`), không
qua library nào. Vì vậy `--pcap` chạy được cả khi không cài Scapy, và toàn bộ
logic phân tích nằm trong một pipeline duy nhất.

## 4. Cấu trúc event chuẩn hoá

Mỗi dòng JSON có các khoá sau (schema_version = 1):

| Khoá | Nội dung |
|---|---|
| `schema_version` | Phiên bản schema, tăng khi có thay đổi phá vỡ tương thích |
| `packet_id` | Số thứ tự packet trong phiên capture, bắt đầu từ 1 |
| `timestamp` / `timestamp_iso` | Thời điểm packet được thu nhận (epoch giây / ISO-8601 UTC) |
| `event_type` | Loại event, xem bảng bên dưới |
| `network_protocol`, `transport_protocol`, `application_protocol` | Giao thức theo từng tầng; `UNKNOWN` nếu không nhận diện được |
| `src_ip`, `dst_ip`, `src_port`, `dst_port` | Trường rút gọn cho Detection Engine |
| `capture` | Nguồn (`live`/`pcap`), file/interface, linktype, độ dài bắt được và độ dài gốc |
| `link` | MAC nguồn/đích, ethertype, tag VLAN |
| `network` | IPv4: TTL, DSCP/ECN, flags, fragment offset, checksum có hợp lệ, options |
| `transport` | TCP/UDP: cổng, seq/ack, flags, window, checksum, options, độ dài payload |
| `application` | `protocol`, `detection` (cách nhận diện + độ tin cậy), và chi tiết protocol (khoá `http`/`dns`/`smtp`) |
| `payload` | `length`, `sha256`, `preview` (có giới hạn), cờ `binary` |
| `errors` | Danh sách lỗi gặp khi parse packet này |

`event_type` nhận một trong các giá trị:

| `event_type` | Khi nào |
|---|---|
| `http_request`, `http_response` | HTTP parse thành công |
| `dns_query`, `dns_response` | DNS parse thành công |
| `smtp_command`, `smtp_response`, `smtp_mixed` | SMTP parse thành công |
| `<proto>_unparsed` | Nhận diện được protocol nhưng payload không parse được |
| `tcp_segment`, `udp_datagram` | Có TCP/UDP nhưng không có payload |
| `unknown_payload` | Có payload nhưng không protocol nào khớp |
| `network_only` | Có IPv4 nhưng không có transport (ví dụ ICMP) |
| `unparsed` | Không parse được tới tầng network (ARP, frame lỗi, linktype lạ) |

Ví dụ một event HTTP thật (rút gọn từ
`python main.py --pcap TEST/fixtures/04-http-get.pcap --output -`, packet thứ hai):

```json
{"schema_version":1,"packet_id":2,"timestamp":1759000001.107919,"event_type":"http_request",
 "network_protocol":"IPv4","transport_protocol":"TCP","application_protocol":"HTTP",
 "src_ip":"10.0.0.1","dst_ip":"10.0.0.2","src_port":51234,"dst_port":80,
 "capture":{"source":"pcap","linktype_name":"EN10MB","captured_length":241,"truncated_by_capture":false},
 "network":{"ttl":64,"total_length":227,"protocol_name":"TCP","header_checksum_valid":true,"fragmented":false},
 "transport":{"flags_string":"PA","seq":1001,"ack":1,"checksum_valid":true,"payload_length":187},
 "application":{"protocol":"HTTP",
   "detection":{"method":"port+payload","confidence":1.0,"port_matched":true,"evidence":"HTTP request line",
                "scores":{"HTTP":1.0,"DNS":0.0,"SMTP":0.0}},
   "http":{"kind":"request","method":"GET","path":"/index.html","query":"q=ids&page=1",
           "query_params":{"q":["ids"],"page":["1"]},"host":"example.com","header_count":5,
           "body":{"length":0}}},
 "payload":{"length":187,"sha256":"…","preview":"GET /index.html?q=ids&page=1 HTTP/1.1\r\nHost: …"},
 "errors":[]}
```

## 5. Nhận diện application protocol

Không phụ thuộc tuyệt đối vào port. Mỗi protocol có một hàm tính điểm trên
payload (0.0 – 1.0); nếu port nằm trong bảng port chuẩn thì cộng thêm 0.25.

| Protocol | Tín hiệu trên payload | Điểm |
|---|---|---|
| HTTP | Dòng đầu là `HTTP/1.x <3 số>` hoặc request line đúng chuẩn | 0.95 |
| HTTP | Request line thiếu version token | 0.80 |
| HTTP | Chỉ có method token | 0.60 |
| DNS | Header parse được, tên câu hỏi hợp lệ, qtype/qclass đã biết | 0.45 → 0.90 |
| DNS | Response có ít nhất một answer | +0.10 |
| SMTP | `HELO/EHLO` hoặc `MAIL FROM` / `RCPT TO` | 0.95 |
| SMTP | `220/250/…` đã biết hoặc dòng nhiều dòng `250-` | 0.85 |
| SMTP | Động từ khác (`DATA`, `QUIT`, `AUTH`, …) | 0.70 |
| SMTP | Dòng 3 số không nằm trong bảng mã SMTP | 0.45 |

- Điểm ≥ 0.5 → nhận diện theo `payload` (hoặc `port+payload` nếu port cũng khớp).
  **HTTP trên port không chuẩn vẫn nhận diện đúng** (điểm 0.95 nhờ chữ ký payload).
- Điểm < 0.5 nhưng port là port chuẩn → gán theo `port` với độ tin cậy 0.3; nếu
  parser sau đó không parse được thì `event_type` là `<proto>_unparsed` và lỗi
  được ghi lại — không tạo event "sạch" giả.
- Không tín hiệu, không port chuẩn → `UNKNOWN` (giữ lại hoặc bỏ qua tuỳ
  `--unknown-policy`).

Điểm chi tiết của cả 3 protocol luôn được ghi trong `application.detection.scores`
để có thể kiểm tra lại quyết định nhận diện.

## 6. Xử lý lỗi

Chương trình **không dừng** khi gặp packet lỗi: mỗi stage bọc trong một guard,
lỗi được ghi vào `errors[]` của đúng packet đó rồi pipeline đi tiếp.

```json
"errors":[{"stage":"transport","code":"truncated_packet",
           "message":"TCP header shorter than 20 bytes",
           "context":{"declared":20,"captured":10}}]
```

| `stage` | `code` thường gặp |
|---|---|
| `capture` | `truncated_packet` (file khai báo nhiều byte hơn thực có) |
| `link` | `truncated_packet`, `malformed_header`, `unsupported_protocol` |
| `network` | `malformed_header` (IHL sai, total_length vô lý), `truncated_packet`, `unsupported_protocol` (IPv6) |
| `transport` | `malformed_header` (TCP data offset < 5), `truncated_packet`, `unsupported_protocol` (ICMP, fragment không phải đầu) |
| `application` | `decode_error`, `truncated_packet`, `truncated_body`, `invalid_content_length`, `malformed_header_line`, `incomplete_message`, `incomplete_reply` |
| `pipeline` / `detect` | `internal_error` (lỗi ngoài dự kiến được cô lập vào một event) |

Một số hành vi được ghi nhận thay vì raise:

- Payload dài hơn `Content-Length` → lấy đúng phần khai báo.
- `Content-Length` lớn hơn số byte bắt được → cờ `body.truncated = true` + lỗi `truncated_body`.
- UDP `checksum = 0` (IPv4) → `checksum_valid = null` (không phải checksum sai).
- Packet bị cắt khi capture → không thể kiểm tra checksum transport → `checksum_valid = null`.
- File PCAP có record khai báo nhiều byte hơn số byte còn lại → đọc record đó rồi
  **dừng**, vì con trỏ file không còn tin cậy; warning được in ra stderr.

## 7. Test

```bash
uv run pytest              # 179 unit test
sh TEST/run_cases.sh       # chạy lại 13 case và ghi lại kết quả
```

`TEST/` chứa fixture và kết quả của 12 test case bắt buộc trong đề bài (cộng thêm
1 case `pcapng`); xem `TEST/README.md` để biết từng case kiểm tra gì và lỗi nào
được mong đợi ở case malformed.

Unit test dựng packet mẫu **độc lập**: các byte vàng (golden bytes) được sinh bằng
Scapy rồi nhúng vào `tests/golden.py`, nhờ vậy parser tự viết được đối chiếu với
một implementation khác — kể cả checksum.

## 8. Hạn chế đã biết

- **Không ghép lại TCP stream.** Mỗi event tương ứng một packet; HTTP request bị
  chia qua nhiều segment sẽ chỉ parse được phần nằm trong packet đó (phần thiếu
  được báo qua `errors` và `body.truncated`).
- **Chỉ hỗ trợ IPv4.** IPv6 được đánh dấu `unsupported_protocol` thay vì parse sai.
- **HTTP/1.x thôi.** TLS không được giải mã; `Transfer-Encoding: chunked` được
  đánh dấu là chunked nhưng không giải mã.
- **Live capture cần quyền** `CAP_NET_RAW` và cần `libpcap`/`tcpdump` nếu muốn
  dùng BPF filter; nếu filter bị từ chối, chương trình tự chạy tiếp không filter
  và ghi warning.
- **PCAPNG** hỗ trợ Section Header, Interface Description, Enhanced Packet, Simple
  Packet; các block khác (Name Resolution, Statistics) được bỏ qua an toàn.

## 9. Khai báo sử dụng AI

OMP(https://github.com/can1357/oh-my-pi) with deepseek-v4.1-flash
