# IDS/IPS bằng Python

Hệ thống phát hiện xâm nhập (IDS) viết bằng Python, được xây dựng dần theo từng module.
Mỗi module chỉ đọc output chuẩn hoá của module đứng trước, nên các tầng phía sau
(Detection Engine, cảnh báo) không cần truy cập packet thô hay Scapy.

## Kiến trúc

```
Live interface / PCAP
  → Capture → Parser → Decoder → Preprocessor → Flow/Connection Tracker
  → Feature Extractor → Detection Engine → Alert
```

| Module | Vai trò | Trạng thái |
|---|---|---|
| Capture | Bắt packet từ interface (Scapy) hoặc đọc `.pcap` / `.pcapng` bằng reader tự viết; cả hai nguồn đi chung một pipeline | Hoàn thành |
| Parser | Ethernet / VLAN / Linux SLL, IPv4, TCP, UDP, HTTP/1.x, DNS, SMTP; nhận diện application protocol bằng port + chữ ký payload | Hoàn thành |
| Decoder | URL / percent-encoding, form-urlencoded, HTML entity, MIME Base64 / Quoted-Printable, ASCII / UTF-8 | Đang phát triển |
| Preprocessor | Kiểm tra field, chuẩn hoá protocol / IP / domain / header / URI / timestamp, gắn trạng thái valid / partial / invalid | Đang phát triển |
| Flow/Connection Tracker | Gom packet thành flow hai chiều theo 5-tuple, theo dõi trạng thái TCP, idle timeout, thống kê theo flow | Đang phát triển |
| Feature Extractor | Trích xuất đặc trưng từ flow cho Detection Engine | Dự kiến |
| Detection Engine, Alert | Phát hiện tấn công và sinh cảnh báo | Dự kiến |

## Cài đặt

```bash
uv sync                          # dùng uv.lock, cố định phiên bản Scapy
pip install -r requirements.txt  # hoặc pip, cần Python >= 3.10
```

## Chạy

```bash
python main.py --interface eth0           # live capture
python main.py --pcap test.pcap           # đọc file PCAP / PCAPNG
python main.py --list-interfaces          # liệt kê interface
```

| Tham số | Ý nghĩa |
|---|---|
| `--interface`, `-i` | Bắt live traffic từ interface |
| `--pcap`, `-r` | Đọc từ file `.pcap` / `.pcapng` |
| `--list-interfaces`, `-L` | Liệt kê interface rồi thoát |
| `--output`, `-o` | File JSON Lines (mặc định `-` = stdout) |
| `--count`, `-c` | Dừng sau N packet |
| `--filter` | BPF filter (chỉ live capture) |
| `--unknown-policy` | `emit` (mặc định) hoặc `skip` packet không nhận diện được protocol |
| `--idle-timeout` | Dừng live capture sau N giây không có traffic |
| `--preview-limit` | Số byte payload tối đa giữ trong `preview` |
| `--stats` | In thống kê tổng kết ra stderr |
| `--quiet`, `-q` | Tắt thông báo tiến độ |

Live capture cần `CAP_NET_RAW` (chạy bằng `sudo` hoặc `setcap`). Sau `uv sync` có thể
gọi `python main.py ...` hoặc console script `ids`.

## Output

Mỗi dòng JSON là một event ứng với một packet, gồm `packet_id`, `timestamp`,
`event_type`, `network_protocol` / `transport_protocol` / `application_protocol`,
`src_ip` / `dst_ip` / `src_port` / `dst_port` và các khối chi tiết `capture`, `link`,
`network`, `transport`, `application`, `payload`, `errors`.

`event_type` cho biết packet đã được xử lý tới đâu (`http_request`, `dns_response`,
`tcp_segment`, `unknown_payload`, `network_only`, `unparsed`, …). Lỗi ở mọi tầng được
ghi vào `errors[]` kèm `stage` / `code`; một packet lỗi không làm dừng chương trình.

Port chỉ là tín hiệu phụ khi nhận diện application protocol, chữ ký payload mới quyết
định, nên HTTP trên port không chuẩn vẫn được nhận đúng. Lý do quyết định nằm trong
`application.detection` (`method`, `confidence`, `evidence`, `scores`).

Ví dụ output: `TEST/case-04-http-get/output.jsonl`, `TEST/case-12-malformed/output.jsonl`.

## Cấu trúc repo

```
main.py              entrypoint
ids/
  capture/           live capture và reader pcap / pcapng
  parsers/           link, IPv4, TCP / UDP, HTTP, DNS, SMTP, detector
  pipeline.py        ghép các tầng thành một pipeline xử lý packet
  event.py           event chuẩn hoá
  cli.py             tham số dòng lệnh
tests/               unit test (pytest)
TEST/                fixture, lệnh chạy và kết quả của từng test case
```

## Kiểm thử

```bash
uv run pytest            # unit test
sh TEST/run_cases.sh     # chạy lại toàn bộ test case, ghi kết quả vào TEST/
```

Danh sách case, fixture và kết quả mong đợi: `TEST/README.md`.

## Quy trình phát triển

- Mỗi task (một module hoặc một chức năng nhỏ) được commit riêng ngay khi hoàn thành.
- Mỗi test case được commit riêng cùng kết quả chạy trong `TEST/`.
- Lịch sử commit không bị sửa hay viết lại.

## Hạn chế hiện tại

Chưa ghép lại TCP stream (mỗi event là một packet); chỉ hỗ trợ IPv4; không giải mã TLS
và không giải mã HTTP `chunked`.

## Khai báo sử dụng AI

OMP(https://github.com/can1357/oh-my-pi) with deepseek-v4.1-flash
