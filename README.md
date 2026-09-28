# PCP: Packet Capture & Parser cho hệ thống IDS/IPS

Bài tập 1. Module thu thập packet từ live traffic hoặc file PCAP, phân tích
IPv4, TCP, UDP, HTTP/1.x, DNS, SMTP và xuất ra event JSON Lines chuẩn hoá để
các bài tập IDS sau chỉ việc đọc event, không cần đụng packet thô.

```
Raw Packet → Network Parser → Transport Parser → Application Detector
           → Application Parser → Normalized IDS Event
```

Cả hai nguồn dùng cùng một pipeline. Scapy chỉ làm I/O cho live capture rồi
chuyển ngay thành bytes; file PCAP do reader tự viết trong `pcparser/capture/pcap.py`
đọc (hỗ trợ cả `.pcap` và `.pcapng`, không cần Scapy).

## Cài đặt

```bash
uv sync                          # dùng uv.lock, cố định phiên bản Scapy
pip install -r requirements.txt  # hoặc dùng pip, cần Python >= 3.10
```

## Chạy

```bash
python main.py --interface eth0           # live capture
python main.py --pcap test.pcap           # đọc file PCAP
python main.py --list-interfaces          # liệt kê interface
```

| Tham số | Ý nghĩa |
|---|---|
| `--interface`, `-i` | Bắt live traffic từ interface |
| `--pcap`, `-r` | Đọc từ file `.pcap` / `.pcapng` |
| `--output`, `-o` | File JSON Lines (mặc định `-` = stdout) |
| `--count`, `-c` | Dừng sau N packet |
| `--unknown-policy` | `emit` (mặc định) hoặc `skip` packet không nhận diện được |
| `--stats` | In thống kê tổng kết ra stderr |

Live capture cần `CAP_NET_RAW` (chạy bằng `sudo` hoặc `setcap`). Sau `uv sync` có
thể gọi `python main.py ...` hoặc console script `pcparser`.

## Output

Mỗi dòng JSON là một packet, với các khoá: `packet_id`, `timestamp`, `event_type`,
`network_protocol` / `transport_protocol` / `application_protocol`, `src_ip` /
`dst_ip` / `src_port` / `dst_port`, `capture`, `link`, `network`, `transport`,
`application`, `payload`, `errors`.

Ví dụ: `TEST/case-04-http-get/output.jsonl` và `TEST/case-12-malformed/output.jsonl`.
`event_type` cho biết packet đã parse tới đâu (`http_request`, `dns_response`,
`tcp_segment`, `unknown_payload`, `network_only`, `unparsed`, …). Lỗi nằm trong
`errors[]` kèm `stage`/`code`, nên không packet lỗi nào làm chương trình dừng.

## Nhận diện application protocol

Port chỉ là tín hiệu cộng thêm, chữ ký payload mới quyết định, nên HTTP trên port
không chuẩn vẫn nhận diện đúng. Quyết định và điểm của từng protocol được ghi lại
trong `application.detection` (`method`, `confidence`, `evidence`, `scores`).

## Test

```bash
uv run pytest            # unit test
sh TEST/run_cases.sh     # chạy lại 12 test case bắt buộc + 1 case pcapng
```

Chi tiết từng case và kết quả mong đợi: `TEST/README.md`.

## Hạn chế

Không ghép lại TCP stream (mỗi event là một packet); chỉ hỗ trợ IPv4; HTTP/1.x
không giải mã TLS và không giải mã `chunked`.

## Khai báo sử dụng AI

OMP(https://github.com/can1357/oh-my-pi) with deepseek-v4.1-flash
