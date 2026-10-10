# IDS/IPS bằng Python

Hệ thống phát hiện xâm nhập (IDS) viết bằng Python, được xây dựng dần theo từng module.
Mỗi module chỉ đọc output chuẩn hoá của module đứng trước, nên các tầng phía sau
(Detection Engine, cảnh báo) không cần truy cập packet thô hay Scapy.

## Kiến trúc

```
Live interface / PCAP / event JSONL
  → Capture → Parser → Decoder → Preprocessor → Flow/Connection Tracker
  → Feature Extractor → Detection Engine → Alert
```

| Module | Vai trò | Trạng thái |
|---|---|---|
| Capture | Bắt packet từ interface (Scapy), đọc `.pcap` / `.pcapng` bằng reader tự viết, hoặc nạp lại event JSONL; mọi nguồn đi chung một pipeline | Hoàn thành |
| Parser | Ethernet / VLAN / Linux SLL, IPv4, TCP, UDP, HTTP/1.x, DNS, SMTP; nhận diện application protocol bằng port + chữ ký payload | Hoàn thành |
| Decoder | URL / percent-encoding, form-urlencoded, HTML entity, MIME Base64 / Quoted-Printable, ASCII / UTF-8; field gốc giữ nguyên, kết quả nằm trong `decoded` | Hoàn thành |
| Preprocessor | Kiểm tra field, chuẩn hoá protocol / IP / domain / header / URI / timestamp, gắn trạng thái valid / partial / invalid và hành động forward / mark / drop | Hoàn thành |
| Flow/Connection Tracker | Gom packet thành flow hai chiều theo 5-tuple, theo dõi trạng thái TCP, idle timeout, thống kê theo flow, ghép thân SMTP DATA thành message | Hoàn thành |
| Feature Extractor | Trích xuất đặc trưng từ flow cho Detection Engine | Dự kiến |
| Detection Engine, Alert | Phát hiện tấn công và sinh cảnh báo | Dự kiến |

## Cài đặt

```bash
uv sync                          # dùng uv.lock, cố định phiên bản Scapy
pip install -r requirements.txt  # hoặc pip, cần Python >= 3.10
```

## Chạy

```bash
# đọc file PCAP / PCAPNG, flow ghi ra file riêng, in thống kê
python main.py --pcap test.pcap -o out.jsonl --flows-output flows.jsonl --stats

# live capture, chỉ lấy HTTP
sudo python main.py --interface eth0 --filter "tcp port 80" -o live.jsonl

# nạp lại event JSONL (schema v2) và chạy lại Decoder, Preprocessor, Flow Tracker
python main.py --events out.jsonl -o replay.jsonl --stats

python main.py --list-interfaces
```

| Tham số | Mặc định | Ý nghĩa |
|---|---|---|
| `--interface`, `-i` | | Bắt live traffic từ interface |
| `--pcap`, `-r` | | Đọc từ file `.pcap` / `.pcapng` |
| `--events`, `-e` | | Đọc event JSON Lines schema v2 (`-` = stdin) |
| `--list-interfaces`, `-L` | | Liệt kê interface rồi thoát |
| `--output`, `-o` | `-` | File JSON Lines (`-` = stdout) |
| `--flows-output` | | Ghi record `flow` ra file này thay vì `--output` |
| `--stats` | | In thống kê tổng kết (JSON) ra stderr |
| `--quiet`, `-q` | | Tắt thông báo tiến độ |
| `--count`, `-c` | | Dừng sau N packet / event |
| `--filter` | | BPF filter (chỉ live capture) |
| `--capture-idle-timeout` | | Dừng live capture sau N giây không có traffic |
| `--max-payload-bytes` | 65535 | Số byte payload giữ trong `payload.data_b64` |
| `--preview-limit` | 256 | Số byte payload giữ trong `payload.preview` |
| `--max-decoded-bytes` | 1048576 | Giới hạn kích thước text sau decode |
| `--max-message-bytes` | 1048576 | Giới hạn thân SMTP DATA được ghép |
| `--max-flows` | 100000 | Số flow theo dõi cùng lúc; vượt quá thì flow ít hoạt động nhất bị xuất với `evicted` |
| `--invalid-policy` | `mark` | `mark` hoặc `drop` event `invalid` |
| `--unsupported-policy` | `mark` | `mark` hoặc `drop` packet không có IPv4 / TCP / UDP |
| `--unknown-policy` | `emit` | `skip` bỏ record packet có application `UNKNOWN`, flow vẫn được theo dõi |
| `--tcp-idle-timeout` | 300 | Số giây không có packet trước khi flow TCP hết hạn |
| `--udp-idle-timeout` | 60 | Như trên, cho UDP |
| `--tcp-closed-timeout` | 5 | Số giây giữ flow TCP đã đóng / reset để nhận ACK và retransmission còn sót |
| `--version` | | In phiên bản rồi thoát |

Tham số số nhận giá trị âm thì bị từ chối (exit 2). Mã thoát: 0 thành công, 1 lỗi khi chạy,
2 sai tham số, 130 bị ngắt bằng Ctrl+C.

Live capture cần `CAP_NET_RAW` (chạy bằng `sudo` hoặc `setcap`). Sau `uv sync` có thể
gọi `python main.py ...` hoặc console script `ids`.

## Output

Mỗi dòng JSON là một record có `schema_version: 2` và `record_type`:

| `record_type` | Nội dung |
|---|---|
| `packet` | Một packet hoặc một event đã nạp: 5-tuple, `event_type`, các khối `capture`, `link`, `network`, `transport`, `application`, `payload`, `decoded`, `normalized`, `flow`, `issues`, kèm `preprocess_status` / `processing_action` / `reason` |
| `message` | Thân SMTP DATA ghép từ nhiều segment, kèm kết quả decode MIME |
| `flow` | Thống kê một flow khi kết thúc: hai endpoint, thời gian, số packet / byte theo từng chiều, bộ đếm cờ TCP, trạng thái cuối, `end_reason` |

Field gốc không bị sửa: giá trị đã decode nằm trong `decoded`, giá trị chuẩn hoá nằm trong
`normalized`. Lỗi ở mọi tầng được ghi vào `issues[]` kèm `stage` / `code`; một packet lỗi
không làm dừng chương trình. Field tuỳ chọn không có giá trị luôn là `null` hoặc `[]`, nên
mọi record cùng loại có cùng tập key.

Port chỉ là tín hiệu phụ khi nhận diện application protocol, chữ ký payload mới quyết
định, nên HTTP trên port không chuẩn vẫn được nhận đúng. Lý do quyết định nằm trong
`application.detection` (`method`, `confidence`, `evidence`, `scores`).

Mô tả đầy đủ từng field, giá trị trạng thái và mã lỗi: `docs/schema.md`. Ví dụ output:
`TEST/capture-parser/case-04-http-get/output.jsonl`,
`TEST/flow-tracker/T03-smtp-mime/output.jsonl`,
`TEST/flow-tracker/T09-tcp-close-reset/flows.jsonl`.

## Cấu trúc repo

```
main.py              entrypoint
ids/
  model/             dataclass cho packet, message, flow (schema v2)
  codec.py           ghi / đọc JSON schema v2
  capture/           live capture, reader pcap / pcapng, nguồn event JSONL
  parsers/           link, IPv4, TCP / UDP, HTTP, DNS, SMTP, detector
  decoder/           URL, form, HTML entity, MIME, charset
  preprocess/        kiểm tra field, chuẩn hoá, policy
  flow/              flow key, trạng thái TCP, bảng flow, ghép SMTP DATA
  pipeline.py        Runner chạy các stage theo thứ tự
  cli.py             tham số dòng lệnh
docs/                spec, kế hoạch triển khai, mô tả schema
tests/               unit test (pytest)
TEST/                fixture, lệnh chạy và kết quả của từng test case
```

## Kiểm thử

```bash
uv run pytest            # unit test, kèm kiểm tra kết quả mong đợi của mọi test case
sh TEST/run_cases.sh     # chạy lại toàn bộ test case, ghi kết quả vào TEST/
```

Danh sách case, fixture và kết quả mong đợi: `TEST/capture-parser/README.md` (13 case của
Packet Capture & Parser) và `TEST/flow-tracker/README.md` (T01–T14 của Decoder,
Preprocessor, Flow/Connection Tracker).

## Quy trình phát triển

- Mỗi task (một module hoặc một chức năng nhỏ) được commit riêng ngay khi hoàn thành.
- Mỗi test case được commit riêng cùng kết quả chạy trong `TEST/`.
- Lịch sử commit không bị sửa hay viết lại.

## Hạn chế hiện tại

Chỉ hỗ trợ IPv4 (packet IPv6 được ghi nhận là unsupported). Không giải mã TLS, DoH / DoT.
Không ghép TCP stream tổng quát, chỉ ghép thân SMTP DATA. Chưa hỗ trợ HTTP `chunked`,
`Content-Encoding` (gzip / deflate) và SMTP `BDAT`. Mọi cấu hình đặt qua tham số dòng
lệnh, chưa có file cấu hình. Chưa có Feature Extractor và Detection Engine.

## Khai báo sử dụng AI

OMP(https://github.com/can1357/oh-my-pi) with deepseek-v4.1-flash

| Công cụ | Mô hình | Mục đích | Phần liên quan |
|---|---|---|---|
| OMP (oh-my-pi) | Claude Opus (Anthropic) | Phân tích codebase, thiết kế, viết kế hoạch và mã nguồn | `ids/` (viết lại theo model có kiểu), `ids/decoder/`, `ids/preprocess/`, `ids/flow/`, `tests/`, fixture trong `TEST/`, `docs/` |
