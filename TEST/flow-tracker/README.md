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
