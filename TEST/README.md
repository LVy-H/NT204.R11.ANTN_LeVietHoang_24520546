# TEST: test case theo module

Mỗi nhóm có README riêng (danh sách case, fixture, kết quả mong đợi), script sinh
fixture `generate_fixtures.py`, thư mục `fixtures/` và một thư mục kết quả cho mỗi case.

| Nhóm | Nội dung |
|---|---|
| [`capture-parser/`](capture-parser/README.md) | 13 case của module Packet Capture & Parser |
| [`flow-tracker/`](flow-tracker/README.md) | 14 case T01–T14 của Decoder, Preprocessor, Flow/Connection Tracker |

## Cách chạy

```bash
sh TEST/run_cases.sh                                            # mọi nhóm
sh TEST/run_cases.sh TEST/capture-parser/fixtures/04-http-get.pcap   # một fixture
```

Fixture `.pcap` / `.pcapng` chạy với `--pcap`, fixture `.jsonl` chạy với `--events`.
Fixture tên bắt đầu bằng số ghi kết quả vào `case-<tên>/`, các fixture khác vào `<tên>/`.
Mỗi thư mục kết quả có `command.txt`, `output.jsonl`, `stdout.txt`, `summary.txt`, và
`flows.jsonl` khi CLI hỗ trợ `--flows-output`.
