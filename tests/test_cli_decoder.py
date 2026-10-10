from __future__ import annotations

import json

import pytest

from ids.cli import main


def test_max_decoded_bytes_caps_decoded_body_text(tmp_path):
    event = {
        "schema_version": 2,
        "record_type": "packet",
        "packet_id": 1,
        "timestamp": 1759000000.0,
        "application": {
            "protocol": "HTTP",
            "message": {
                "protocol": "HTTP",
                "kind": "response",
                "headers": [{"name": "Content-Type", "value": "text/plain"}],
                "body": {"offset": 0, "length": 10},
            },
        },
        "payload": {"length": 10, "data_b64": "MDEyMzQ1Njc4OQ=="},
    }
    events = tmp_path / "events.jsonl"
    events.write_text(json.dumps(event) + "\n", encoding="utf-8")
    out = tmp_path / "out.jsonl"

    code = main(["-e", str(events), "-o", str(out), "-q", "--max-decoded-bytes", "4"])

    assert code == 0
    records = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
    [packet] = [r for r in records if r["record_type"] == "packet"]
    assert packet["decoded"]["body"]["text"] == "0123"
    assert packet["decoded"]["body"]["truncated"] is True
    assert "decoder/decoded_truncated" in [f"{i['stage']}/{i['code']}" for i in packet["issues"]]


def test_negative_max_decoded_bytes_exits_with_code_2(tmp_path):
    with pytest.raises(SystemExit) as exit_info:
        main(["-e", str(tmp_path / "events.jsonl"), "--max-decoded-bytes", "-1"])

    assert exit_info.value.code == 2
