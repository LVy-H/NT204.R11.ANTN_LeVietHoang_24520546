from __future__ import annotations

import hashlib

import pytest

from ids.model import Payload
from ids.payload import looks_binary, make_payload


def test_empty_payload():
    assert make_payload(b"") == Payload(
        length=0,
        sha256=hashlib.sha256(b"").hexdigest(),
        data=b"",
        data_truncated=False,
        preview="",
        preview_truncated=False,
        preview_encoding="utf-8",
        binary=False,
        preview_hex=None,
    )


def test_payload_at_max_bytes_is_kept_whole():
    data = b"A" * 16
    payload = make_payload(data, max_bytes=16)
    assert payload.data == data
    assert payload.data_truncated is False
    assert payload.length == 16


def test_payload_over_max_bytes_keeps_the_prefix_but_hashes_everything():
    data = b"A" * 16 + b"B"
    payload = make_payload(data, max_bytes=16)
    assert payload.data == b"A" * 16
    assert payload.data_truncated is True
    assert payload.length == 17
    assert payload.sha256 == hashlib.sha256(data).hexdigest()


def test_max_bytes_zero_keeps_no_bytes():
    payload = make_payload(b"abc", max_bytes=0)
    assert payload.data == b""
    assert payload.data_truncated is True
    assert payload.length == 3


def test_preview_at_limit_is_not_truncated():
    payload = make_payload(b"PAYL", preview_limit=4)
    assert (payload.preview, payload.preview_truncated) == ("PAYL", False)


def test_preview_over_limit_is_cut_and_flagged():
    payload = make_payload(b"PAYLOAD-01", preview_limit=4)
    assert (payload.preview, payload.preview_truncated) == ("PAYL", True)
    assert payload.data == b"PAYLOAD-01"


def test_utf8_preview():
    payload = make_payload("price: 5€ only".encode())
    assert (payload.preview, payload.preview_encoding, payload.binary) == (
        "price: 5€ only",
        "utf-8",
        False,
    )
    assert payload.preview_hex is None


def test_invalid_utf8_text_falls_back_to_latin1():
    payload = make_payload(b"caf\xe9 au lait")
    assert (payload.preview, payload.preview_encoding, payload.binary) == (
        "café au lait",
        "latin-1",
        False,
    )
    assert payload.preview_hex is None


def test_binary_preview_is_masked_and_hex_is_added():
    data = b"\x00\x01GET\x7f\xff"
    payload = make_payload(data)
    assert payload.binary is True
    assert payload.preview_encoding == "binary"
    assert payload.preview == "..GET.."
    assert payload.preview_hex == data.hex()


def test_preview_hex_is_capped_at_64_bytes():
    data = bytes(range(200))
    payload = make_payload(data)
    assert payload.preview_hex == data[:64].hex()


def test_binary_is_decided_on_the_full_data_not_the_preview():
    data = b"GET / HTTP/1.1\r\n" + b"\x00" * 64
    payload = make_payload(data, preview_limit=4)
    assert payload.binary is True
    assert payload.preview_encoding == "binary"
    assert payload.preview == "GET "


def test_utf8_cut_inside_a_character_drops_the_partial_character():
    data = b"a" * 255 + "é".encode()
    payload = make_payload(data, preview_limit=256)
    assert payload.preview == "a" * 255
    assert payload.preview_encoding == "utf-8"
    assert payload.preview_truncated is True


def test_invalid_byte_before_the_cut_still_falls_back_to_latin1():
    data = b"abcdefghijklmnop\xff" + "é".encode()
    payload = make_payload(data, preview_limit=18)
    assert payload.preview_encoding == "latin-1"
    assert payload.preview == "abcdefghijklmnopÿÃ"


@pytest.mark.parametrize(
    ("data", "binary"),
    [
        (b"", False),
        (b"abc\x01", False),
        (b"ab\x01", True),
        (b"text\x00", True),
        (b"line one\r\n\tline two\n", False),
    ],
)
def test_looks_binary_threshold(data, binary):
    assert looks_binary(data) is binary
