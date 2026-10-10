from __future__ import annotations

import json

from ids.decoder.text import decode_text
from ids.model import DecodeStatus


def test_ascii_is_unchanged_and_reported_as_ascii():
    result = decode_text(b"GET / ok")

    assert result.text == "GET / ok"
    assert result.charset == "ascii"
    assert result.status is DecodeStatus.UNCHANGED
    assert result.invalid_byte_count == 0
    assert result.first_invalid_offset is None
    assert result.truncated is False


def test_valid_utf8_vietnamese_is_decoded():
    result = decode_text("Xin chào Việt Nam".encode())

    assert result.text == "Xin chào Việt Nam"
    assert result.charset == "utf-8"
    assert result.status is DecodeStatus.DECODED
    assert result.invalid_byte_count == 0


def test_invalid_and_truncated_utf8_is_partial_with_byte_count_and_offset():
    # T04 shape: \xff\xfe never valid in UTF-8, \xe2\x82 is a cut three-byte sequence
    result = decode_text(b"ok \xff\xfe bad \xe2\x82", "utf-8")

    assert result.text == "ok \ufffd\ufffd bad \ufffd"
    assert result.charset == "utf-8"
    assert result.status is DecodeStatus.PARTIAL
    assert result.invalid_byte_count == 4
    assert result.first_invalid_offset == 3


def test_invalid_bytes_between_valid_multibyte_text_keep_the_valid_text():
    data = "ệ".encode() + b"\x80" + "à".encode() + b"\xc3"

    result = decode_text(data)

    assert result.text == "ệ\ufffdà\ufffd"
    assert result.invalid_byte_count == 2
    assert result.first_invalid_offset == 3


def test_long_run_of_invalid_bytes_is_counted_per_byte():
    result = decode_text(b"\xff" * 65535 + b"end")

    assert result.invalid_byte_count == 65535
    assert result.first_invalid_offset == 0
    assert result.text == "\ufffd" * 65535 + "end"


def test_declared_latin1_decodes_high_bytes_strictly():
    result = decode_text(b"caf\xe9", "ISO-8859-1")

    assert result.text == "café"
    assert result.charset == "iso-8859-1"
    assert result.status is DecodeStatus.DECODED


def test_declared_charset_name_is_trimmed_and_lowercased():
    assert decode_text(b"abc", " UTF-8 ").charset == "utf-8"


def test_unknown_declared_charset_falls_back_to_utf8():
    result = decode_text("Việt".encode(), "x-bogus-charset")

    assert result.text == "Việt"
    assert result.charset == "utf-8"
    assert result.status is DecodeStatus.DECODED


def test_non_text_codec_name_falls_back_to_utf8():
    result = decode_text(b"uryyb", "rot13")

    assert result.text == "uryyb"
    assert result.charset == "ascii"


def test_declared_charset_that_fails_strictly_falls_back_to_utf8():
    result = decode_text("Việt".encode(), "ascii")

    assert result.text == "Việt"
    assert result.charset == "utf-8"
    assert result.status is DecodeStatus.DECODED


def test_escape_codec_that_would_yield_lone_surrogates_is_rejected():
    result = decode_text(b"\\ud800 x", "unicode_escape")

    assert result.text == "\\ud800 x"
    assert result.charset == "ascii"
    json.dumps(result.text, ensure_ascii=False).encode("utf-8")


def test_text_exactly_at_the_cap_is_not_truncated():
    data = "ệ".encode() * 3  # 9 bytes

    result = decode_text(data, max_bytes=9)

    assert result.text == "ệệệ"
    assert result.truncated is False


def test_text_over_the_cap_is_cut_on_a_character_boundary():
    data = "ệ".encode() * 3

    result = decode_text(data, max_bytes=8)

    assert result.text == "ệệ"
    assert result.truncated is True
    assert result.status is DecodeStatus.DECODED


def test_cap_counts_replacement_characters_in_utf8_bytes():
    result = decode_text(b"\xff\xff", max_bytes=3)

    assert result.text == "\ufffd"
    assert result.truncated is True
    assert result.invalid_byte_count == 2


def test_zero_cap_keeps_nothing():
    result = decode_text(b"abc", max_bytes=0)

    assert result.text == ""
    assert result.truncated is True


def test_empty_input_is_unchanged_empty_text():
    result = decode_text(b"")

    assert result.text == ""
    assert result.status is DecodeStatus.UNCHANGED
    assert result.truncated is False


def test_declared_punycode_falls_back_to_utf8():
    # punycode decodes in quadratic pure Python; it is never a content charset
    result = decode_text(b"mnchen-3ya", "punycode")

    assert result.text == "mnchen-3ya"
    assert result.charset == "ascii"
    assert result.status is DecodeStatus.UNCHANGED


def test_unicode_escape_with_invalid_escape_does_not_raise():
    result = decode_text(b"\\q", "unicode_escape")

    assert result.text == "\\q"
    assert result.charset == "ascii"
