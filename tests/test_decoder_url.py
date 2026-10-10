from __future__ import annotations

from ids.decoder.url import decode_form, decode_uri
from ids.model import DecodeStatus


def test_t01_sql_injection_query_is_decoded_once():
    raw = "/search%20page?q=%27%20OR%201%3D1&x=a+b"

    result = decode_uri(raw)

    assert result.text == "/search page?q=' OR 1=1&x=a b"
    assert result.path == "/search page"
    assert result.query == "q=' OR 1=1&x=a b"
    assert result.params == [["q", "' OR 1=1"], ["x", "a b"]]
    assert result.status is DecodeStatus.DECODED
    assert result.double_encoded is False


def test_plus_is_a_space_only_in_the_query():
    result = decode_uri("/a+b?c+d=e+f")

    assert result.path == "/a+b"
    assert result.params == [["c d", "e f"]]


def test_encoded_plus_and_ampersand_stay_inside_their_value():
    result = decode_uri("/?q=1%2B1%3D2%26x&y=%3D")

    assert result.params == [["q", "1+1=2&x"], ["y", "="]]


def test_plain_uri_is_unchanged():
    result = decode_uri("/index.html")

    assert result.text == "/index.html"
    assert result.path == "/index.html"
    assert result.query is None
    assert result.params == []
    assert result.status is DecodeStatus.UNCHANGED
    assert result.double_encoded is False


def test_query_without_escapes_is_unchanged_and_split():
    result = decode_uri("/index.html?q=ids&page=1")

    assert result.status is DecodeStatus.UNCHANGED
    assert result.params == [["q", "ids"], ["page", "1"]]


def test_invalid_escapes_are_kept_literally_and_mark_partial():
    result = decode_uri("/a%G1b%4?x=%&y=%41")

    assert result.path == "/a%G1b%4"
    assert result.params == [["x", "%"], ["y", "A"]]
    assert result.status is DecodeStatus.PARTIAL


def test_trailing_percent_is_partial():
    result = decode_uri("/download%")

    assert result.path == "/download%"
    assert result.status is DecodeStatus.PARTIAL


def test_escape_left_after_one_pass_flags_double_encoding_without_second_pass():
    result = decode_uri("/%252e%252e/etc?f=%2541")

    assert result.path == "/%2e%2e/etc"
    assert result.params == [["f", "%41"]]
    assert result.double_encoded is True
    assert result.status is DecodeStatus.DECODED


def test_literal_percent_that_is_not_an_escape_is_not_double_encoding():
    assert decode_uri("/100%25").double_encoded is False


def test_duplicate_names_blank_values_and_empty_segments():
    result = decode_uri("/?a=1&&b=&c&a=2")

    assert result.params == [["a", "1"], ["b", ""], ["c", ""], ["a", "2"]]


def test_percent_encoded_utf8_becomes_text():
    result = decode_uri("/t%C3%ACm?q=Vi%E1%BB%87t")

    assert result.path == "/tìm"
    assert result.params == [["q", "Việt"]]
    assert result.status is DecodeStatus.DECODED


def test_raw_utf8_target_from_the_parser_is_decoded():
    # the parser stores the request target latin-1 decoded
    raw = "/tìm".encode().decode("latin-1")

    result = decode_uri(raw)

    assert result.path == "/tìm"
    assert result.status is DecodeStatus.DECODED


def test_escape_of_invalid_utf8_byte_is_replaced_and_partial():
    result = decode_uri("/%FF")

    assert result.path == "/\ufffd"
    assert result.status is DecodeStatus.PARTIAL


def test_absolute_form_path_excludes_scheme_and_authority():
    result = decode_uri("http://Example.com:8080/a%20b?x=1")

    assert result.text == "http://Example.com:8080/a b?x=1"
    assert result.path == "/a b"
    assert result.params == [["x", "1"]]


def test_absolute_form_without_path_has_empty_path():
    assert decode_uri("http://example.com").path == ""


def test_form_body_is_split_and_decoded():
    result = decode_form(b"user=nguy%E1%BB%85n+v%C4%83n&pass=a%26b&pass=&remember")

    assert result.params == [
        ["user", "nguyễn văn"],
        ["pass", "a&b"],
        ["pass", ""],
        ["remember", ""],
    ]
    assert result.status is DecodeStatus.DECODED


def test_form_without_escapes_is_unchanged():
    result = decode_form(b"username=alice&password=s3cr3t&on=1")

    assert result.params == [["username", "alice"], ["password", "s3cr3t"], ["on", "1"]]
    assert result.status is DecodeStatus.UNCHANGED


def test_form_with_invalid_escape_is_partial():
    result = decode_form(b"a=%zz")

    assert result.params == [["a", "%zz"]]
    assert result.status is DecodeStatus.PARTIAL


def test_empty_form_is_unchanged_with_no_params():
    result = decode_form(b"")

    assert result.params == []
    assert result.status is DecodeStatus.UNCHANGED
