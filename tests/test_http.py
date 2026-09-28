import pytest
from golden import HTTP_GET, HTTP_POST, HTTP_RESPONSE

from pcparser.errors import DecodeError
from pcparser.parsers.http import first_line, parse


def test_get_request_fields():
    info = parse(HTTP_GET)
    assert info["kind"] == "request"
    assert info["method"] == "GET"
    assert info["version"] == "1.1"
    assert info["uri"] == "/index.html?q=ids&page=1"
    assert info["path"] == "/index.html"
    assert info["query"] == "q=ids&page=1"
    assert info["query_params"] == {"q": ["ids"], "page": ["1"]}
    assert info["host"] == "example.com"
    assert info["user_agent"] == "test/1.0"
    assert info["header_order"] == ["host", "user-agent", "accept"]
    assert info["body"]["length"] == 0
    assert info["errors"] == []


def test_post_body_and_form_are_extracted():
    info = parse(HTTP_POST)
    assert info["method"] == "POST"
    assert info["content_type"] == "application/x-www-form-urlencoded"
    assert info["body"]["length"] == 34
    assert info["body"]["declared_length"] == 34
    assert info["body"]["truncated"] is False
    assert info["form"] == {"username": ["alice"], "password": ["s3cr3t"], "on": [""]}


def test_response_status_and_headers():
    info = parse(HTTP_RESPONSE)
    assert info["kind"] == "response"
    assert info["status_code"] == 301
    assert info["reason"] == "Moved Permanently"
    assert info["server"] == "nginx/1.24.0"
    assert info["headers"]["location"] == "https://example.com/"
    assert info["body"]["preview"] == "ok"


def test_absolute_form_target_is_split():
    info = parse(b"GET http://example.com/a/b?x=1 HTTP/1.1\r\nHost: example.com\r\n\r\n")
    assert info["scheme"] == "http"
    assert info["authority"] == "example.com"
    assert info["path"] == "/a/b"
    assert info["query_params"] == {"x": ["1"]}


def test_duplicate_headers_are_kept_as_a_list():
    info = parse(b"GET / HTTP/1.1\r\nX-Tag: one\r\nX-Tag: two\r\n\r\n")
    assert info["headers"]["x-tag"] == ["one", "two"]


def test_folded_header_is_appended():
    info = parse(b"GET / HTTP/1.1\r\nHost: a\r\nX-Long: one\r\n  two\r\n\r\n")
    assert info["headers"]["x-long"] == "one two"


def test_header_without_colon_is_recorded_but_does_not_abort():
    info = parse(b"GET / HTTP/1.1\r\nnot-a-header\r\nHost: a\r\n\r\n")
    assert info["host"] == "a"
    assert [error["code"] for error in info["errors"]] == ["malformed_header_line"]


def test_body_shorter_than_content_length_is_reported():
    info = parse(b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 100\r\n\r\nshort")
    assert info["body"]["length"] == 5
    assert info["body"]["truncated"] is True
    assert info["body"]["declared_length"] == 100
    assert [error["code"] for error in info["errors"]] == ["truncated_body"]


def test_missing_header_terminator_is_reported():
    info = parse(b"GET / HTTP/1.1\r\nHost: a")
    assert [error["code"] for error in info["errors"]] == ["incomplete_message"]
    assert info["host"] == "a"


def test_invalid_content_length_is_reported():
    info = parse(b"POST / HTTP/1.1\r\nContent-Length: abc\r\n\r\nxx")
    assert [error["code"] for error in info["errors"]] == ["invalid_content_length"]


def test_chunked_body_is_flagged_not_decoded():
    info = parse(b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n")
    assert info["body"]["encoding"] == "chunked"
    assert info["body"]["chunked_decoded"] is False


@pytest.mark.parametrize(
    "payload",
    [b"", b"\x16\x03\x01\x00\x10garbage", b"NOT-HTTP\r\n\r\n", b"\x00\x01\x02\x03"],
)
def test_non_http_payloads_raise_decode_error(payload):
    with pytest.raises(DecodeError):
        parse(payload)


def test_first_line_helper():
    assert first_line(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n") == b"GET / HTTP/1.1"
    assert first_line(b"GET / HTTP/1.1\nHost: x") == b"GET / HTTP/1.1"
    assert first_line(b"no terminator") == b"no terminator"
