import pytest
from golden import HTTP_GET, HTTP_POST, HTTP_RESPONSE

from ids.issues import Issue, Issues, ParseError
from ids.model import HttpBody, HttpHeader
from ids.parsers.http import MAX_HEADER_BYTES, first_line, parse, score


def parse_http(payload, issues=None):
    return parse(payload, tcp=True, issues=issues if issues is not None else Issues("application"))


def body_bytes(payload, message):
    return payload[message.body.offset : message.body.offset + message.body.length]


def codes(issues):
    return [issue.code for issue in issues.records]


def test_get_request_fields():
    issues = Issues("application")
    message = parse_http(HTTP_GET, issues)
    assert message.kind == "request"
    assert message.method == "GET"
    assert message.version == "1.1"
    assert message.start_line == "GET /index.html?q=ids&page=1 HTTP/1.1"
    assert message.uri == "/index.html?q=ids&page=1"
    assert message.header("host") == "example.com"
    assert message.header("user-agent") == "test/1.0"
    assert [header.name for header in message.headers] == ["Host", "User-Agent", "Accept"]
    assert message.complete is True
    assert message.body == HttpBody(
        offset=len(HTTP_GET), length=0, transfer_encoding="identity", truncated=False
    )
    assert issues.records == []


def test_post_body_is_cut_at_content_length():
    message = parse_http(HTTP_POST)
    assert message.method == "POST"
    assert message.header("content-type") == "application/x-www-form-urlencoded"
    assert message.body.length == 34
    assert message.body.declared_length == 34
    assert message.body.truncated is False
    assert body_bytes(HTTP_POST, message) == b"username=alice&password=s3cr3t&on="


def test_response_status_and_headers():
    message = parse_http(HTTP_RESPONSE)
    assert message.kind == "response"
    assert message.status_code == 301
    assert message.reason == "Moved Permanently"
    assert message.method is None
    assert message.uri is None
    assert message.header("server") == "nginx/1.24.0"
    assert message.header("location") == "https://example.com/"
    assert body_bytes(HTTP_RESPONSE, message) == b"ok"


def test_status_line_without_reason():
    message = parse_http(b"HTTP/1.0 204\r\n\r\n")
    assert message.status_code == 204
    assert message.reason == ""


def test_request_target_is_kept_raw():
    message = parse_http(b"GET http://example.com/a%20b?x=%41&y=1+2 HTTP/1.1\r\nHost: e\r\n\r\n")
    assert message.uri == "http://example.com/a%20b?x=%41&y=1+2"


def test_header_names_keep_case_and_order_and_lookup_ignores_case():
    message = parse_http(b"GET / HTTP/1.1\r\nhOsT: a\r\nX-Custom: b\r\nACCEPT: c\r\n\r\n")
    assert message.headers == [
        HttpHeader(name="hOsT", value="a"),
        HttpHeader(name="X-Custom", value="b"),
        HttpHeader(name="ACCEPT", value="c"),
    ]
    assert message.header("HOST") == "a"
    assert message.header("accept") == "c"


def test_duplicate_headers_are_kept_in_order():
    message = parse_http(b"GET / HTTP/1.1\r\nX-Tag: one\r\nHost: a\r\nX-Tag: two\r\n\r\n")
    assert [header.name for header in message.headers] == ["X-Tag", "Host", "X-Tag"]
    assert message.header_values("x-tag") == ["one", "two"]
    assert message.header("x-tag") == "two"


def test_folded_header_is_appended_to_the_previous_value():
    message = parse_http(b"GET / HTTP/1.1\r\nHost: a\r\nX-Long: one\r\n  two\r\n\tthree\r\n\r\n")
    assert message.headers == [
        HttpHeader(name="Host", value="a"),
        HttpHeader(name="X-Long", value="one two three"),
    ]


def test_header_without_colon_is_recorded_but_does_not_abort():
    issues = Issues("application")
    message = parse_http(b"GET / HTTP/1.1\r\nnot-a-header\r\nHost: a\r\n\r\n", issues)
    assert message.header("host") == "a"
    assert issues.records == [
        Issue(
            "application",
            "malformed_header_line",
            "HTTP header line has no field name",
            {"line": "not-a-header"},
        )
    ]


def test_leading_continuation_line_is_malformed():
    issues = Issues("application")
    message = parse_http(b"GET / HTTP/1.1\r\n  orphan\r\nHost: a\r\n\r\n", issues)
    assert [header.name for header in message.headers] == ["Host"]
    assert codes(issues) == ["malformed_header_line"]


def test_body_shorter_than_content_length_is_reported():
    issues = Issues("application")
    payload = b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 100\r\n\r\nshort"
    message = parse_http(payload, issues)
    assert message.body.length == 5
    assert message.body.truncated is True
    assert message.body.declared_length == 100
    assert body_bytes(payload, message) == b"short"
    assert codes(issues) == ["truncated_body"]
    assert issues.records[0].context == {"declared": 100, "captured": 5}


def test_missing_header_terminator_is_reported():
    issues = Issues("application")
    payload = b"GET / HTTP/1.1\r\nHost: a"
    message = parse_http(payload, issues)
    assert codes(issues) == ["incomplete_message"]
    assert message.complete is False
    assert message.header("host") == "a"
    assert message.body == HttpBody(
        offset=len(payload), length=0, transfer_encoding="identity", truncated=False
    )


def test_lf_only_message_locates_the_body():
    payload = b"POST /x HTTP/1.0\nHost: a\nContent-Length: 3\n\nabcdef"
    message = parse_http(payload)
    assert message.complete is True
    assert message.header("host") == "a"
    assert message.body.offset == payload.index(b"\n\n") + 2
    assert body_bytes(payload, message) == b"abc"


def test_lf_only_header_terminator_wins_over_a_later_crlf_pair():
    issues = Issues("application")
    payload = b"POST /x HTTP/1.0\nHost: a\nContent-Length: 6\n\nab\r\n\r\n"
    message = parse_http(payload, issues)
    assert message.body.offset == payload.index(b"\n\n") + 2
    assert body_bytes(payload, message) == b"ab\r\n\r\n"
    assert issues.records == []


def test_header_block_beyond_the_limit_is_incomplete():
    issues = Issues("application")
    payload = b"GET / HTTP/1.1\r\nX-Pad: " + b"a" * MAX_HEADER_BYTES + b"\r\n\r\nbody"
    message = parse_http(payload, issues)
    assert message.complete is False
    assert message.header("x-pad") == "a" * (MAX_HEADER_BYTES - len(b"GET / HTTP/1.1\r\nX-Pad: "))
    assert message.body.offset == len(payload)
    assert message.body.length == 0
    assert codes(issues) == ["incomplete_message"]


def test_invalid_content_length_is_reported():
    issues = Issues("application")
    message = parse_http(b"POST / HTTP/1.1\r\nContent-Length: abc\r\n\r\nxx", issues)
    assert codes(issues) == ["invalid_content_length"]
    assert message.body.declared_length is None
    assert message.body.length == 2


def test_negative_content_length_is_invalid_not_incomplete():
    issues = Issues("application")
    message = parse_http(b"POST / HTTP/1.1\r\nContent-Length: -5\r\nHost: a", issues)
    assert codes(issues) == ["invalid_content_length"]
    assert message.body.declared_length is None


def test_last_content_length_wins():
    payload = b"POST / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 3\r\n\r\nabcdef"
    message = parse_http(payload)
    assert body_bytes(payload, message) == b"abc"


def test_chunked_body_is_flagged_not_decoded():
    issues = Issues("application")
    payload = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
    message = parse_http(payload, issues)
    assert message.body.transfer_encoding == "chunked"
    assert message.body.declared_length is None
    assert body_bytes(payload, message) == b"5\r\nhello\r\n0\r\n\r\n"
    assert issues.records == []


@pytest.mark.parametrize(
    "payload",
    [b"", b"\x16\x03\x01\x00\x10garbage", b"NOT-HTTP\r\n\r\n", b"\x00\x01\x02\x03", b"\r\n\r\n"],
)
def test_non_http_payloads_raise_decode_error(payload):
    with pytest.raises(ParseError) as caught:
        parse_http(payload)
    assert caught.value.code == "decode_error"


def test_first_line_helper():
    assert first_line(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n") == b"GET / HTTP/1.1"
    assert first_line(b"GET / HTTP/1.1\nHost: x") == b"GET / HTTP/1.1"
    assert first_line(b"no terminator") == b"no terminator"


@pytest.mark.parametrize(
    "payload,expected",
    [
        (HTTP_RESPONSE, (0.95, "HTTP status line")),
        (HTTP_GET, (0.95, "HTTP request line")),
        (b"PROPFIND /dav HTTP/1.1\r\n\r\n", (0.95, "HTTP request line")),
        (b"FETCH /x HTTP/1.1\r\n\r\n", (0.8, "HTTP request line without a strict version token")),
        (b"GET /index.html\r\n", (0.6, "HTTP method token")),
        (b"hello world\r\n", (0.0, None)),
        (b"\x16\x03\x01\x00\x10", (0.0, None)),
    ],
)
def test_score_tiers(payload, expected):
    assert score(payload, True) == expected


def test_scored_unknown_method_still_parses_as_a_request():
    assert parse_http(b"FETCH /x HTTP/1.1\r\n\r\n").method == "FETCH"
