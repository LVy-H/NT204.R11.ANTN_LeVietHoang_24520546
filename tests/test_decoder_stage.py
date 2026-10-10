from __future__ import annotations

import gzip
import json
import struct

from ids.decoder import DecoderConfig, DecoderStage
from ids.issues import Issue
from ids.model import (
    ApplicationInfo,
    DecodedHttp,
    DecodedMime,
    DecodeStatus,
    DnsMessage,
    HttpBody,
    HttpHeader,
    HttpMessage,
    MessageEvent,
    PacketEvent,
    Payload,
    RawPacket,
    SmtpSession,
)
from ids.parsers import PacketParser
from ids.pipeline import Runner
from ids.sink import JsonlSink
from ids.stats import Stats

HEAD = b"HTTP/1.1 200 OK\r\nX-Pad: 1\r\n\r\n"  # stands in for the header bytes before the body


def ignore(record: object) -> None:
    return None


def http_event(
    *,
    kind: str = "request",
    uri: str | None = None,
    headers: tuple[tuple[str, str], ...] = (),
    body: bytes = b"",
    stored: int | None = None,
) -> PacketEvent:
    data = HEAD + body
    kept = data if stored is None else data[:stored]
    message = HttpMessage(
        kind=kind,
        uri=uri,
        headers=[HttpHeader(name, value) for name, value in headers],
        body=HttpBody(offset=len(HEAD), length=len(body)) if body else None,
        complete=True,
    )
    return PacketEvent(
        packet_id=1,
        timestamp=1759000000.0,
        application=ApplicationInfo(protocol="HTTP", message=message),
        payload=Payload(length=len(data), data=kept, data_truncated=len(kept) < len(data)),
    )


def smtp_event(data: bytes, *, kind: str = "data", truncated: bool = False) -> PacketEvent:
    return PacketEvent(
        packet_id=2,
        timestamp=1759000001.0,
        application=ApplicationInfo(protocol="SMTP", message=SmtpSession(kind=kind)),
        payload=Payload(length=len(data), data=data, data_truncated=truncated),
    )


def run(record: PacketEvent | MessageEvent, **config: int) -> PacketEvent | MessageEvent:
    DecoderStage(DecoderConfig(**config)).process(record, ignore)
    return record


def codes(record: PacketEvent | MessageEvent) -> list[tuple[str | None, str | None]]:
    return [(issue.stage, issue.code) for issue in record.issues]


def test_t01_request_uri_is_decoded_and_raw_uri_kept():
    raw = "/search%20page?q=%27%20OR%201%3D1&x=a+b"
    event = run(http_event(uri=raw))

    decoded = event.decoded
    assert isinstance(decoded, DecodedHttp)
    assert decoded.uri.path == "/search page"
    assert decoded.uri.params == [["q", "' OR 1=1"], ["x", "a b"]]
    assert decoded.form is None
    assert decoded.body is None
    assert decoded.status is DecodeStatus.DECODED
    assert event.application.message.uri == raw
    assert event.issues == []


def test_invalid_uri_escape_is_partial_with_issue():
    event = run(http_event(uri="/a%G1"))

    assert event.decoded.status is DecodeStatus.PARTIAL
    assert codes(event) == [("decoder", "invalid_escape")]
    assert event.issues[0].context == {"field": "uri"}


def test_uri_escape_of_invalid_utf8_reports_charset_bytes():
    event = run(http_event(uri="/%FF"))

    assert codes(event) == [("decoder", "invalid_charset_bytes")]


def test_chunked_body_is_not_decoded():
    event = http_event(
        uri="/login",
        headers=(("Content-Type", "application/x-www-form-urlencoded"),),
        body=b"9\r\nuser=aA\r\n0\r\n\r\n",
    )
    event.application.message.body.transfer_encoding = "chunked"

    run(event)

    assert event.decoded.body is None
    assert event.decoded.form is None
    assert event.issues == []


def test_response_has_no_uri():
    event = run(http_event(kind="response", headers=(("Content-Type", "text/plain"),), body=b"ok"))

    assert event.decoded.uri is None
    assert event.decoded.body.text == "ok"


def test_urlencoded_form_body_is_decoded_into_params():
    event = run(
        http_event(
            uri="/login",
            headers=(("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8"),),
            body=b"user=nguy%E1%BB%85n&pass=a+b&pass=",
        )
    )

    assert event.decoded.form.params == [["user", "nguyễn"], ["pass", "a b"], ["pass", ""]]
    assert event.decoded.form.status is DecodeStatus.DECODED
    assert event.decoded.body.text == "user=nguy%E1%BB%85n&pass=a+b&pass="
    assert event.decoded.body.entity_count is None


def test_invalid_escape_in_form_is_reported():
    event = run(
        http_event(
            uri="/f",
            headers=(("content-type", "application/x-www-form-urlencoded"),),
            body=b"a=%zz",
        )
    )

    assert event.decoded.form.status is DecodeStatus.PARTIAL
    assert codes(event) == [("decoder", "invalid_escape")]
    assert event.issues[0].context == {"field": "form"}


def test_t02_html_body_entities_are_decoded_and_counted():
    body = b"&lt;script&gt;alert(1)&lt;/script&gt; &amp; &#x27; &bogus;"
    event = run(http_event(kind="response", headers=(("Content-Type", "text/html"),), body=body))

    text = event.decoded.body
    assert text.text == "<script>alert(1)</script> & ' &bogus;"
    assert text.entity_count == 6
    assert text.charset == "ascii"
    assert text.status is DecodeStatus.DECODED
    assert event.decoded.status is DecodeStatus.DECODED
    assert event.issues == []


def test_html_body_without_entities_is_unchanged_with_zero_count():
    event = run(
        http_event(kind="response", headers=(("Content-Type", "text/html"),), body=b"<p>hi</p>")
    )

    assert event.decoded.body.entity_count == 0
    assert event.decoded.body.status is DecodeStatus.UNCHANGED


def test_json_body_is_text_but_not_entity_decoded():
    event = run(
        http_event(
            kind="response",
            headers=(("Content-Type", "application/json"),),
            body=b'{"a":"&lt;"}',
        )
    )

    assert event.decoded.body.text == '{"a":"&lt;"}'
    assert event.decoded.body.entity_count is None


def test_absent_content_type_text_body_is_entity_decoded():
    event = run(http_event(kind="response", body=b"a &amp; b"))

    assert event.decoded.body.text == "a & b"
    assert event.decoded.body.entity_count == 1


def test_absent_content_type_binary_body_is_not_decoded():
    event = run(http_event(kind="response", body=b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"))

    assert event.decoded.body is None
    assert event.decoded.status is DecodeStatus.NOT_APPLICABLE
    assert event.issues == []


def test_binary_media_type_is_not_decoded_as_text():
    event = run(
        http_event(kind="response", headers=(("Content-Type", "image/png"),), body=b"\xff\xd8\xff")
    )

    assert event.decoded.body is None
    assert event.issues == []


def test_compressed_body_is_not_decoded_as_text():
    event = run(
        http_event(
            kind="response",
            headers=(("Content-Type", "text/html"), ("Content-Encoding", "gzip")),
            body=b"\x1f\x8b\x08\x00garbage",
        )
    )

    assert event.decoded.body is None
    assert event.issues == []


def test_compressed_form_body_is_not_decoded_as_a_form():
    event = run(
        http_event(
            headers=(
                ("Content-Type", "application/x-www-form-urlencoded"),
                ("Content-Encoding", "gzip"),
            ),
            body=gzip.compress(b"user=admin&pass=secret", mtime=0),
        )
    )

    assert (event.decoded.form, event.decoded.body) == (None, None)
    assert event.decoded.status is DecodeStatus.NOT_APPLICABLE
    assert event.issues == []


def test_t04_invalid_utf8_body_is_partial_with_issue():
    event = run(
        http_event(
            kind="response",
            headers=(("Content-Type", "text/plain; charset=utf-8"),),
            body=b"ok \xff\xfe bad \xe2\x82",
        )
    )

    text = event.decoded.body
    assert text.status is DecodeStatus.PARTIAL
    assert text.invalid_byte_count == 4
    assert text.first_invalid_offset == 3
    assert event.decoded.status is DecodeStatus.PARTIAL
    assert codes(event) == [("decoder", "invalid_charset_bytes")]
    assert event.issues[0].context == {
        "field": "body",
        "invalid_byte_count": 4,
        "first_invalid_offset": 3,
    }


def test_quoted_charset_parameter_is_used():
    event = run(
        http_event(
            kind="response",
            headers=(("Content-Type", 'text/plain; format=flowed; Charset="ISO-8859-1"'),),
            body=b"caf\xe9",
        )
    )

    assert event.decoded.body.text == "café"
    assert event.decoded.body.charset == "iso-8859-1"


def test_body_cut_by_payload_cap_is_partial_and_reported():
    event = run(
        http_event(
            kind="response",
            headers=(("Content-Type", "text/plain"),),
            body=b"0123456789",
            stored=len(HEAD) + 4,
        )
    )

    assert event.decoded.body.text == "0123"
    assert event.decoded.body.status is DecodeStatus.PARTIAL
    assert codes(event) == [("decoder", "decoded_truncated")]
    assert event.issues[0].context == {"field": "body", "expected": 10, "available": 4}


def test_missing_payload_bytes_for_a_declared_body_is_partial():
    event = http_event(kind="response", headers=(("Content-Type", "text/plain"),), body=b"abc")
    event.payload.data = None

    run(event)

    assert event.decoded.body.text == ""
    assert event.decoded.body.status is DecodeStatus.PARTIAL
    assert codes(event) == [("decoder", "decoded_truncated")]


def test_body_text_over_max_decoded_bytes_is_truncated_and_reported():
    event = run(
        http_event(kind="response", headers=(("Content-Type", "text/plain"),), body=b"abcdef"),
        max_decoded_bytes=4,
    )

    assert event.decoded.body.text == "abcd"
    assert event.decoded.body.truncated is True
    assert codes(event) == [("decoder", "decoded_truncated")]


def test_existing_issues_are_kept_and_decoder_issues_appended():
    event = http_event(uri="/a%G1")
    event.issues.append(Issue("application", "truncated_body", "short", {}))

    run(event)

    assert codes(event) == [("application", "truncated_body"), ("decoder", "invalid_escape")]


SMTP_MIME = (
    b"Subject: =?utf-8?q?Ch=C3=A0o?=\r\n"
    b"MIME-Version: 1.0\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n"
    b"Content-Transfer-Encoding: base64\r\n"
    b"\r\n"
    b"WGluIGNow6Bv\r\n"
    b".\r\n"
)


def test_smtp_data_packet_with_mime_headers_is_decoded():
    event = run(smtp_event(SMTP_MIME))

    decoded = event.decoded
    assert isinstance(decoded, DecodedMime)
    assert decoded.headers.subject == "Chào"
    assert decoded.parts[0].text == "Xin chào"
    assert decoded.status is DecodeStatus.DECODED
    assert event.issues == []


def test_smtp_payload_without_mime_header_block_is_not_decoded():
    command = run(smtp_event(b"MAIL FROM:<a@example.test>\r\n", kind="command"))
    plain_body = run(smtp_event(b"second half of the body text\r\n.\r\n"))
    after_blank = run(smtp_event(b"Subject: hi\r\n\r\nContent-Type: text/plain\r\n"))

    assert command.decoded is None
    assert plain_body.decoded is None
    assert after_blank.decoded is None


def test_smtp_segment_starting_with_a_part_header_block_is_decoded():
    event = run(smtp_event(b"--b1\r\nContent-Type: text/plain\r\n\r\nhello\r\n--b1--\r\n"))

    assert isinstance(event.decoded, DecodedMime)
    assert event.decoded.parts[0].content_type == "text/plain"
    assert event.decoded.parts[0].text.startswith("hello")


def test_smtp_payload_cut_by_payload_cap_is_partial():
    event = run(smtp_event(SMTP_MIME[:-3], truncated=True))

    assert event.decoded.status is DecodeStatus.PARTIAL
    assert codes(event) == [("decoder", "decoded_truncated")]


def test_message_event_is_always_mime_decoded():
    message = MessageEvent(
        message_id="f-1",
        flow_id="f",
        protocol="SMTP",
        data=b"Subject: hi\r\nContent-Transfer-Encoding: x-uuencode\r\n\r\nbegin\r\n.\r\n",
    )

    run(message)

    assert isinstance(message.decoded, DecodedMime)
    assert message.decoded.headers.subject == "hi"
    assert message.decoded.status is DecodeStatus.FAILED
    assert codes(message) == [("decoder", "unsupported_encoding")]


def test_dns_and_bare_transport_events_are_left_undecoded():
    dns = PacketEvent(application=ApplicationInfo(protocol="DNS", message=DnsMessage(kind="query")))
    unknown = PacketEvent(
        application=ApplicationInfo(protocol="UNKNOWN"), payload=Payload(data=b"x")
    )
    bare = PacketEvent()

    for event in (dns, unknown, bare):
        run(event)
        assert event.decoded is None
        assert event.issues == []


def tcp_frame(payload: bytes, *, sport: int, dport: int) -> bytes:
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 1000, 1, 0x50, 0x18, 65535, 0, 0)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(tcp) + len(payload),
        1,
        0,
        64,
        6,
        0,
        bytes((10, 0, 0, 1)) if dport == 80 else bytes((10, 0, 0, 2)),
        bytes((10, 0, 0, 2)) if dport == 80 else bytes((10, 0, 0, 1)),
    )
    ethernet = bytes.fromhex("0200000000020200000000010800")
    return ethernet + ip + tcp + payload


def test_runner_decodes_parsed_http_packets_end_to_end(tmp_path):
    t02 = b"&lt;script&gt;alert(1)&lt;/script&gt; &amp; &#x27; &bogus;"
    t04 = b"ok \xff\xfe bad \xe2\x82"
    payloads = [
        (
            b"GET /search%20page?q=%27%20OR%201%3D1&x=a+b HTTP/1.1\r\nHost: example.test\r\n\r\n",
            40000,
            80,
        ),
        (
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n"
            b"Content-Length: %d\r\n\r\n" % len(t04) + t04,
            80,
            40000,
        ),
        (
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
            b"Content-Length: %d\r\n\r\n" % len(t02) + t02,
            80,
            40000,
        ),
    ]
    packets = [
        RawPacket(
            packet_id=index,
            timestamp=1759000000.0 + index,
            data=tcp_frame(payload, sport=sport, dport=dport),
            linktype=1,
            source="pcap",
            origin="test",
        )
        for index, (payload, sport, dport) in enumerate(payloads, start=1)
    ]
    out = tmp_path / "out.jsonl"

    with JsonlSink(str(out)) as sink:
        Runner(PacketParser(), [DecoderStage()], sink, Stats()).run(packets)

    records = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
    request, bad, html = [r for r in records if r["record_type"] == "packet"]
    assert request["application"]["message"]["uri"] == "/search%20page?q=%27%20OR%201%3D1&x=a+b"
    assert request["decoded"]["kind"] == "http"
    assert request["decoded"]["uri"]["path"] == "/search page"
    assert request["decoded"]["uri"]["params"] == [["q", "' OR 1=1"], ["x", "a b"]]
    assert request["decoded"]["status"] == "decoded"
    assert bad["decoded"]["body"]["status"] == "partial"
    assert bad["decoded"]["body"]["invalid_byte_count"] == 4
    assert [i["code"] for i in bad["issues"] if i["stage"] == "decoder"] == [
        "invalid_charset_bytes"
    ]
    assert html["decoded"]["body"]["text"] == "<script>alert(1)</script> & ' &bogus;"
    assert html["decoded"]["body"]["entity_count"] == 6
    assert [i for i in html["issues"] if i["stage"] == "decoder"] == []
