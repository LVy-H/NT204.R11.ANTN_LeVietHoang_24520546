from __future__ import annotations

import hashlib
import json
import random

from ids.codec import to_jsonable
from ids.decoder.mime import decode_message
from ids.issues import Issues
from ids.model import DecodeStatus

MULTIPART = (
    b"From: =?utf-8?b?Tmd1eeG7hW4gVsSDbiBB?= <a@example.test>\r\n"
    b"To: bob@example.test\r\n"
    b"Subject: =?utf-8?q?B=C3=A1o_c=C3=A1o_th=C3=A1ng?= 9\r\n"
    b"Date: Sat, 27 Sep 2025 10:00:00 +0700\r\n"
    b"Message-ID: <m1@example.test>\r\n"
    b"MIME-Version: 1.0\r\n"
    b'Content-Type: multipart/mixed; boundary="b1"\r\n'
    b"\r\n"
    b"--b1\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n"
    b"Content-Transfer-Encoding: base64\r\n"
    b"\r\n"
    b"Q2jDoG8gYuG6oW4sDQrEkcOieSBsw6AgcGjhuqduIEJhc2U2NC4NCg==\r\n"
    b"--b1\r\n"
    b"Content-Type: text/plain; charset=UTF-8\r\n"
    b"Content-Transfer-Encoding: quoted-printable\r\n"
    b"\r\n"
    b"Ti=E1=BA=BFng Vi=E1=BB=87t c=C3=B3 d=E1=BA=A5u: =E1=BA=AF =E1=BA=B3 =E1=BA=\r\n"
    b"=B5.\r\n"
    b"--b1\r\n"
    b"Content-Type: application/octet-stream\r\n"
    b'Content-Disposition: attachment; filename="report.bin"\r\n'
    b"Content-Transfer-Encoding: base64\r\n"
    b"\r\n"
    b"AAEC/w==\r\n"
    b"--b1--\r\n"
)

BASE64_TEXT = "Chào bạn,\r\nđây là phần Base64.\r\n"
# the CRLF before a boundary belongs to the boundary, so the QP part has no final newline
QP_TEXT = "Tiếng Việt có dấu: ắ ẳ ẵ."


def single(encoding: str | None, body: bytes, content_type: bytes = b"text/plain") -> bytes:
    header = b"MIME-Version: 1.0\r\nContent-Type: " + content_type + b"\r\n"
    if encoding is not None:
        header += b"Content-Transfer-Encoding: " + encoding.encode() + b"\r\n"
    return header + b"\r\n" + body


def test_multipart_base64_and_quoted_printable_parts_are_decoded():
    issues = Issues("decoder")

    result = decode_message(MULTIPART + b".\r\n", issues)

    assert result.status is DecodeStatus.DECODED
    assert [part.index for part in result.parts] == [0, 1, 2]
    text_b64, text_qp, attachment = result.parts
    assert text_b64.content_type == "text/plain"
    assert text_b64.transfer_encoding == "base64"
    assert text_b64.charset == "utf-8"
    assert text_b64.text == BASE64_TEXT
    assert text_b64.status is DecodeStatus.DECODED
    assert text_b64.size == len(BASE64_TEXT.encode())
    assert text_b64.sha256 == hashlib.sha256(BASE64_TEXT.encode()).hexdigest()
    assert text_qp.transfer_encoding == "quoted-printable"
    assert text_qp.text == QP_TEXT
    assert text_qp.status is DecodeStatus.DECODED
    assert attachment.text is None
    assert attachment.filename == "report.bin"
    assert attachment.size == 4
    assert attachment.sha256 == hashlib.sha256(b"\x00\x01\x02\xff").hexdigest()
    assert issues.records == []


def test_rfc2047_headers_are_decoded():
    result = decode_message(MULTIPART, Issues("decoder"))

    assert result.headers.subject == "Báo cáo tháng 9"
    assert result.headers.from_ == "Nguyễn Văn A <a@example.test>"
    assert result.headers.to == "bob@example.test"
    assert result.headers.cc is None
    assert result.headers.date == "Sat, 27 Sep 2025 10:00:00 +0700"
    assert result.headers.message_id == "<m1@example.test>"


def test_folded_encoded_words_join_without_the_folding_space():
    data = b"Subject: =?utf-8?q?Xin_ch?=\r\n =?utf-8?q?=C3=A0o?=\r\n\r\nbody\r\n"

    assert decode_message(data, Issues("decoder")).headers.subject == "Xin chào"


def test_header_over_the_input_bound_is_cut_before_decoding_and_reported():
    # 1000 encoded words of 16 characters each; the 8192-character bound keeps 512 of them
    data = b"Subject: " + b"=?utf-8?q?abc?= " * 1000 + b"\r\nTo: bob@example.test\r\n\r\nbody\r\n"
    issues = Issues("decoder")

    result = decode_message(data, issues)

    assert result.headers.subject == "abc" * 512
    assert result.headers.to == "bob@example.test"
    assert [(i.code, i.context) for i in issues.records] == [
        ("decoded_truncated", {"field": "subject"})
    ]


def test_single_part_base64_message():
    data = single("base64", b"WGluIGNo\r\nw6Bv\r\n", b"text/plain; charset=utf-8")

    result = decode_message(data, Issues("decoder"))

    assert len(result.parts) == 1
    assert result.parts[0].index == 0
    assert result.parts[0].text == "Xin chào"
    assert result.status is DecodeStatus.DECODED


def test_seven_bit_ascii_part_is_unchanged():
    result = decode_message(single("7bit", b"hello\r\n"), Issues("decoder"))

    assert result.parts[0].text == "hello\r\n"
    assert result.parts[0].charset == "ascii"
    assert result.status is DecodeStatus.UNCHANGED


def test_missing_transfer_encoding_is_unchanged():
    result = decode_message(single(None, b"hello\r\n"), Issues("decoder"))

    assert result.parts[0].transfer_encoding is None
    assert result.parts[0].status is DecodeStatus.UNCHANGED


def test_terminator_is_stripped_and_dot_stuffing_undone():
    body = b"..hidden line\r\nmiddle\r\n...\r\nend\r\n.\r\n"

    result = decode_message(single("7bit", body), Issues("decoder"))

    assert result.parts[0].text == ".hidden line\r\nmiddle\r\n..\r\nend\r\n"


def test_bad_base64_padding_decodes_the_whole_quanta_and_is_partial():
    issues = Issues("decoder")

    result = decode_message(single("base64", b"WGluIGNow6Bv=\r\n"), issues)

    assert result.parts[0].text == "Xin chào"
    assert result.parts[0].status is DecodeStatus.PARTIAL
    assert result.status is DecodeStatus.PARTIAL
    assert [(i.stage, i.code) for i in issues.records] == [("decoder", "invalid_base64")]
    assert issues.records[0].context["part"] == 0


def test_missing_base64_padding_still_recovers_the_bytes():
    issues = Issues("decoder")

    result = decode_message(single("base64", b"WGk"), issues)

    assert result.parts[0].text == "Xi"
    assert result.parts[0].status is DecodeStatus.PARTIAL
    assert [i.code for i in issues.records] == ["invalid_base64"]


def test_invalid_base64_character_keeps_the_valid_prefix():
    issues = Issues("decoder")

    result = decode_message(single("base64", b"WGluIGNo*w6Bv"), issues)

    assert result.parts[0].text == "Xin ch"
    assert result.parts[0].size == 6
    assert result.parts[0].status is DecodeStatus.PARTIAL
    assert issues.records[0].code == "invalid_base64"


def test_malformed_quoted_printable_is_kept_literally_and_partial():
    issues = Issues("decoder")

    result = decode_message(single("quoted-printable", b"gi=C3=A1 =G1 =4\r\n"), issues)

    assert result.parts[0].text == "giá =G1 =4\r\n"
    assert result.parts[0].status is DecodeStatus.PARTIAL
    assert [i.code for i in issues.records] == ["invalid_quoted_printable"]
    assert issues.records[0].context["count"] == 2


def test_quoted_printable_equals_before_trailing_space_is_malformed():
    issues = Issues("decoder")

    result = decode_message(single("quoted-printable", b"ab= \r\ncd"), issues)

    assert result.parts[0].text == "ab= \r\ncd"
    assert result.parts[0].status is DecodeStatus.PARTIAL
    assert [i.code for i in issues.records] == ["invalid_quoted_printable"]


def test_quoted_printable_soft_breaks_are_not_malformed():
    issues = Issues("decoder")

    result = decode_message(single("quoted-printable", b"ab=\r\ncd=\nef="), issues)

    assert result.parts[0].text == "abcdef"
    assert result.parts[0].status is DecodeStatus.DECODED
    assert issues.records == []


def test_unsupported_transfer_encoding_fails_the_part():
    issues = Issues("decoder")

    result = decode_message(single("x-uuencode", b"begin 644 a\r\n`\r\nend\r\n"), issues)

    part = result.parts[0]
    assert part.status is DecodeStatus.FAILED
    assert part.transfer_encoding == "x-uuencode"
    assert (part.text, part.size, part.sha256) == (None, None, None)
    assert result.status is DecodeStatus.FAILED
    assert [i.code for i in issues.records] == ["unsupported_encoding"]


def test_overall_status_is_the_worst_part_status():
    data = (
        b'Content-Type: multipart/mixed; boundary="x"\r\n\r\n'
        b"--x\r\nContent-Transfer-Encoding: base64\r\n\r\naGk=\r\n"
        b"--x\r\nContent-Transfer-Encoding: base64\r\n\r\naGk\r\n"
        b"--x--\r\n"
    )

    result = decode_message(data, Issues("decoder"))

    assert [part.status for part in result.parts] == [DecodeStatus.DECODED, DecodeStatus.PARTIAL]
    assert result.status is DecodeStatus.PARTIAL


def test_invalid_charset_bytes_in_a_text_part_are_reported():
    issues = Issues("decoder")

    result = decode_message(single("8bit", b"ok \xff", b"text/plain; charset=utf-8"), issues)

    assert result.parts[0].text == "ok \ufffd"
    assert result.parts[0].status is DecodeStatus.PARTIAL
    assert issues.records[0].code == "invalid_charset_bytes"
    assert issues.records[0].context["invalid_byte_count"] == 1


def test_part_text_over_the_cap_is_truncated_and_reported():
    issues = Issues("decoder")

    result = decode_message(single("7bit", b"abcdefghij"), issues, max_bytes=4)

    assert result.parts[0].text == "abcd"
    assert result.parts[0].truncated is True
    assert result.parts[0].size == 10
    assert [i.code for i in issues.records] == ["decoded_truncated"]


def test_raw_utf8_header_without_encoded_words_is_decoded():
    data = "Subject: Báo cáo\r\n\r\nx".encode()

    assert decode_message(data, Issues("decoder")).headers.subject == "Báo cáo"


def test_eight_bit_utf8_body_is_decoded_byte_exact():
    body = "Gửi bạn bản báo cáo.\r\n".encode()

    result = decode_message(single("8bit", body, b"text/plain; charset=utf-8"), Issues("decoder"))

    assert result.parts[0].text == "Gửi bạn bản báo cáo.\r\n"
    assert result.parts[0].sha256 == hashlib.sha256(body).hexdigest()
    assert result.parts[0].status is DecodeStatus.DECODED


def test_broken_encoded_word_keeps_raw_header_and_reports():
    issues = Issues("decoder")

    result = decode_message(b"Subject: =?utf-8?b?Q?=\r\n\r\nx", issues)

    assert result.headers.subject == "=?utf-8?b?Q?="
    assert [i.code for i in issues.records] == ["invalid_base64"]


def test_garbage_input_never_raises():
    rng = random.Random(20261010)
    alphabet = b"\r\n:;=?-\"'* abcXYZ019+/\x00\x80\xff"
    prefixes = [
        b"",
        b"Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n",
        b"Content-Transfer-Encoding: base64\r\nContent-Type: text/plain; charset=\xff\r\n\r\n",
        b"Content-Transfer-Encoding: quoted-printable\r\nSubject: =?utf-8?q?x=",
    ]
    for prefix in prefixes:
        for _ in range(200):
            blob = prefix + bytes(rng.choice(alphabet) for _ in range(rng.randrange(120)))
            issues = Issues("decoder")
            result = decode_message(blob, issues)
            json.dumps(to_jsonable(result), ensure_ascii=False).encode("utf-8")
            json.dumps(to_jsonable(issues.records), ensure_ascii=False).encode("utf-8")


def test_nul_in_rfc2231_parameter_charset_does_not_raise():
    issues = Issues("decoder")
    data = (
        b"MIME-Version: 1.0\r\nContent-Type: application/octet-stream\r\n"
        b"Content-Disposition: attachment; filename*=a\x00b''x\r\n\r\nhi"
    )

    result = decode_message(data, issues)

    assert result.parts[0].filename is None
    assert result.parts[0].size == 2
    assert [i.code for i in issues.records] == ["invalid_charset_bytes"]
    assert issues.records[0].context["part"] == 0

    multipart = (
        b"Content-Type: multipart/mixed; boundary*=a\x00b''x\r\n\r\n--x\r\n\r\nhi\r\n--x--\r\n"
    )

    result = decode_message(multipart, Issues("decoder"))

    assert len(result.parts) == 1


def test_lone_surrogate_in_rfc2231_filename_is_dropped():
    issues = Issues("decoder")
    data = (
        b"MIME-Version: 1.0\r\nContent-Type: application/octet-stream\r\n"
        b"Content-Disposition: attachment; filename*=utf-7''%2B2AA-\r\n\r\nhi"
    )

    result = decode_message(data, issues)

    assert result.parts[0].filename is None
    assert [i.code for i in issues.records] == ["invalid_charset_bytes"]
    assert issues.records[0].context["part"] == 0
    json.dumps(to_jsonable(result), ensure_ascii=False).encode("utf-8")


def test_refused_charsets_in_rfc2231_parameters_are_never_decoded(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("punycode decoder ran")

    monkeypatch.setattr("encodings.punycode.punycode_decode", refuse)
    issues = Issues("decoder")
    data = (
        b"Content-Type: multipart/mixed; boundary*=punycode''b1\r\n\r\n"
        b"--b1\r\n"
        b"Content-Type: text/plain; charset*=punycode''utf-8\r\n"
        b"Content-Disposition: attachment; filename*=punycode''a.txt\r\n\r\n"
        b"hi\r\n"
        b"--b1\r\n"
        b"Content-Type: text/plain; charset*=unicode-escape''utf-8\r\n"
        b"Content-Disposition: attachment; filename*=raw-unicode-escape''%5Cu0041.txt\r\n\r\n"
        b"ho\r\n"
        b"--b1--\r\n"
    )

    result = decode_message(data, issues)

    assert [(part.charset, part.filename, part.text) for part in result.parts] == [
        ("utf-8", "a.txt", "hi"),
        ("utf-8", "\\u0041.txt", "ho"),
    ]
    assert issues.records == []
