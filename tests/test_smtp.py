import pytest

from pcparser.errors import DecodeError
from pcparser.parsers.smtp import first_line, parse

from golden import (
    SMTP_EHLO,
    SMTP_GREETING,
    SMTP_MAIL_FROM,
    SMTP_MULTILINE,
    SMTP_RCPT_TO,
    SMTP_REJECT,
)


def test_ehlo_command():
    info = parse(SMTP_EHLO)
    assert info["kind"] == "command"
    assert info["command"] == "EHLO"
    assert info["commands"][0]["verb"] == "EHLO"
    assert info["commands"][0]["domain"] == "client.example.test"
    assert info["replies"] == []


def test_helo_is_accepted_like_ehlo():
    info = parse(b"HELO relay.test\r\n")
    assert info["commands"][0]["verb"] == "HELO"
    assert info["commands"][0]["domain"] == "relay.test"


def test_mail_from_extracts_address_and_parameters():
    info = parse(SMTP_MAIL_FROM)
    assert info["command"] == "MAIL"
    assert info["mail_from"] == "alice@example.test"
    assert info["commands"][0]["parameters"] == ["SIZE=1024"]


def test_mail_from_without_angle_brackets():
    info = parse(b"MAIL FROM: alice@example.test\r\n")
    assert info["mail_from"] == "alice@example.test"


def test_mail_from_with_empty_reverse_path():
    info = parse(b"MAIL FROM:<>\r\n")
    assert info["mail_from"] == ""


def test_rcpt_to_extracts_address():
    info = parse(SMTP_RCPT_TO)
    assert info["command"] == "RCPT"
    assert info["rcpt_to"] == ["bob@example.test"]


def test_pipelined_commands_in_one_segment():
    info = parse(b"MAIL FROM:<a@b.test>\r\nRCPT TO:<c@d.test>\r\nRCPT TO:<e@f.test>\r\nDATA\r\n")
    assert info["command_count"] == 4
    assert [command["verb"] for command in info["commands"]] == ["MAIL", "RCPT", "RCPT", "DATA"]
    assert info["mail_from"] == "a@b.test"
    assert info["rcpt_to"] == ["c@d.test", "e@f.test"]


def test_greeting_status_code():
    info = parse(SMTP_GREETING)
    assert info["kind"] == "response"
    assert info["status_code"] == 220
    assert info["status_text"] == "mail.example.test ESMTP Postfix"
    assert info["last_status_code"] == 220


def test_multiline_reply_is_joined_into_one_reply():
    info = parse(SMTP_MULTILINE)
    assert info["reply_count"] == 1
    assert info["status_code"] == 250
    assert info["replies"][0]["continuation"] is False
    assert info["replies"][0]["lines"] == [
        "mail.example.test",
        "PIPELINING",
        "SIZE 10240000",
        "AUTH LOGIN PLAIN",
    ]
    assert info["status_text"].endswith("AUTH LOGIN PLAIN")


def test_rejection_status_code():
    info = parse(SMTP_REJECT)
    assert info["status_code"] == 550
    assert "Recipient address rejected" in info["status_text"]


def test_incomplete_multiline_reply_is_reported():
    info = parse(b"250-first\r\n250-second\r\n")
    assert info["replies"][0]["continuation"] is True
    assert [error["code"] for error in info["errors"]] == ["incomplete_reply"]


def test_auth_mechanism_is_captured():
    info = parse(b"AUTH PLAIN AGFsaWNlAHNlY3JldA==\r\n")
    assert info["commands"][0]["mechanism"] == "PLAIN"
    assert info["commands"][0]["credentials_present"] is True


def test_message_body_lines_are_collected_as_unparsed():
    info = parse(b"220 hi\r\nSubject: test\r\n\r\nbody line\r\n")
    assert info["status_code"] == 220
    assert info["unparsed_lines"] == ["Subject: test", "body line"]


def test_unknown_verb_is_unparsed_not_an_error():
    info = parse(b"220 ok\r\nFROBNICATE now\r\n")
    assert info["status_code"] == 220
    assert info["unparsed_lines"] == ["FROBNICATE now"]


@pytest.mark.parametrize("payload", [b"", b"\x00\x01\x02\x03", b"random text here", b"999 nope\r\n"])
def test_non_smtp_payloads_raise_decode_error(payload):
    with pytest.raises(DecodeError):
        parse(payload)


def test_first_line_helper():
    assert first_line(SMTP_EHLO) == b"EHLO client.example.test"
    assert first_line(b"220 hi") == b"220 hi"
