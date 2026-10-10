import pytest
from golden import (
    SMTP_EHLO,
    SMTP_GREETING,
    SMTP_MAIL_FROM,
    SMTP_MULTILINE,
    SMTP_RCPT_TO,
    SMTP_REJECT,
)

from ids.issues import Issue, Issues, ParseError
from ids.model import SmtpReply
from ids.parsers.smtp import COMMANDS, MAX_UNPARSED, first_line, parse, score


def parse_smtp(payload, issues=None):
    return parse(payload, tcp=True, issues=issues if issues is not None else Issues("application"))


def test_ehlo_command():
    session = parse_smtp(SMTP_EHLO)
    assert session.kind == "command"
    assert session.command == "EHLO"
    assert session.commands[0].verb == "EHLO"
    assert session.commands[0].arguments == "client.example.test"
    assert session.commands[0].domain == "client.example.test"
    assert session.replies == []
    assert session.status_code is None


def test_helo_is_accepted_like_ehlo():
    session = parse_smtp(b"helo relay.test\r\n")
    assert session.commands[0].verb == "HELO"
    assert session.commands[0].domain == "relay.test"


def test_mail_from_extracts_address_and_parameters():
    session = parse_smtp(SMTP_MAIL_FROM)
    assert session.command == "MAIL"
    assert session.mail_from == "alice@example.test"
    assert session.commands[0].parameters == ["SIZE=1024"]
    assert session.commands[0].path == "<alice@example.test> SIZE=1024"


def test_mail_from_without_angle_brackets():
    session = parse_smtp(b"MAIL FROM: alice@example.test BODY=8BITMIME\r\n")
    assert session.mail_from == "alice@example.test"
    assert session.commands[0].parameters == ["BODY=8BITMIME"]


def test_mail_from_with_empty_reverse_path():
    assert parse_smtp(b"MAIL FROM:<>\r\n").mail_from == ""


def test_rcpt_to_extracts_address():
    session = parse_smtp(SMTP_RCPT_TO)
    assert session.command == "RCPT"
    assert session.rcpt_to == ["bob@example.test"]


def test_rcpt_without_a_path_adds_no_recipient():
    session = parse_smtp(b"RCPT bob\r\n")
    assert session.commands[0].verb == "RCPT"
    assert session.commands[0].address is None
    assert session.rcpt_to == []


def test_pipelined_commands_in_one_segment():
    session = parse_smtp(
        b"MAIL FROM:<a@b.test>\r\nRCPT TO:<c@d.test>\r\nRCPT TO:<e@f.test>\r\nDATA\r\n"
    )
    assert [command.verb for command in session.commands] == ["MAIL", "RCPT", "RCPT", "DATA"]
    assert session.mail_from == "a@b.test"
    assert session.rcpt_to == ["c@d.test", "e@f.test"]


def test_greeting_status_code():
    session = parse_smtp(SMTP_GREETING)
    assert session.kind == "response"
    assert session.status_code == 220
    assert session.replies[0].text == "mail.example.test ESMTP Postfix"
    assert session.last_status_code == 220
    assert session.command is None


def test_reply_without_text_is_accepted():
    session = parse_smtp(b"250\r\n")
    assert session.kind == "response"
    assert session.replies == [SmtpReply(code=250, text="", lines=[""], continuation=False)]


def test_multiline_reply_is_joined_into_one_reply():
    issues = Issues("application")
    session = parse_smtp(SMTP_MULTILINE, issues)
    assert len(session.replies) == 1
    assert session.status_code == 250
    reply = session.replies[0]
    assert reply.continuation is False
    assert reply.lines == ["mail.example.test", "PIPELINING", "SIZE 10240000", "AUTH LOGIN PLAIN"]
    assert reply.text == "mail.example.test\nPIPELINING\nSIZE 10240000\nAUTH LOGIN PLAIN"
    assert issues.records == []


def test_first_and_last_status_codes_differ_across_replies():
    session = parse_smtp(b"250 ok\r\n354 go ahead\r\n")
    assert [reply.code for reply in session.replies] == [250, 354]
    assert session.status_code == 250
    assert session.last_status_code == 354


def test_rejection_status_code():
    session = parse_smtp(SMTP_REJECT)
    assert session.status_code == 550
    assert "Recipient address rejected" in session.replies[0].text


def test_command_and_reply_in_one_payload_is_mixed():
    session = parse_smtp(b"220 hi\r\nEHLO me\r\n")
    assert session.kind == "mixed"
    assert session.command == "EHLO"
    assert session.status_code == 220


def test_incomplete_multiline_reply_is_reported():
    issues = Issues("application")
    session = parse_smtp(b"250-first\r\n250-second\r\n", issues)
    assert session.replies[0].continuation is True
    assert session.replies[0].lines == ["first", "second"]
    assert issues.records == [
        Issue(
            "application",
            "incomplete_reply",
            "last SMTP reply uses a continuation code with no terminating line",
            {},
        )
    ]


def test_auth_mechanism_is_captured():
    session = parse_smtp(b"AUTH plain AGFsaWNlAHNlY3JldA==\r\n")
    assert session.commands[0].mechanism == "PLAIN"
    assert session.commands[0].credentials_present is True


def test_auth_without_initial_response_has_no_credentials():
    session = parse_smtp(b"AUTH LOGIN\r\n")
    assert session.commands[0].mechanism == "LOGIN"
    assert session.commands[0].credentials_present is None


def test_message_body_lines_are_collected_as_unparsed():
    session = parse_smtp(b"220 hi\r\nSubject: test\r\n\r\nbody line\r\n")
    assert session.status_code == 220
    assert session.unparsed_lines == ["Subject: test", "body line"]


def test_unknown_verb_is_unparsed_not_an_error():
    session = parse_smtp(b"220 ok\r\nFROBNICATE now\r\n")
    assert session.status_code == 220
    assert session.unparsed_lines == ["FROBNICATE now"]


def test_turn_is_a_command():
    session = parse_smtp(b"TURN\r\n")
    assert session.kind == "command"
    assert session.command == "TURN"


def test_data_phase_content_is_kind_data():
    issues = Issues("application")
    payload = b"Subject: hi\r\nMIME-Version: 1.0\r\n\r\nHello Bob\r\n.\r\n"
    session = parse_smtp(payload, issues)
    assert session.kind == "data"
    assert session.commands == []
    assert session.replies == []
    assert session.unparsed_lines == ["Subject: hi", "MIME-Version: 1.0", "Hello Bob", "."]
    assert issues.records == []


def test_unparsed_lines_are_capped():
    payload = b"".join(b"line %d\r\n" % index for index in range(MAX_UNPARSED + 5))
    session = parse_smtp(payload)
    assert session.kind == "data"
    assert len(session.unparsed_lines) == MAX_UNPARSED
    assert session.unparsed_lines[-1] == f"line {MAX_UNPARSED - 1}"


@pytest.mark.parametrize("payload", [b"\x00\x01\x02\x03", b"random text here", b"999 nope\r\n"])
def test_non_smtp_payloads_are_data_not_errors(payload):
    session = parse_smtp(payload)
    assert session.kind == "data"
    assert session.commands == []
    assert session.replies == []
    assert session.unparsed_lines == [payload.rstrip(b"\r\n").decode("latin-1")]


def test_empty_payload_raises_decode_error():
    with pytest.raises(ParseError) as caught:
        parse_smtp(b"")
    assert caught.value.code == "decode_error"


def test_first_line_helper():
    assert first_line(SMTP_EHLO) == b"EHLO client.example.test"
    assert first_line(b"220 hi") == b"220 hi"


@pytest.mark.parametrize(
    "payload,expected",
    [
        (SMTP_EHLO, (0.95, "SMTP HELO/EHLO command")),
        (SMTP_MAIL_FROM, (0.95, "SMTP MAIL/RCPT path")),
        (SMTP_GREETING, (0.85, "SMTP status code 220")),
        (b"299-first\r\n", (0.85, "SMTP status code 299")),
        (b"299 numeric\r\n", (0.45, "numeric status line 299")),
        (b"199 too low\r\n", (0.0, None)),
        (b"QUIT\r\n", (0.7, "SMTP verb")),
        (b"hello world\r\n", (0.0, None)),
    ],
)
def test_score_tiers(payload, expected):
    assert score(payload, True) == expected


@pytest.mark.parametrize("verb", sorted(COMMANDS))
def test_every_parsed_verb_scores_as_smtp(verb):
    payload = verb.encode() + b"\r\n"
    assert score(payload, True)[0] >= 0.7
    assert parse_smtp(payload).command == verb
