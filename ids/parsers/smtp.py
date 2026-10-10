from __future__ import annotations

import re

from ..issues import Issues, ParseError
from ..model import SmtpCommand, SmtpReply, SmtpSession

NAME = "SMTP"
PORTS = frozenset((25, 465, 587, 2525))

COMMANDS = frozenset(
    (
        "HELO",
        "EHLO",
        "MAIL",
        "RCPT",
        "DATA",
        "QUIT",
        "RSET",
        "NOOP",
        "VRFY",
        "EXPN",
        "HELP",
        "AUTH",
        "STARTTLS",
        "BDAT",
        "TURN",
        "ETRN",
    )
)

REPLY_CODES = frozenset(
    (
        211,
        214,
        220,
        221,
        250,
        251,
        252,
        354,
        421,
        450,
        451,
        452,
        455,
        500,
        501,
        502,
        503,
        504,
        530,
        532,
        550,
        551,
        552,
        553,
        554,
        555,
    )
)

REPLY_LINE = re.compile(rb"^(\d{3})(?:([ -])(.*))?$")
COMMAND_LINE = re.compile(rb"^([A-Za-z]{3,10})(?:[ \t]+(.*))?$")
HELLO_LINE = re.compile(rb"^(?:HELO|EHLO)[ \t]+\S", re.IGNORECASE)
PATH_LINE = re.compile(rb"^(MAIL|RCPT)[ \t]+(?:FROM|TO)[ \t]*:[ \t]*(.*)$", re.IGNORECASE)
AUTH_LINE = re.compile(rb"^AUTH[ \t]+(\S+)(?:[ \t]+(.*))?$", re.IGNORECASE)
VERB_LINE = re.compile(
    rb"^(?:" + rb"|".join(sorted(verb.encode("ascii") for verb in COMMANDS)) + rb")(?:[ \t]|$)",
    re.IGNORECASE,
)
ADDRESS = re.compile(rb"<([^>]*)>")

MAX_LINE = 4096
MAX_UNPARSED = 10
SCORE_WINDOW = 512


def first_line(data: bytes) -> bytes:
    index = data.find(b"\n")
    line = data if index < 0 else data[:index]
    return line.rstrip(b"\r")


def score(payload: bytes, tcp: bool) -> tuple[float, str | None]:
    line = first_line(payload[:SCORE_WINDOW])
    if HELLO_LINE.match(line):
        return 0.95, "SMTP HELO/EHLO command"
    if PATH_LINE.match(line):
        return 0.95, "SMTP MAIL/RCPT path"
    reply = REPLY_LINE.match(line)
    if reply:
        code = int(reply.group(1))
        if 200 <= code <= 599:
            if reply.group(2) == b"-" or code in REPLY_CODES:
                return 0.85, f"SMTP status code {code}"
            return 0.45, f"numeric status line {code}"
    if VERB_LINE.match(line):
        return 0.7, "SMTP verb"
    return 0.0, None


def _lines(data: bytes) -> list[bytes]:
    lines = []
    for raw in data.split(b"\n"):
        raw = raw.rstrip(b"\r")
        if raw:
            lines.append(raw[:MAX_LINE])
    return lines


def _command(verb: str, arguments: str, raw: bytes) -> SmtpCommand:
    command = SmtpCommand(verb=verb, arguments=arguments)
    path = PATH_LINE.match(raw)
    if path:
        address = ADDRESS.search(raw)
        if address:
            command.address = address.group(1).decode("latin-1")
            tail = raw[address.end() :].decode("latin-1").strip()
            command.parameters = tail.split() if tail else []
        else:
            tokens = path.group(2).decode("latin-1").split()
            command.address = tokens[0] if tokens else ""
            command.parameters = tokens[1:]
        command.path = path.group(2).decode("latin-1").strip()
    elif verb in ("HELO", "EHLO"):
        command.domain = arguments
    elif verb == "AUTH":
        auth = AUTH_LINE.match(raw)
        if auth:
            command.mechanism = auth.group(1).decode("latin-1").upper()
            if auth.group(2):
                command.credentials_present = True
    return command


def parse(payload: bytes, *, tcp: bool, issues: Issues) -> SmtpSession:
    if not payload:
        raise ParseError("decode_error", "SMTP payload is empty")

    session = SmtpSession()
    for raw in _lines(payload):
        reply = REPLY_LINE.match(raw)
        if reply and 100 <= int(reply.group(1)) <= 599:
            code = int(reply.group(1))
            text = (reply.group(3) or b"").decode("latin-1")
            continuation = reply.group(2) == b"-"
            if session.replies and session.replies[-1].continuation:
                last = session.replies[-1]
                last.lines.append(text)
                last.code = code
                last.continuation = continuation
            else:
                session.replies.append(
                    SmtpReply(code=code, lines=[text], continuation=continuation)
                )
            continue
        command = COMMAND_LINE.match(raw)
        if command:
            verb = command.group(1).decode("latin-1").upper()
            if verb in COMMANDS:
                arguments = (command.group(2) or b"").decode("latin-1").strip()
                session.commands.append(_command(verb, arguments, raw))
                continue
        if len(session.unparsed_lines) < MAX_UNPARSED:
            session.unparsed_lines.append(raw.decode("latin-1"))

    for reply in session.replies:
        reply.text = "\n".join(reply.lines)

    if session.commands and session.replies:
        session.kind = "mixed"
    elif session.commands:
        session.kind = "command"
    elif session.replies:
        session.kind = "response"
    else:
        session.kind = "data"

    if session.commands:
        session.command = session.commands[0].verb
    if session.replies:
        session.status_code = session.replies[0].code
        session.last_status_code = session.replies[-1].code
        if session.replies[-1].continuation:
            issues.add(
                "incomplete_reply",
                "last SMTP reply uses a continuation code with no terminating line",
            )

    for command in session.commands:
        if command.address is None:
            continue
        if command.verb == "MAIL":
            session.mail_from = command.address
        elif command.verb == "RCPT":
            session.rcpt_to.append(command.address)
    return session
