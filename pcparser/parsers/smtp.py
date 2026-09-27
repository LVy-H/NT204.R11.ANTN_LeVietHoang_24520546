from __future__ import annotations

import re

from ..errors import DecodeError

COMMANDS = frozenset(
    "HELO EHLO MAIL RCPT DATA QUIT RSET NOOP VRFY EXPN HELP AUTH STARTTLS BDAT TURN ETRN".split()
)

RESPONSE_LINE = re.compile(rb"^(\d{3})([ -])(.*)$")
COMMAND_LINE = re.compile(rb"^([A-Za-z]{3,10})(?:[ \t]+(.*))?$")
PATH_LINE = re.compile(rb"^(MAIL|RCPT)[ \t]+(?:FROM|TO)[ \t]*:[ \t]*(.*)$", re.IGNORECASE)
AUTH_LINE = re.compile(rb"^AUTH[ \t]+(\S+)(?:[ \t]+(.*))?$", re.IGNORECASE)
ADDRESS = re.compile(rb"<([^>]*)>")

MAX_LINE = 4096
MAX_UNPARSED = 10
PATH_KEYS = {"MAIL": "mail_from", "RCPT": "rcpt_to"}


def first_line(data: bytes) -> bytes:
    index = data.find(b"\n")
    line = data if index < 0 else data[:index]
    return line.rstrip(b"\r")


def _lines(data: bytes) -> list[bytes]:
    lines = []
    for raw in data.split(b"\n"):
        raw = raw.rstrip(b"\r")
        if raw:
            lines.append(raw[:MAX_LINE])
    return lines


def parse(data: bytes) -> dict:
    if not data:
        raise DecodeError("SMTP payload is empty", stage="application")

    commands: list[dict] = []
    replies: list[dict] = []
    unparsed: list[str] = []
    errors: list[dict] = []

    for raw in _lines(data):
        response = RESPONSE_LINE.match(raw)
        if response:
            code = int(response.group(1))
            if not 100 <= code <= 599:
                unparsed.append(raw.decode("latin-1", "replace"))
                continue
            text = response.group(3).decode("latin-1")
            continuation = response.group(2) == b"-"
            if replies and replies[-1]["continuation"]:
                replies[-1]["lines"].append(text)
                replies[-1]["code"] = code
                replies[-1]["continuation"] = continuation
            else:
                replies.append(
                    {"code": code, "text": text, "lines": [text], "continuation": continuation}
                )
            continue

        command = COMMAND_LINE.match(raw)
        if command:
            verb = command.group(1).decode("latin-1").upper()
            if verb in COMMANDS:
                commands.append(_command(verb, (command.group(2) or b"").decode("latin-1").strip(), raw))
                continue
        if len(unparsed) < MAX_UNPARSED:
            unparsed.append(raw.decode("latin-1", "replace"))

    for reply in replies:
        reply["text"] = "\n".join(reply["lines"])

    info: dict = {
        "commands": commands,
        "replies": replies,
        "command_count": len(commands),
        "reply_count": len(replies),
        "unparsed_lines": unparsed,
        "errors": errors,
    }

    if commands and replies:
        info["kind"] = "mixed"
    elif commands:
        info["kind"] = "command"
    elif replies:
        info["kind"] = "response"
    else:
        raise DecodeError(
            "payload contains neither an SMTP command nor a status line",
            stage="application",
            first_line=first_line(data).decode("latin-1", "replace")[:120],
        )

    if commands:
        info["command"] = commands[0]["verb"]
        info["arguments"] = commands[0].get("arguments", "")
    if replies:
        info["status_code"] = replies[0]["code"]
        info["status_text"] = replies[0]["text"]
        info["last_status_code"] = replies[-1]["code"]
        if replies[-1]["continuation"]:
            errors.append(
                {
                    "stage": "application",
                    "code": "incomplete_reply",
                    "message": "last SMTP reply uses a continuation code with no terminating line",
                }
            )

    for command in commands:
        key = PATH_KEYS.get(command["verb"])
        if not key:
            continue
        if key == "mail_from":
            info["mail_from"] = command.get("address")
        else:
            info.setdefault("rcpt_to", []).append(command.get("address"))

    return info


def _command(verb: str, arguments: str, raw: bytes) -> dict:
    entry: dict = {"verb": verb, "arguments": arguments}
    path = PATH_LINE.match(raw)
    if path:
        address = ADDRESS.search(raw)
        if address:
            entry["address"] = address.group(1).decode("latin-1")
            tail = raw[address.end() :].decode("latin-1").strip()
            entry["parameters"] = tail.split() if tail else []
        else:
            tokens = path.group(2).decode("latin-1").split()
            entry["address"] = tokens[0] if tokens else ""
            entry["parameters"] = tokens[1:]
        entry["path"] = path.group(2).decode("latin-1").strip()
        return entry
    if verb in ("HELO", "EHLO"):
        entry["domain"] = arguments
        return entry
    if verb == "AUTH":
        auth = AUTH_LINE.match(raw)
        if auth:
            entry["mechanism"] = auth.group(1).decode("latin-1").upper()
            masked = auth.group(2)
            if masked:
                entry["credentials_present"] = True
        return entry
    return entry
