from __future__ import annotations

import re
from collections import namedtuple

from ..errors import PacketParseError
from . import dns, http, smtp

STANDARD_PORTS = {
    53: "DNS",
    80: "HTTP",
    465: "SMTP",
    587: "SMTP",
    2525: "SMTP",
    3128: "HTTP",
    8000: "HTTP",
    8008: "HTTP",
    8080: "HTTP",
    8081: "HTTP",
    8888: "HTTP",
    9080: "HTTP",
    5353: "DNS",
    25: "SMTP",
}

PROTOCOLS = ("HTTP", "DNS", "SMTP")
PORT_BOOST = 0.25
MIN_CONFIDENCE = 0.5
PORT_ONLY_CONFIDENCE = 0.3

SMTP_CODES = frozenset(
    (211, 214, 220, 221, 250, 251, 252, 354, 421, 450, 451, 452, 455, 500, 501, 502, 503, 504, 530,
     532, 550, 551, 552, 553, 554, 555)
)

HTTP_REQUEST_LINE = re.compile(
    rb"^(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT|PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK)"
    rb"[ \t]+\S+[ \t]+HTTP/\d\.\d"
)
HTTP_STATUS_LINE = re.compile(rb"^HTTP/\d\.\d[ \t]+\d{3}")
HTTP_METHOD_TOKEN = re.compile(rb"^[A-Z]{3,12}[ \t]+\S")
HTTP_VERSION_TOKEN = re.compile(rb"HTTP/\d\.\d")

SMTP_HELLO = re.compile(rb"^(?:HELO|EHLO)[ \t]+\S", re.IGNORECASE)
SMTP_PATH = re.compile(rb"^(?:MAIL|RCPT)[ \t]+(?:FROM|TO)[ \t]*:", re.IGNORECASE)
SMTP_VERB = re.compile(
    rb"^(?:DATA|QUIT|RSET|NOOP|VRFY|EXPN|HELP|AUTH|STARTTLS|BDAT|ETRN)(?:[ \t]|$)", re.IGNORECASE
)
SMTP_STATUS_LINE = re.compile(rb"^([2-5]\d{2})([ -]|$)")

PLAUSIBLE_LABEL = re.compile(rb"^[A-Za-z0-9_-]{1,63}$")

Detection = namedtuple(
    "Detection", "protocol method confidence port_matched port_hint evidence scores"
)


def _plausible_name(name: str) -> bool:
    if not name or name == ".":
        return False
    labels = name.rstrip(".").split(".")
    return all(PLAUSIBLE_LABEL.match(label.encode("latin-1", "replace")) for label in labels if label)


def http_score(payload: bytes) -> tuple[float, str | None]:
    line = http.first_line(payload[:512])
    if HTTP_STATUS_LINE.match(line):
        return 0.95, "HTTP status line"
    if HTTP_REQUEST_LINE.match(line):
        return 0.95, "HTTP request line"
    if HTTP_METHOD_TOKEN.match(line):
        if HTTP_VERSION_TOKEN.search(payload[:512]):
            return 0.8, "HTTP request line without a strict version token"
        return 0.6, "HTTP method token"
    return 0.0, None


def dns_score(payload: bytes, tcp: bool) -> tuple[float, str | None]:
    if tcp:
        if len(payload) < 14:
            return 0.0, None
        declared = int.from_bytes(payload[:2], "big")
        if declared < 12 or declared + 2 > len(payload):
            return 0.0, None
    elif len(payload) < 12:
        return 0.0, None

    try:
        message = dns.parse(payload, tcp=tcp)
    except PacketParseError:
        return 0.0, None

    if message["opcode"] not in dns.OPCODES:
        return 0.2, "DNS header with an unknown opcode"

    score = 0.45
    evidence = ["DNS header"]
    questions = message["questions"]
    if questions:
        question = questions[0]
        if _plausible_name(question["name"]):
            score += 0.25
            evidence.append("plausible question name")
        if question["type"] in dns.QTYPES:
            score += 0.15
            evidence.append(f"known qtype {question['type_name']}")
        if question["class"] in dns.QCLASSES:
            score += 0.05
    if message["kind"] == "response" and message["counts"]["answers"]:
        score += 0.10
        evidence.append("response with answers")
    return min(score, 1.0), ", ".join(evidence)


def smtp_score(payload: bytes) -> tuple[float, str | None]:
    line = smtp.first_line(payload[:512])
    if SMTP_HELLO.match(line):
        return 0.95, "SMTP HELO/EHLO command"
    if SMTP_PATH.match(line):
        return 0.95, "SMTP MAIL/RCPT path"
    status = SMTP_STATUS_LINE.match(line)
    if status:
        code = int(status.group(1))
        if status.group(2) == b"-" or code in SMTP_CODES:
            return 0.85, f"SMTP status code {code}"
        return 0.6, f"numeric status line {code}"
    if SMTP_VERB.match(line):
        return 0.7, "SMTP verb"
    return 0.0, None


def detect(payload: bytes, *, src_port=None, dst_port=None, tcp: bool = False) -> Detection:
    if not payload:
        return Detection("UNKNOWN", "none", 0.0, False, None, "no payload to inspect", {})

    scores: dict[str, float] = {}
    evidence: dict[str, str | None] = {}
    for name, (score, why) in (
        ("HTTP", http_score(payload)),
        ("DNS", dns_score(payload, tcp)),
        ("SMTP", smtp_score(payload)),
    ):
        scores[name] = score
        evidence[name] = why

    hints = [STANDARD_PORTS[port] for port in (src_port, dst_port) if port in STANDARD_PORTS]
    port_hint = hints[0] if hints else None
    if port_hint:
        scores[port_hint] = min(scores[port_hint] + PORT_BOOST, 1.0)

    best = max(PROTOCOLS, key=lambda name: scores[name])
    payload_matched = evidence[best] is not None
    port_matched = port_hint == best

    if scores[best] >= MIN_CONFIDENCE:
        if payload_matched and port_matched:
            method = "port+payload"
        elif payload_matched:
            method = "payload"
        else:
            method = "port"
        return Detection(
            best,
            method,
            round(scores[best], 2),
            port_matched,
            port_hint,
            evidence[best],
            {name: round(value, 2) for name, value in scores.items()},
        )

    if port_hint:
        return Detection(
            port_hint,
            "port",
            PORT_ONLY_CONFIDENCE,
            True,
            port_hint,
            "standard port with no recognisable signature",
            {name: round(value, 2) for name, value in scores.items()},
        )

    return Detection(
        "UNKNOWN",
        "none",
        0.0,
        False,
        None,
        "no signature matched and no standard port",
        {name: round(value, 2) for name, value in scores.items()},
    )
