from __future__ import annotations

import re
from collections import namedtuple

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

SMTP_HELLO = re.compile(rb"^(?:HELO|EHLO)[ \t]+\S", re.IGNORECASE)
SMTP_PATH = re.compile(rb"^(?:MAIL|RCPT)[ \t]+(?:FROM|TO)[ \t]*:", re.IGNORECASE)
SMTP_VERB = re.compile(
    rb"^(?:DATA|QUIT|RSET|NOOP|VRFY|EXPN|HELP|AUTH|STARTTLS|BDAT|ETRN)(?:[ \t]|$)", re.IGNORECASE
)
SMTP_STATUS_LINE = re.compile(rb"^([2-5]\d{2})([ -]|$)")

Detection = namedtuple(
    "Detection", "protocol method confidence port_matched port_hint evidence scores"
)


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
        return 0.45, f"numeric status line {code}"
    if SMTP_VERB.match(line):
        return 0.7, "SMTP verb"
    return 0.0, None


def detect(payload: bytes, *, src_port=None, dst_port=None, tcp: bool = False) -> Detection:
    if not payload:
        return Detection("UNKNOWN", "none", 0.0, False, None, "no payload to inspect", {})

    scores: dict[str, float] = {}
    evidence: dict[str, str | None] = {}
    for name, (score, why) in (
        ("HTTP", http.score(payload, tcp)),
        ("DNS", dns.score(payload, tcp)),
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
