from __future__ import annotations

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

Detection = namedtuple(
    "Detection", "protocol method confidence port_matched port_hint evidence scores"
)


def detect(payload: bytes, *, src_port=None, dst_port=None, tcp: bool = False) -> Detection:
    if not payload:
        return Detection("UNKNOWN", "none", 0.0, False, None, "no payload to inspect", {})

    scores: dict[str, float] = {}
    evidence: dict[str, str | None] = {}
    for name, (score, why) in (
        ("HTTP", http.score(payload, tcp)),
        ("DNS", dns.score(payload, tcp)),
        ("SMTP", smtp.score(payload, tcp)),
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
