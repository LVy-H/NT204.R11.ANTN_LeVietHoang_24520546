from __future__ import annotations

from ..model import Detection
from ..model.event import UNKNOWN
from .registry import PROTOCOLS, STANDARD_PORTS

PORT_BOOST = 0.25
MIN_CONFIDENCE = 0.5
PORT_ONLY_CONFIDENCE = 0.3


def _rounded(scores: dict[str, float]) -> dict[str, float]:
    return {name: round(value, 2) for name, value in scores.items()}


def detect(payload: bytes, *, src_port: int | None, dst_port: int | None, tcp: bool) -> Detection:
    if not payload:
        return Detection(
            protocol=UNKNOWN,
            method="none",
            confidence=0.0,
            port_matched=False,
            evidence="no payload to inspect",
        )

    scores: dict[str, float] = {}
    evidence: dict[str, str | None] = {}
    for protocol in PROTOCOLS:
        scores[protocol.name], evidence[protocol.name] = protocol.score(payload, tcp)

    port_hint = STANDARD_PORTS.get(src_port) or STANDARD_PORTS.get(dst_port)
    if port_hint:
        scores[port_hint] = min(scores[port_hint] + PORT_BOOST, 1.0)

    best = max(scores, key=scores.__getitem__)
    if scores[best] >= MIN_CONFIDENCE:
        payload_matched = evidence[best] is not None
        port_matched = port_hint == best
        if payload_matched and port_matched:
            method = "port+payload"
        elif payload_matched:
            method = "payload"
        else:
            method = "port"
        return Detection(
            protocol=best,
            method=method,
            confidence=round(scores[best], 2),
            port_matched=port_matched,
            port_hint=port_hint,
            evidence=evidence[best],
            scores=_rounded(scores),
        )

    if port_hint:
        return Detection(
            protocol=port_hint,
            method="port",
            confidence=PORT_ONLY_CONFIDENCE,
            port_matched=True,
            port_hint=port_hint,
            evidence="standard port with no recognisable signature",
            scores=_rounded(scores),
        )

    return Detection(
        protocol=UNKNOWN,
        method="none",
        confidence=0.0,
        port_matched=False,
        evidence="no signature matched and no standard port",
        scores=_rounded(scores),
    )
