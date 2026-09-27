from __future__ import annotations

from datetime import datetime, timezone

UNKNOWN = "UNKNOWN"

SCHEMA_VERSION = 1


def iso_timestamp(value: float):
    try:
        return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def _event_type(network, transport, protocol, application, payload_length) -> str:
    if network is None:
        return "unparsed"
    if transport is None:
        return "network_only"
    kind = (application or {}).get("kind")
    if kind:
        return f"{protocol.lower()}_{kind}"
    if protocol != UNKNOWN:
        return f"{protocol.lower()}_unparsed"
    if payload_length:
        return "unknown_payload"
    return f"{transport['protocol'].lower()}_segment"


def build_event(
    raw,
    *,
    capture: dict,
    link,
    network,
    transport,
    payload: dict,
    detection,
    application,
    errors: list[dict],
) -> dict:
    protocol = detection.protocol if detection else UNKNOWN
    event = {
        "schema_version": SCHEMA_VERSION,
        "packet_id": raw.packet_id,
        "timestamp": raw.timestamp,
        "timestamp_iso": iso_timestamp(raw.timestamp),
        "event_type": _event_type(network, transport, protocol, application, payload["length"]),
        "network_protocol": network["protocol"] if network else None,
        "transport_protocol": transport["protocol"] if transport else None,
        "application_protocol": protocol,
        "src_ip": network["src_ip"] if network else None,
        "dst_ip": network["dst_ip"] if network else None,
        "src_port": transport["src_port"] if transport else None,
        "dst_port": transport["dst_port"] if transport else None,
        "capture": capture,
        "link": link,
        "network": network,
        "transport": transport,
        "application": {
            "protocol": protocol,
            "detection": (
                {
                    "method": detection.method,
                    "confidence": detection.confidence,
                    "port_matched": detection.port_matched,
                    "port_hint": detection.port_hint,
                    "evidence": detection.evidence,
                    "scores": detection.scores,
                }
                if detection
                else None
            ),
            (protocol.lower() if protocol != UNKNOWN else "unknown"): application,
        },
        "payload": payload,
        "errors": errors,
    }
    return event
