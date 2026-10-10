from __future__ import annotations

import base64
import dataclasses
import json
import typing
from datetime import datetime, timezone
from enum import Enum
from functools import cache

from .model.event import MessageEvent, PacketEvent
from .model.flow import FlowRecord

SCHEMA_VERSION = 2


@dataclasses.dataclass(frozen=True, slots=True)
class _Field:
    name: str
    key: str
    is_bytes: bool


def iso_timestamp(value: float | None) -> str | None:
    if value is None:
        return None
    try:
        moment = datetime.fromtimestamp(value, timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None
    return moment.isoformat(timespec="microseconds").replace("+00:00", "Z")


def to_jsonable(obj: object) -> object:
    kind = type(obj)
    if obj is None or kind is str or kind is int or kind is float or kind is bool:
        return obj
    if isinstance(obj, Enum):
        return obj.value
    if dataclasses.is_dataclass(kind):
        return _dump_fields(obj, {})
    if kind is list or kind is tuple:
        return [to_jsonable(item) for item in obj]
    if kind is dict:
        out: dict[str, object] = {}
        for key, value in obj.items():
            if type(key) is not str:
                raise TypeError(f"dict key {key!r} is not a str")
            out[key] = to_jsonable(value)
        return out
    raise TypeError(f"{kind.__name__} value {obj!r} is not JSON serialisable")


def _dump_fields(obj: object, out: dict[str, object]) -> dict[str, object]:
    for spec in _fields(type(obj)):
        value = getattr(obj, spec.name)
        if spec.is_bytes:
            out[spec.key] = None if value is None else base64.b64encode(value).decode("ascii")
        else:
            out[spec.key] = to_jsonable(value)
    return out


def encode(record: PacketEvent | MessageEvent | FlowRecord) -> dict[str, object]:
    if isinstance(record, PacketEvent):
        return _encode_packet(record)
    if isinstance(record, (MessageEvent, FlowRecord)):
        head: dict[str, object] = {
            "schema_version": SCHEMA_VERSION,
            "record_type": record.RECORD_TYPE,
        }
        return _dump_fields(record, head)
    raise TypeError(f"cannot encode {type(record).__name__}")


def _encode_packet(event: PacketEvent) -> dict[str, object]:
    return {
        "schema_version": SCHEMA_VERSION,
        "record_type": PacketEvent.RECORD_TYPE,
        "packet_id": to_jsonable(event.packet_id),
        "timestamp": to_jsonable(event.timestamp),
        "timestamp_iso": iso_timestamp(event.timestamp),
        "event_type": event.event_type,
        "src_ip": event.src_ip,
        "dst_ip": event.dst_ip,
        "src_port": event.src_port,
        "dst_port": event.dst_port,
        "protocol": event.protocol,
        "application_protocol": event.application_protocol,
        "preprocess_status": to_jsonable(event.preprocess_status),
        "processing_action": to_jsonable(event.processing_action),
        "reason": to_jsonable(event.reason),
        "flow": to_jsonable(event.flow),
        "capture": to_jsonable(event.capture),
        "link": to_jsonable(event.link),
        "network": to_jsonable(event.network),
        "transport": to_jsonable(event.transport),
        "application": to_jsonable(event.application),
        "payload": to_jsonable(event.payload),
        "decoded": to_jsonable(event.decoded),
        "normalized": to_jsonable(event.normalized),
        "issues": to_jsonable(event.issues),
    }


def encode_line(record: PacketEvent | MessageEvent | FlowRecord) -> str:
    return json.dumps(encode(record), ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def _is_bytes(hint: object) -> bool:
    return hint is bytes or bytes in typing.get_args(hint)


@cache
def _fields(cls: type) -> tuple[_Field, ...]:
    hints = typing.get_type_hints(cls)
    specs = []
    for item in dataclasses.fields(cls):
        key = item.metadata.get("json", item.name)
        is_bytes = _is_bytes(hints[item.name])
        specs.append(_Field(item.name, f"{key}_b64" if is_bytes else key, is_bytes))
    return tuple(specs)
