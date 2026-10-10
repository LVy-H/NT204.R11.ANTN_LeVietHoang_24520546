from __future__ import annotations

import base64
import dataclasses
import json
import math
import types
import typing
from collections.abc import Callable
from datetime import datetime, timezone
from enum import Enum
from functools import cache
from typing import Any, TypeVar, Union

from .issues import Issue, Issues
from .model.event import MessageEvent, PacketEvent
from .model.flow import FlowRecord
from .model.packet import Ipv4Info, TcpInfo, UdpInfo

SCHEMA_VERSION = 2
MAX_JSON_DEPTH = 64

T = TypeVar("T")
Loader = Callable[[object, Issues, str], object]

_INVALID = object()
_NONE_TYPE = type(None)
_TRANSPORTS: dict[str, type[TcpInfo] | type[UdpInfo]] = {"tcp": TcpInfo, "udp": UdpInfo}


@dataclasses.dataclass(frozen=True, slots=True)
class _Field:
    name: str
    key: str
    is_bytes: bool
    load: Loader


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


def from_jsonable(cls: type[T], obj: object, issues: Issues, path: str) -> T | None:
    if not isinstance(obj, dict):
        _invalid(issues, path, cls.__name__, obj)
        return None
    return _load_object(cls, obj, issues, path)


def decode_packet(obj: object) -> tuple[PacketEvent, list[Issue]]:
    issues = Issues("load")
    if not isinstance(obj, dict):
        _invalid(issues, "", "object", obj)
        return PacketEvent(), issues.records
    if "schema_version" in obj:
        version = obj["schema_version"]
        if type(version) is not int or version != SCHEMA_VERSION:
            echoed = _echo(version)
            issues.add(
                "unsupported_schema",
                f"schema_version {echoed!r} is not supported",
                schema_version=echoed,
            )
    if "record_type" in obj:
        record_type = obj["record_type"]
        if record_type != PacketEvent.RECORD_TYPE:
            echoed = _echo(record_type)
            issues.add(
                "unsupported_schema",
                f"record_type {echoed!r} is not a packet record",
                record_type=echoed,
            )
    event = _load_object(PacketEvent, obj, issues, "")
    if obj.get("network") is None or obj.get("transport") is None:
        _flat_fallback(event, obj, issues)
    return event, issues.records


def _echo(value: object) -> object:
    kind = type(value)
    if value is None or kind is bool or kind is int:
        return value
    if kind is float and math.isfinite(value):
        return value
    if kind is str and _utf8(value):
        return value
    return kind.__name__


def _flat_fallback(event: PacketEvent, obj: dict[str, object], issues: Issues) -> None:
    protocol = _flat(obj, "protocol", _load_str, issues)
    if obj.get("network") is None:
        src_ip = _flat(obj, "src_ip", _load_str, issues)
        dst_ip = _flat(obj, "dst_ip", _load_str, issues)
        if src_ip is not None or dst_ip is not None:
            event.network = Ipv4Info(
                protocol="IPv4", src_ip=src_ip, dst_ip=dst_ip, protocol_name=protocol
            )
    if obj.get("transport") is None:
        info = _TRANSPORTS.get(protocol.casefold()) if protocol is not None else None
        if info is None:
            name = _flat(obj, "transport_protocol", _load_str, issues)
            info = _TRANSPORTS.get(name.casefold()) if name is not None else None
        if info is not None:
            event.transport = info(
                src_port=_flat(obj, "src_port", _load_int, issues),
                dst_port=_flat(obj, "dst_port", _load_int, issues),
            )


def _flat(obj: dict[str, object], key: str, load: Loader, issues: Issues) -> Any:
    value = obj.get(key)
    if value is None:
        return None
    loaded = load(value, issues, key)
    return None if loaded is _INVALID else loaded


def _load_object(cls: type[T], obj: dict[str, object], issues: Issues, path: str) -> T:
    prefix = f"{path}." if path else ""
    kwargs: dict[str, object] = {}
    for spec in _fields(cls):
        if spec.key in obj:
            loaded = spec.load(obj[spec.key], issues, prefix + spec.key)
            if loaded is not _INVALID:
                kwargs[spec.name] = loaded
    return cls(**kwargs)


def _invalid(issues: Issues, path: str, expected: str, value: object) -> object:
    got = type(value).__name__
    issues.add(
        "invalid_type",
        f"{path or 'record'}: expected {expected}, got {got}",
        field=path,
        expected=expected,
        got=got,
    )
    return _INVALID


def _utf8(text: str) -> bool:
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _load_str(value: object, issues: Issues, path: str) -> object:
    if type(value) is not str:
        return _invalid(issues, path, "str", value)
    return value if _utf8(value) else _invalid(issues, path, "UTF-8 str", value)


def _load_int(value: object, issues: Issues, path: str) -> object:
    return value if type(value) is int else _invalid(issues, path, "int", value)


def _load_bool(value: object, issues: Issues, path: str) -> object:
    return value if type(value) is bool else _invalid(issues, path, "bool", value)


def _load_float(value: object, issues: Issues, path: str) -> object:
    if type(value) is float:
        if math.isfinite(value):
            return value
    elif type(value) is int:
        try:
            return float(value)
        except OverflowError:
            pass
    return _invalid(issues, path, "float", value)


def _load_b64(value: object, issues: Issues, path: str) -> object:
    if type(value) is str:
        try:
            return base64.b64decode(value, validate=True)
        except ValueError:
            pass
    return _invalid(issues, path, "base64 str", value)


def _load_timestamp(value: object, issues: Issues, path: str) -> object:
    if type(value) is not str:
        return _load_float(value, issues, path)
    text = value.strip()
    if text[-1:] in ("Z", "z"):
        text = text[:-1] + "+00:00"
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return _invalid(issues, path, "float or ISO-8601 str", value)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.timestamp()


def _load_any(value: object, issues: Issues, path: str) -> object:
    return value if _is_json(value) else _invalid(issues, path, "JSON value", value)


def _is_json(value: object) -> bool:
    stack = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        kind = type(item)
        if kind is float:
            if not math.isfinite(item):
                return False
        elif kind is str:
            if not _utf8(item):
                return False
        elif kind is list or kind is dict:
            if depth > MAX_JSON_DEPTH:
                return False
            if kind is list:
                stack.extend((child, depth + 1) for child in item)
            else:
                for key, child in item.items():
                    if type(key) is not str or not _utf8(key):
                        return False
                    stack.append((child, depth + 1))
        elif not (item is None or kind is int or kind is bool):
            return False
    return True


def _optional(inner: Loader) -> Loader:
    def load(value: object, issues: Issues, path: str) -> object:
        return None if value is None else inner(value, issues, path)

    return load


def _list_of(item: Loader) -> Loader:
    def load(value: object, issues: Issues, path: str) -> object:
        if type(value) is not list:
            return _invalid(issues, path, "list", value)
        out = []
        for index, element in enumerate(value):
            loaded = item(element, issues, f"{path}[{index}]")
            if loaded is not _INVALID:
                out.append(loaded)
        return out

    return load


def _dict_of(item: Loader) -> Loader:
    def load(value: object, issues: Issues, path: str) -> object:
        if type(value) is not dict:
            return _invalid(issues, path, "object", value)
        out = {}
        for key, element in value.items():
            if type(key) is not str or not _utf8(key):
                _invalid(issues, path, "UTF-8 str key", key)
                continue
            loaded = item(element, issues, f"{path}.{key}")
            if loaded is not _INVALID:
                out[key] = loaded
        return out

    return load


def _enum_of(cls: type[Enum]) -> Loader:
    def load(value: object, issues: Issues, path: str) -> object:
        if type(value) is str:
            try:
                return cls(value)
            except ValueError:
                pass
        return _invalid(issues, path, cls.__name__, value)

    return load


def _dataclass_of(cls: type) -> Loader:
    def load(value: object, issues: Issues, path: str) -> object:
        if type(value) is not dict:
            return _invalid(issues, path, cls.__name__, value)
        return _load_object(cls, value, issues, path)

    return load


def _tagged_union_of(members: tuple[type, ...]) -> Loader:
    tags = [(cls.TAG[0], cls.TAG[1].casefold(), cls) for cls in members]
    expected = " | ".join(cls.__name__ for cls in members)

    def load(value: object, issues: Issues, path: str) -> object:
        if type(value) is dict:
            for key, tag, cls in tags:
                found = value.get(key)
                if type(found) is str and found.casefold() == tag:
                    return _load_object(cls, value, issues, path)
        return _invalid(issues, path, expected, value)

    return load


_SCALARS: dict[object, Loader] = {
    str: _load_str,
    int: _load_int,
    float: _load_float,
    bool: _load_bool,
    bytes: _load_b64,
}

_FIELD_LOADERS: dict[tuple[type, str], Loader] = {
    (PacketEvent, "timestamp"): _optional(_load_timestamp),
}


def _loader(hint: object) -> Loader:
    if hint is object or hint is Any:
        return _load_any
    origin = typing.get_origin(hint)
    if origin is Union or origin is types.UnionType:
        args = typing.get_args(hint)
        members = tuple(arg for arg in args if arg is not _NONE_TYPE)
        if len(members) == 1:
            inner = _loader(members[0])
        elif all(dataclasses.is_dataclass(member) for member in members):
            inner = _tagged_union_of(members)
        else:
            raise TypeError(f"unsupported union {hint!r}")
        return _optional(inner) if len(members) < len(args) else inner
    if origin is list:
        return _list_of(_loader(typing.get_args(hint)[0]))
    if origin is dict:
        key, item = typing.get_args(hint)
        if key is not str:
            raise TypeError(f"unsupported dict key type {key!r}")
        return _dict_of(_loader(item))
    if hint in _SCALARS:
        return _SCALARS[hint]
    if isinstance(hint, type) and issubclass(hint, Enum):
        return _enum_of(hint)
    if isinstance(hint, type) and dataclasses.is_dataclass(hint):
        return _dataclass_of(hint)
    raise TypeError(f"unsupported field type {hint!r}")


def _is_bytes(hint: object) -> bool:
    return hint is bytes or bytes in typing.get_args(hint)


@cache
def _fields(cls: type) -> tuple[_Field, ...]:
    hints = typing.get_type_hints(cls)
    specs = []
    for item in dataclasses.fields(cls):
        hint = hints[item.name]
        key = item.metadata.get("json", item.name)
        is_bytes = _is_bytes(hint)
        if is_bytes:
            key = f"{key}_b64"
        load = _FIELD_LOADERS.get((cls, item.name)) or _loader(hint)
        specs.append(_Field(item.name, key, is_bytes, load))
    return tuple(specs)
