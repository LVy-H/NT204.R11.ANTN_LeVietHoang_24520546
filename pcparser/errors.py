from __future__ import annotations

__all__ = [
    "PacketParseError",
    "TruncatedPacketError",
    "MalformedHeaderError",
    "UnsupportedProtocolError",
    "DecodeError",
    "ErrorCollector",
    "jsonable",
]


def jsonable(value):
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).hex()
    if isinstance(value, dict):
        return {str(k): jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [jsonable(v) for v in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return repr(value)


class PacketParseError(Exception):
    stage = "unknown"
    code = "parse_error"

    def __init__(self, message, *, stage=None, **context):
        super().__init__(message)
        self.message = message
        self.stage = stage if stage is not None else type(self).stage
        self.context = context

    def to_dict(self):
        record = {"stage": self.stage, "code": self.code, "message": self.message}
        if self.context:
            record["context"] = jsonable(self.context)
        return record


class TruncatedPacketError(PacketParseError):
    stage = "capture"
    code = "truncated_packet"


class MalformedHeaderError(PacketParseError):
    stage = "parse"
    code = "malformed_header"


class UnsupportedProtocolError(PacketParseError):
    stage = "detect"
    code = "unsupported_protocol"


class DecodeError(PacketParseError):
    stage = "decode"
    code = "decode_error"


class ErrorCollector:
    def __init__(self):
        self.records = []

    def add(self, error):
        self.records.append(error.to_dict())

    def add_raw(self, stage, code, message):
        self.records.append({"stage": stage, "code": code, "message": message})

    def add_exception(self, exc, stage):
        self.records.append(
            {
                "stage": stage,
                "code": "internal_error",
                "message": str(exc) or exc.__class__.__name__,
                "context": {"exception": exc.__class__.__name__},
            }
        )

    def extend(self, records):
        self.records.extend(records)

    def __bool__(self):
        return bool(self.records)

    def __len__(self):
        return len(self.records)

    def __iter__(self):
        return iter(self.records)
