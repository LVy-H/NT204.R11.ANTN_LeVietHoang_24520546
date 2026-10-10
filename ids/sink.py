from __future__ import annotations

import sys
from types import TracebackType
from typing import TextIO

from .codec import encode_line
from .model import FlowRecord, MessageEvent, PacketEvent


class _Output:
    __slots__ = ("flush_every", "owned", "pending", "stream")

    def __init__(self, path: str | None, flush_every: int) -> None:
        self.stream: TextIO
        if path is None or path == "-":
            self.stream = sys.stdout
            self.owned = False
            self.flush_every = 1
        else:
            self.stream = open(path, "w", encoding="utf-8")
            self.owned = True
            self.flush_every = max(1, flush_every)
        self.pending = 0

    def write(self, line: str) -> None:
        self.stream.write(line)
        self.stream.write("\n")
        self.pending += 1
        if self.pending >= self.flush_every:
            self.stream.flush()
            self.pending = 0

    def close(self) -> None:
        self.stream.flush()
        if self.owned:
            self.stream.close()


class JsonlSink:
    def __init__(
        self, path: str | None = "-", *, flows_path: str | None = None, flush_every: int = 100
    ) -> None:
        self._main = _Output(path, flush_every)
        try:
            self._flows = _Output(flows_path, flush_every) if flows_path is not None else None
        except OSError:
            self._main.close()
            raise
        self._closed = False

    def write(self, record: PacketEvent | MessageEvent | FlowRecord) -> None:
        if self._flows is not None and isinstance(record, FlowRecord):
            self._flows.write(encode_line(record))
        else:
            self._main.write(encode_line(record))

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._main.close()
        finally:
            if self._flows is not None:
                self._flows.close()

    def __enter__(self) -> JsonlSink:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()
