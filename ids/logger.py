from __future__ import annotations

import json
import sys
from pathlib import Path

DEFAULT_FLUSH_EVERY = 100


class JsonlWriter:
    def __init__(self, path=None, *, flush_every=DEFAULT_FLUSH_EVERY, stream=None):
        self.path = path
        self.count = 0
        self._pending = 0
        self._owns_stream = stream is None
        if stream is not None:
            self._stream = stream
            self.flush_every = 1
        elif path in (None, "-"):
            self._stream = sys.stdout
            self.flush_every = 1
            self.path = "-"
        else:
            self._stream = Path(path).open("w", encoding="utf-8")
            self.flush_every = max(1, flush_every)

    def write(self, event: dict) -> None:
        self._stream.write(
            json.dumps(event, ensure_ascii=False, separators=(",", ":"), default=str)
        )
        self._stream.write("\n")
        self.count += 1
        self._pending += 1
        if self._pending >= self.flush_every:
            self.flush()

    def writemany(self, events) -> None:
        for event in events:
            self.write(event)

    def flush(self) -> None:
        self._stream.flush()
        self._pending = 0

    def close(self) -> None:
        if self._owns_stream and self._stream is not sys.stdout:
            self.flush()
            self._stream.close()
        else:
            self.flush()

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self.close()
        return False
