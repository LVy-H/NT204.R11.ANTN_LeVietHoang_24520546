from __future__ import annotations

import re

from ..model import MessageEvent, PacketEvent, SmtpSession, TcpInfo
from .tcp import SEQ_MOD, seq_ge

TERMINATOR = b"\r\n.\r\n"
_DATA_LINE = re.compile(rb"^DATA[ \t]*\r?$", re.IGNORECASE | re.MULTILINE)
_REPLY_354 = re.compile(rb"^354(?:[ \t-]|\r?$)", re.MULTILINE)

_IDLE, _WAIT_REPLY, _COLLECT = 0, 1, 2


def _seq_offset(seq: int, expected: int) -> int:
    """Signed distance from `expected` to `seq` in 32-bit sequence space."""
    diff = (seq - expected) % SEQ_MOD
    return diff if seq_ge(seq, expected) else diff - SEQ_MOD


def _has_data_command(data: bytes, session: SmtpSession | None) -> bool:
    if _DATA_LINE.search(data):
        return True
    return session is not None and any(command.verb == "DATA" for command in session.commands)


def _has_354(data: bytes, session: SmtpSession | None) -> bool:
    if _REPLY_354.search(data):
        return True
    return session is not None and any(reply.code == 354 for reply in session.replies)


class SmtpReassembler:
    """Rebuilds SMTP DATA bodies of one TCP flow into MessageEvents.

    The client is the side that sends `DATA`; collection starts after a `354` reply from the
    other side and stops at the `\\r\\n.\\r\\n` terminator, which is kept in `data`.
    """

    __slots__ = (
        "_buffer",
        "_client",
        "_count",
        "_end",
        "_flow_id",
        "_gap",
        "_max_bytes",
        "_next_seq",
        "_packet_ids",
        "_phase",
        "_seen",
        "_start",
        "_tail",
        "_truncated",
    )

    def __init__(self, flow_id: str, max_bytes: int) -> None:
        self._flow_id = flow_id
        self._max_bytes = max_bytes
        self._count = 0
        self._phase = _IDLE
        self._client: bool | None = None
        self._next_seq: int | None = None
        self._reset_message()

    def feed(self, event: PacketEvent, forward: bool, timestamp: float) -> MessageEvent | None:
        """Account one packet of the flow; return a MessageEvent when a body completes."""
        transport = event.transport
        if not isinstance(transport, TcpInfo):
            return None
        payload = event.payload
        data = payload.data if payload is not None and payload.data is not None else b""
        length = transport.payload_length if transport.payload_length is not None else len(data)
        if length == 0 and not data:
            return None
        message = event.application.message if event.application is not None else None
        session = message if isinstance(message, SmtpSession) else None

        if self._phase == _IDLE:
            if _has_data_command(data, session):
                self._phase = _WAIT_REPLY
                self._client = forward
                self._advance(transport.seq, length)
            return None
        if forward != self._client:
            if self._phase == _WAIT_REPLY and _has_354(data, session):
                self._phase = _COLLECT
            return None
        if self._phase == _WAIT_REPLY:
            self._advance(transport.seq, length)
            return None
        return self._collect(transport.seq, data, length, event.packet_id, timestamp)

    def finish(self) -> MessageEvent | None:
        """At flow export: the body being collected, if any, as an incomplete message."""
        if self._phase != _COLLECT or self._start is None:
            return None
        return self._emit(complete=False)

    def _advance(self, seq: int | None, length: int) -> None:
        if seq is None:
            return
        end = (seq + length) % SEQ_MOD
        if self._next_seq is None or _seq_offset(end, self._next_seq) > 0:
            self._next_seq = end

    def _collect(
        self, seq: int | None, data: bytes, length: int, packet_id: int | None, timestamp: float
    ) -> MessageEvent | None:
        offset = 0
        if seq is not None and self._next_seq is not None:
            offset = _seq_offset(seq, self._next_seq)
            if offset + length <= 0:
                return None  # retransmission of bytes already collected
        self._advance(seq, length)
        short = len(data) < length
        if offset > 0 or short:
            self._gap = True  # bytes before or inside this segment were never captured
        if offset > 0:
            self._tail = b""  # the terminator search must not span the missing bytes
        if offset < 0:
            data = data[-offset:]  # overlap with bytes already collected
        if not data:
            if short:
                self._tail = b""  # the missing bytes break the terminator search
            return None
        if packet_id is not None:
            self._packet_ids.append(packet_id)
        if self._start is None:
            self._start = timestamp
        self._end = timestamp

        # The body start counts as a line start, unless bytes before it were never captured.
        prefix = self._tail if self._seen or offset > 0 else b"\r\n"
        cut = (prefix + data[:4]).find(TERMINATOR)
        if cut >= 0:
            cut += len(TERMINATOR) - len(prefix)
        else:
            cut = data.find(TERMINATOR)
            if cut >= 0:
                cut += len(TERMINATOR)
        body = data if cut < 0 else data[:cut]
        room = self._max_bytes - len(self._buffer)
        if len(body) > room:
            self._buffer += body[:room]
            self._truncated = True
        else:
            self._buffer += body
        self._seen += len(body)
        self._tail = body[-4:] if len(body) >= 4 else (prefix + body)[-4:]
        if short:
            self._tail = b""  # bytes after this segment's captured part are missing
        if cut < 0:
            return None

        message = self._emit(complete=True)
        # Pipelined commands after the terminator may already contain the next DATA.
        self._phase = _WAIT_REPLY if _DATA_LINE.search(data, cut) else _IDLE
        return message

    def _emit(self, *, complete: bool) -> MessageEvent:
        self._count += 1
        message = MessageEvent(
            message_id=f"{self._flow_id}-{self._count}",
            flow_id=self._flow_id,
            protocol="SMTP",
            packet_ids=self._packet_ids,
            start_time=self._start,
            end_time=self._end,
            data=bytes(self._buffer),
            complete=complete,
            truncated=self._truncated,
            gap=self._gap,
        )
        self._phase = _IDLE
        self._reset_message()
        return message

    def _reset_message(self) -> None:
        self._buffer = bytearray()
        self._packet_ids: list[int] = []
        self._start: float | None = None
        self._end: float | None = None
        self._seen = 0
        self._tail = b""
        self._truncated = False
        self._gap = False
