from __future__ import annotations

import pytest
from flow_events import T0, app, make_table, smtp_app, tcp_event

from ids.flow.key import make_key
from ids.flow.smtp import SmtpReassembler
from ids.flow.tcp import SEQ_MOD
from ids.model import (
    EndReason,
    FlowRecord,
    MessageEvent,
    SmtpCommand,
    SmtpReply,
    SmtpSession,
)

FLOW_ID = "0123456789abcdef"
MAIL_CLIENT = ("10.0.0.1", 40000)
MAIL_SERVER = ("10.0.0.2", 25)


class Exchange:
    """Feeds client/server segments with running sequence numbers into one reassembler."""

    def __init__(self, *, max_bytes=1_048_576, client_seq=1000, client_forward=True):
        self.reassembler = SmtpReassembler(FLOW_ID, max_bytes)
        self.client_seq = client_seq
        self.server_seq = 5000
        self.client_forward = client_forward
        self.events = []

    def _event(self, src, dst, data, seq, ack):
        packet_id = len(self.events) + 1
        event = tcp_event(packet_id, T0 + packet_id, src, dst, "PA", seq=seq, ack=ack, payload=data)
        self.events.append(event)
        return event

    def client(self, data: bytes, *, seq: int | None = None, event=None):
        start = self.client_seq if seq is None else seq
        if event is None:
            event = self._event(MAIL_CLIENT, MAIL_SERVER, data, start, self.server_seq)
        end = (start + event.transport.payload_length) % SEQ_MOD
        if (end - self.client_seq) % SEQ_MOD < 1 << 31:
            self.client_seq = end
        return self.reassembler.feed(event, self.client_forward, event.timestamp)

    def server(self, data: bytes):
        event = self._event(MAIL_SERVER, MAIL_CLIENT, data, self.server_seq, self.client_seq)
        self.server_seq += len(data)
        return self.reassembler.feed(event, not self.client_forward, event.timestamp)

    def start(self):
        assert self.client(b"DATA\r\n") is None
        assert self.server(b"354 End data with <CR><LF>.<CR><LF>\r\n") is None


def test_message_split_over_two_segments():
    exchange = Exchange()
    exchange.start()
    assert exchange.client(b"Subject: hi\r\n\r\nline one\r\n") is None
    message = exchange.client(b"line two\r\n.\r\n")
    assert isinstance(message, MessageEvent)
    assert message.data == b"Subject: hi\r\n\r\nline one\r\nline two\r\n.\r\n"
    assert (message.complete, message.truncated, message.gap) == (True, False, False)
    assert (message.message_id, message.flow_id, message.protocol) == (
        f"{FLOW_ID}-1",
        FLOW_ID,
        "SMTP",
    )
    assert message.packet_ids == [3, 4]
    assert (message.start_time, message.end_time) == (T0 + 3, T0 + 4)


@pytest.mark.parametrize("split", [1, 2, 3, 4])
def test_terminator_split_across_segments_is_found(split):
    exchange = Exchange()
    exchange.start()
    stream = b"body\r\n.\r\n"
    assert exchange.client(stream[: 4 + split]) is None
    message = exchange.client(stream[4 + split :])
    assert message.data == stream
    assert message.complete is True


def test_empty_message_is_a_lone_dot_line():
    exchange = Exchange()
    exchange.start()
    message = exchange.client(b".\r\n")
    assert message.data == b".\r\n"
    assert message.complete is True


def test_dot_that_does_not_start_a_line_is_not_the_terminator():
    exchange = Exchange()
    exchange.start()
    assert exchange.client(b"a.\r\n") is None
    assert exchange.client(b"b\r\n.\r\n").data == b"a.\r\nb\r\n.\r\n"


def test_retransmitted_and_overlapping_segments_are_trimmed():
    exchange = Exchange()
    exchange.start()
    first_seq = exchange.client_seq
    assert exchange.client(b"Hello\r\n") is None
    assert exchange.client(b"Hello\r\n", seq=first_seq) is None  # full retransmission
    message = exchange.client(b"o\r\nWorld\r\n.\r\n", seq=first_seq + 4)  # 3 bytes overlap
    assert message.data == b"Hello\r\nWorld\r\n.\r\n"
    assert message.packet_ids == [3, 5]
    assert message.gap is False


def test_missing_bytes_set_gap_and_collection_continues():
    exchange = Exchange()
    exchange.start()
    assert exchange.client(b"part one\r\n") is None
    message = exchange.client(b"part three\r\n.\r\n", seq=exchange.client_seq + 50)
    assert message.data == b"part one\r\npart three\r\n.\r\n"
    assert (message.gap, message.complete) == (True, True)


def test_segment_captured_shorter_than_its_length_sets_gap():
    exchange = Exchange()
    exchange.start()
    seq = exchange.client_seq
    short = tcp_event(3, T0 + 3, MAIL_CLIENT, MAIL_SERVER, "PA", seq=seq, ack=1, payload=b"12345")
    short.transport.payload_length = 20  # only 5 of 20 bytes kept (--max-payload-bytes)
    exchange.events.append(short)
    assert exchange.client(b"", event=short) is None
    message = exchange.client(b"tail\r\n.\r\n")
    assert message.data == b"12345tail\r\n.\r\n"
    assert message.gap is True


def test_cap_keeps_the_first_bytes_and_still_finds_the_terminator():
    exchange = Exchange(max_bytes=8)
    exchange.start()
    message = exchange.client(b"0123456789abcdef\r\n.\r\n")
    assert message.data == b"01234567"
    assert (message.truncated, message.complete) == (True, True)


def test_terminator_straddling_segments_is_found_after_the_cap():
    exchange = Exchange(max_bytes=4)
    exchange.start()
    assert exchange.client(b"AAAAAAAAAA\r\n.") is None
    message = exchange.client(b"\r\n")
    assert message.data == b"AAAA"
    assert (message.truncated, message.complete) == (True, True)


def test_flow_end_during_collection_gives_an_incomplete_message():
    exchange = Exchange()
    exchange.start()
    exchange.client(b"partial body\r\n")
    message = exchange.reassembler.finish()
    assert message.data == b"partial body\r\n"
    assert message.complete is False
    assert message.packet_ids == [3]
    assert exchange.reassembler.finish() is None


def test_nothing_to_finish_without_collected_bytes():
    idle = Exchange()
    assert idle.reassembler.finish() is None
    waiting = Exchange()
    waiting.client(b"DATA\r\n")
    assert waiting.reassembler.finish() is None
    accepted = Exchange()
    accepted.start()
    assert accepted.reassembler.finish() is None


def test_pipelined_data_in_the_same_segment_as_rcpt():
    exchange = Exchange()
    exchange.client(b"MAIL FROM:<a@example.test>\r\nRCPT TO:<b@example.test>\r\nDATA\r\n")
    exchange.server(b"250 OK\r\n250 OK\r\n354 go ahead\r\n")
    assert exchange.client(b"Hi\r\n.\r\n").data == b"Hi\r\n.\r\n"


def test_body_is_not_collected_without_a_354_after_data():
    rejected = Exchange()
    rejected.client(b"DATA\r\n")
    rejected.server(b"554 no valid recipients\r\n")
    assert rejected.client(b"body\r\n.\r\n") is None
    early = Exchange()
    early.server(b"354 go ahead\r\n")
    assert early.client(b"body\r\n.\r\n") is None


def test_several_messages_in_one_flow_are_numbered():
    exchange = Exchange()
    exchange.start()
    first = exchange.client(b"one\r\n.\r\n")
    exchange.client(b"MAIL FROM:<a@example.test>\r\n")
    exchange.server(b"250 OK\r\n")
    exchange.start()
    second = exchange.client(b"two\r\n.\r\n")
    assert [first.message_id, second.message_id] == [f"{FLOW_ID}-1", f"{FLOW_ID}-2"]
    assert second.data == b"two\r\n.\r\n"
    assert second.packet_ids == [8]


def test_next_data_pipelined_after_the_terminator():
    exchange = Exchange()
    exchange.start()
    first = exchange.client(b"one\r\n.\r\nMAIL FROM:<a@x.test>\r\nRCPT TO:<b@x.test>\r\nDATA\r\n")
    assert first.data == b"one\r\n.\r\n"
    exchange.server(b"250 OK\r\n250 OK\r\n354 go ahead\r\n")
    second = exchange.client(b"two\r\n.\r\n")
    assert second.data == b"two\r\n.\r\n"
    assert second.message_id == f"{FLOW_ID}-2"


def test_parsed_commands_and_replies_also_drive_collection():
    exchange = Exchange()
    data_cmd = tcp_event(1, T0 + 1, MAIL_CLIENT, MAIL_SERVER, "PA", seq=1000, ack=5000)
    data_cmd.transport.payload_length = 6
    data_cmd.application = smtp_app(SmtpSession(commands=[SmtpCommand(verb="DATA")]))
    reply = tcp_event(2, T0 + 2, MAIL_SERVER, MAIL_CLIENT, "PA", seq=5000, ack=1006)
    reply.transport.payload_length = 10
    reply.application = smtp_app(SmtpSession(replies=[SmtpReply(code=354)]))
    exchange.events += [data_cmd, reply]
    exchange.reassembler.feed(data_cmd, True, data_cmd.timestamp)
    exchange.reassembler.feed(reply, False, reply.timestamp)
    exchange.client_seq = 1006
    message = exchange.client(b"x\r\n.\r\n")
    assert message.data == b"x\r\n.\r\n"
    assert message.gap is False


def test_client_seen_as_endpoint_b_in_a_midstream_capture():
    exchange = Exchange(client_forward=False)
    exchange.start()
    assert exchange.client(b"Hi\r\n.\r\n").data == b"Hi\r\n.\r\n"


def test_sequence_numbers_wrapping_around_during_collection():
    exchange = Exchange(client_seq=SEQ_MOD - 6)
    exchange.start()  # DATA\r\n ends exactly at the wrap
    assert exchange.client_seq == 0
    assert exchange.client(b"Hello\r\n") is None
    assert exchange.client(b"Hello\r\n", seq=0) is None
    message = exchange.client(b"\r\n.\r\n")
    assert message.data == b"Hello\r\n\r\n.\r\n"
    assert message.gap is False


def smtp_flow_events(application=None, body=b"Subject: x\r\n\r\nhello\r\n.\r\n"):
    application = application or smtp_app()
    c, s = MAIL_CLIENT, MAIL_SERVER
    return [
        tcp_event(
            1, T0, c, s, "PA", seq=100, ack=900, payload=b"EHLO c\r\n", application=application
        ),
        tcp_event(2, T0 + 1, s, c, "PA", seq=900, ack=108, payload=b"250 ok\r\n"),
        tcp_event(3, T0 + 2, c, s, "PA", seq=108, ack=908, payload=b"DATA\r\n"),
        tcp_event(4, T0 + 3, s, c, "PA", seq=908, ack=114, payload=b"354 go\r\n"),
        tcp_event(5, T0 + 4, c, s, "PA", seq=114, ack=916, payload=body),
    ]


def feed_all(table, events, out):
    for event in events:
        key, src, dst = make_key(event)
        table.apply(event, key, src, dst, event.timestamp, out.append)


def test_table_emits_the_message_while_applying_the_terminating_packet():
    table, out = make_table(), []
    events = smtp_flow_events()
    feed_all(table, events[:-1], out)
    assert out == []
    feed_all(table, events[-1:], out)
    assert [type(r) for r in out] == [MessageEvent]
    table.flush(out.append)
    message, record = out
    assert isinstance(record, FlowRecord)
    assert message.flow_id == record.flow_id
    assert message.message_id == f"{record.flow_id}-1"
    assert message.data == b"Subject: x\r\n\r\nhello\r\n.\r\n"


@pytest.mark.parametrize(
    ("finish", "reason"),
    [
        ("flush", EndReason.END_OF_INPUT),
        ("evict", EndReason.EVICTED),
        ("expire", EndReason.IDLE_TIMEOUT),
    ],
)
def test_flow_export_mid_message_emits_it_incomplete_before_the_record(finish, reason):
    table, out = make_table(max_flows=1), []
    feed_all(table, smtp_flow_events(body=b"Subject: x\r\n\r\nunfinished"), out)
    if finish == "flush":
        table.flush(out.append)
    elif finish == "evict":
        other = tcp_event(6, T0 + 5, ("10.0.0.9", 1234), MAIL_SERVER, "S", seq=1, ack=0)
        feed_all(table, [other], out)
    else:
        table.advance(T0 + 400, out.append)
    message, record = out[:2]
    assert isinstance(message, MessageEvent)
    assert (message.complete, message.data) == (False, b"Subject: x\r\n\r\nunfinished")
    assert (record.flow_id, record.end_reason) == (message.flow_id, reason)


def test_flows_not_detected_as_smtp_are_not_reassembled():
    table, out = make_table(), []
    feed_all(table, smtp_flow_events(application=app("HTTP", "payload", 0.9)), out)
    table.flush(out.append)
    assert [type(r) for r in out] == [FlowRecord]


def test_gap_clears_the_terminator_search_tail():
    exchange = Exchange()
    exchange.start()
    assert exchange.client(b"x\r\n.") is None
    message = exchange.client(b"\r\nmore\r\n.\r\n", seq=exchange.client_seq + 10)
    assert message.data == b"x\r\n.\r\nmore\r\n.\r\n"
    assert message.gap is True


def _short_segment(exchange, payload, seq, length):
    packet_id = len(exchange.events) + 1
    event = tcp_event(
        packet_id, T0 + packet_id, MAIL_CLIENT, MAIL_SERVER, "PA", seq=seq, ack=1, payload=payload
    )
    event.transport.payload_length = length
    exchange.events.append(event)
    return exchange.client(b"", seq=seq, event=event)


def test_short_segment_clears_the_terminator_search_tail():
    exchange = Exchange()
    exchange.start()
    assert _short_segment(exchange, b"x\r\n.", exchange.client_seq, 20) is None
    message = exchange.client(b"\r\nmore\r\n.\r\n")
    assert message.data == b"x\r\n.\r\nmore\r\n.\r\n"
    assert message.gap is True


def test_short_retransmission_without_new_bytes_clears_the_tail():
    exchange = Exchange()
    exchange.start()
    first_seq = exchange.client_seq
    assert exchange.client(b"x\r\n.") is None
    assert _short_segment(exchange, b"x\r\n.", first_seq, 14) is None
    message = exchange.client(b"\r\nmore\r\n.\r\n")
    assert message.data == b"x\r\n.\r\nmore\r\n.\r\n"
    assert message.gap is True


def test_body_start_is_no_line_start_after_missing_bytes():
    exchange = Exchange()
    exchange.start()
    message = exchange.client(b".\r\nrest\r\n.\r\n", seq=exchange.client_seq + 10)
    assert message.data == b".\r\nrest\r\n.\r\n"
    assert message.gap is True


@pytest.mark.parametrize("skip", [0, 10])
def test_body_start_is_no_line_start_after_an_earlier_empty_gap_segment(skip):
    exchange = Exchange()
    exchange.start()
    assert _short_segment(exchange, b"", exchange.client_seq + skip, 10) is None
    message = exchange.client(b".\r\nrest\r\n.\r\n")
    assert message.data == b".\r\nrest\r\n.\r\n"
    assert message.gap is True
