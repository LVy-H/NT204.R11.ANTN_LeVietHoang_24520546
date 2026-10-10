from __future__ import annotations

from ids.issues import Issue
from ids.model import (
    ApplicationInfo,
    CaptureInfo,
    DecodedForm,
    DecodedHttp,
    DecodedMime,
    DecodedText,
    DecodedUri,
    DecodeStatus,
    Detection,
    Direction,
    DirectionStats,
    DnsCounts,
    DnsFlags,
    DnsMessage,
    DnsQuestion,
    DnsRecord,
    Endpoint,
    EndReason,
    FlowRecord,
    FlowRef,
    HttpBody,
    HttpHeader,
    HttpMessage,
    IpOption,
    Ipv4Flags,
    Ipv4Info,
    LinkInfo,
    MessageEvent,
    MimeHeaders,
    MimePart,
    Normalized,
    NormalizedDns,
    NormalizedHttp,
    NormalizedSmtp,
    PacketEvent,
    Payload,
    PreprocessStatus,
    ProcessingAction,
    SmtpCommand,
    SmtpReply,
    SmtpSession,
    TcpFlags,
    TcpFlowStats,
    TcpInfo,
    TcpOption,
    TcpState,
    UdpInfo,
    VlanTag,
)

TS = 1759000000.1
HTTP_BYTES = b"POST /login?next=%2Fhome HTTP/1.1\r\nHost: Example.COM\r\n\r\nuser=a+b&pw=%27x"


def capture(length: int) -> CaptureInfo:
    return CaptureInfo(
        source="pcap",
        origin="TEST/fixtures/x.pcap",
        linktype=1,
        linktype_name="EN10MB",
        captured_length=length,
        original_length=length,
        declared_capture_length=length,
        truncated_by_capture=False,
    )


def ethernet() -> LinkInfo:
    return LinkInfo(
        protocol="Ethernet",
        src_mac="02:00:00:00:00:01",
        dst_mac="02:00:00:00:00:02",
        ethertype=0x0800,
        ethertype_name="IPv4",
        vlan=[VlanTag(tpid="0x8100", pcp=5, dei=False, vid=42)],
    )


def ipv4(protocol_number: int, protocol_name: str) -> Ipv4Info:
    return Ipv4Info(
        protocol="IPv4",
        version=4,
        header_length=24,
        dscp=0,
        ecn=0,
        tos=0,
        total_length=120,
        identification=1,
        flags=Ipv4Flags(reserved=False, df=True, mf=False),
        fragment_offset=0,
        fragmented=False,
        ttl=64,
        protocol_number=protocol_number,
        protocol_name=protocol_name,
        header_checksum="0x1234",
        header_checksum_valid=True,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        options=[IpOption(type=1, name="NOP", length=1), IpOption(type=7, data="0409")],
        captured_truncated=False,
        declared_payload_length=96,
        captured_payload_length=96,
    )


def rich_http_event() -> PacketEvent:
    return PacketEvent(
        packet_id=7,
        timestamp=TS,
        capture=capture(134),
        link=ethernet(),
        network=ipv4(6, "TCP"),
        transport=TcpInfo(
            src_port=51234,
            dst_port=80,
            seq=1001,
            ack=1,
            header_length=32,
            reserved=0,
            flags=TcpFlags(psh=True, ack=True, syn=False, fin=False, rst=False),
            flags_list=["PSH", "ACK"],
            flags_string="PA",
            window=8192,
            checksum="0x54ac",
            checksum_valid=True,
            urgent_pointer=0,
            options=[
                TcpOption(type=2, name="MSS", length=4, mss=1460),
                TcpOption(type=5, name="SACK", length=10, blocks=[[1, 2], [3, 4]]),
                TcpOption(type=8, name="Timestamp", length=10, tsval=111, tsecr=0),
            ],
            payload_length=len(HTTP_BYTES),
        ),
        application=ApplicationInfo(
            protocol="HTTP",
            detection=Detection(
                protocol="HTTP",
                method="port+payload",
                confidence=1.0,
                port_matched=True,
                port_hint="HTTP",
                evidence="HTTP request line",
                scores={"HTTP": 1.0, "DNS": 0.0, "SMTP": 0.25},
            ),
            message=HttpMessage(
                kind="request",
                version="HTTP/1.1",
                start_line="POST /login?next=%2Fhome HTTP/1.1",
                method="POST",
                uri="/login?next=%2Fhome",
                headers=[HttpHeader("Host", "Example.COM")],
                body=HttpBody(
                    offset=58,
                    length=17,
                    declared_length=None,
                    transfer_encoding="identity",
                    truncated=False,
                ),
                complete=True,
            ),
        ),
        payload=Payload(
            length=len(HTTP_BYTES),
            sha256="ab" * 32,
            data=HTTP_BYTES,
            data_truncated=False,
            preview=HTTP_BYTES.decode(),
            preview_truncated=False,
            preview_encoding="utf-8",
            binary=False,
        ),
        decoded=DecodedHttp(
            uri=DecodedUri(
                text="/login?next=/home",
                path="/login",
                query="next=/home",
                params=[["next", "/home"]],
                status=DecodeStatus.DECODED,
                double_encoded=False,
            ),
            form=DecodedForm(params=[["user", "a b"], ["pw", "'x"]], status=DecodeStatus.DECODED),
            body=DecodedText(
                text="user=a+b&pw=%27x",
                charset="ascii",
                status=DecodeStatus.UNCHANGED,
                invalid_byte_count=0,
                truncated=False,
            ),
            status=DecodeStatus.DECODED,
        ),
        normalized=Normalized(
            timestamp=TS,
            timestamp_iso="2025-09-27T19:06:40.100000Z",
            network_protocol="IPv4",
            protocol="TCP",
            application_protocol="HTTP",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=51234,
            dst_port=80,
            http=NormalizedHttp(
                method="POST",
                scheme="http",
                host="example.com",
                port=80,
                path="/login",
                headers={"host": ["Example.COM"]},
            ),
        ),
        preprocess_status=PreprocessStatus.PARTIAL,
        processing_action=ProcessingAction.MARK,
        reason=["transport/truncated_packet"],
        flow=FlowRef(
            flow_id="0123456789abcdef",
            direction=Direction.FORWARD,
            state=TcpState.ESTABLISHED,
            flow_packet_index=4,
        ),
        issues=[
            Issue("transport", "truncated_packet", "short segment", {"needed": 20, "have": 12})
        ],
    )


def rich_dns_event() -> PacketEvent:
    return PacketEvent(
        packet_id=8,
        timestamp=TS + 1,
        capture=capture(90),
        link=ethernet(),
        network=ipv4(17, "UDP"),
        transport=UdpInfo(
            src_port=53,
            dst_port=40000,
            length=56,
            checksum="0x0000",
            checksum_valid=None,
            declared_payload_length=48,
            payload_length=48,
            captured_truncated=False,
        ),
        application=ApplicationInfo(
            protocol="DNS",
            detection=Detection(protocol="DNS", method="port", confidence=0.5),
            message=DnsMessage(
                kind="response",
                id=0x1234,
                flags=DnsFlags(qr=True, opcode=0, aa=False, tc=False, rd=True, ra=True, rcode=0),
                opcode=0,
                opcode_name="QUERY",
                rcode=0,
                rcode_name="NOERROR",
                counts=DnsCounts(questions=1, answers=2, authorities=0, additionals=1),
                questions=[DnsQuestion("Example.com", 1, "A", 1, "IN")],
                answers=[
                    DnsRecord("example.com", 1, "A", 1, "IN", 60, 4, "93.184.216.34"),
                    DnsRecord(
                        "example.com",
                        16,
                        "TXT",
                        1,
                        "IN",
                        60,
                        12,
                        ["v=spf1", "-all"],
                    ),
                ],
                additionals=[
                    DnsRecord(
                        name="",
                        type=41,
                        type_name="OPT",
                        rdlength=3,
                        value={"flags": 0, "note": "x"},
                        rdata="00ff01",
                        rdata_error=Issue("application", "decode_error", "bad", {"offset": 3}),
                        udp_payload_size=1232,
                    )
                ],
                tcp=False,
            ),
        ),
        payload=Payload(
            length=4,
            sha256="cd" * 32,
            data=b"\x12\x34\x81\x80",
            data_truncated=False,
            preview=".4..",
            preview_truncated=False,
            preview_encoding="binary",
            binary=True,
            preview_hex="12348180",
        ),
        normalized=Normalized(dns=NormalizedDns(names=["example.com"])),
        preprocess_status=PreprocessStatus.VALID,
        processing_action=ProcessingAction.FORWARD,
        flow=FlowRef(flow_id="fedcba9876543210", direction=Direction.BACKWARD, flow_packet_index=2),
    )


def rich_smtp_event() -> PacketEvent:
    return PacketEvent(
        packet_id=9,
        timestamp=TS + 2,
        network=ipv4(6, "TCP"),
        transport=TcpInfo(src_port=40000, dst_port=25),
        application=ApplicationInfo(
            protocol="SMTP",
            message=SmtpSession(
                kind="mixed",
                commands=[
                    SmtpCommand(verb="EHLO", arguments="client.example", domain="client.example"),
                    SmtpCommand(
                        verb="MAIL",
                        arguments="FROM:<a@example.com> SIZE=10",
                        address="a@example.com",
                        parameters=["SIZE=10"],
                        path="<a@example.com>",
                    ),
                    SmtpCommand(verb="AUTH", mechanism="PLAIN", credentials_present=True),
                ],
                replies=[
                    SmtpReply(
                        code=250, text="ok", lines=["250-hello", "250 ok"], continuation=False
                    )
                ],
                unparsed_lines=["???"],
                command="EHLO",
                status_code=250,
                last_status_code=250,
                mail_from="a@example.com",
                rcpt_to=["b@example.com"],
            ),
        ),
        decoded=mime(),
        normalized=Normalized(
            smtp=NormalizedSmtp(
                helo="client.example", mail_from="a@example.com", rcpt_to=["b@example.com"]
            )
        ),
    )


def mime() -> DecodedMime:
    return DecodedMime(
        headers=MimeHeaders(
            subject="Chào",
            from_="a@example.com",
            to="b@example.com",
            cc=None,
            date="Sat, 27 Sep 2025 19:06:40 +0000",
            message_id="<1@example.com>",
        ),
        parts=[
            MimePart(
                index=0,
                content_type="text/plain",
                charset="utf-8",
                transfer_encoding="base64",
                size=5,
                sha256="ef" * 32,
                text="Chào",
                status=DecodeStatus.DECODED,
                truncated=False,
            )
        ],
        status=DecodeStatus.DECODED,
    )


def message_event() -> MessageEvent:
    return MessageEvent(
        message_id="0123456789abcdef-1",
        flow_id="0123456789abcdef",
        protocol="SMTP",
        packet_ids=[5, 6],
        start_time=TS,
        end_time=TS + 1,
        data=b"Subject: hi\r\n\r\nbody\r\n.\r\n",
        complete=True,
        truncated=False,
        gap=False,
        decoded=mime(),
        preprocess_status=PreprocessStatus.VALID,
        processing_action=ProcessingAction.FORWARD,
        reason=[],
        issues=[Issue("decoder", "invalid_base64", "bad pad", {"part": 0})],
    )


def flow_record() -> FlowRecord:
    return FlowRecord(
        flow_id="0123456789abcdef",
        protocol="TCP",
        application_protocol="HTTP",
        endpoint_a=Endpoint("10.0.0.1", 51234),
        endpoint_b=Endpoint("10.0.0.2", 80),
        start_time=TS,
        last_seen=TS + 2.5,
        duration=2.5,
        packet_count=5,
        byte_count=400,
        payload_byte_count=120,
        forward=DirectionStats(3, 250, 100),
        backward=DirectionStats(2, 150, 20),
        tcp=TcpFlowStats(
            state=TcpState.CLOSED,
            syn_count=2,
            ack_count=4,
            fin_count=2,
            rst_count=0,
            handshake_complete=True,
            midstream=False,
        ),
        end_reason=EndReason.CLOSED,
        first_packet_id=1,
        last_packet_id=5,
    )
