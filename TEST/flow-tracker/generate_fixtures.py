from __future__ import annotations

import base64
import json
import struct
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from scapy.all import DNS, DNSQR, DNSRR, IP, TCP, UDP, Ether, Raw

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "TEST" / "flow-tracker" / "fixtures"

LINKTYPE_ETHERNET = 1
BASE_TIME = 1759000000
SNAPLEN = 262144

CLIENT = "10.0.0.1"
SERVER = "10.0.0.2"
CLIENT2 = "10.0.0.3"
MACS = {
    CLIENT: "02:00:00:00:00:01",
    SERVER: "02:00:00:00:00:02",
    CLIENT2: "02:00:00:00:00:03",
}

CLIENT_PORT = 51234
HTTP_PORT = 80
SMTP_PORT = 25
DNS_PORT = 53
APP_PORT = 9000


@dataclass(frozen=True, slots=True)
class Frame:
    offset_ms: int  # milliseconds after BASE_TIME
    data: bytes


def frame(offset_ms: int, packet) -> Frame:
    """Ethernet frame around an IP packet; the MACs follow the IP addresses."""
    ether = Ether(src=MACS[packet[IP].src], dst=MACS[packet[IP].dst])
    return Frame(offset_ms, bytes(ether / packet))


def udp(offset_ms: int, src: str, sport: int, dst: str, dport: int, payload) -> Frame:
    return frame(offset_ms, IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / payload)


class TcpConversation:
    """One TCP connection; sequence and acknowledgement numbers stay consistent."""

    def __init__(
        self,
        client: str = CLIENT,
        client_port: int = CLIENT_PORT,
        server: str = SERVER,
        server_port: int = APP_PORT,
        *,
        client_isn: int = 1000,
        server_isn: int = 5000,
    ) -> None:
        self.hosts = {"client": (client, client_port), "server": (server, server_port)}
        self.next_seq = {"client": client_isn, "server": server_isn}

    def client(self, offset_ms: int, flags: str, payload: bytes = b"") -> Frame:
        return self._send("client", "server", offset_ms, flags, payload)

    def server(self, offset_ms: int, flags: str, payload: bytes = b"") -> Frame:
        return self._send("server", "client", offset_ms, flags, payload)

    def _send(self, me: str, peer: str, offset_ms: int, flags: str, payload: bytes) -> Frame:
        (src, sport), (dst, dport) = self.hosts[me], self.hosts[peer]
        seq = self.next_seq[me]
        ack = self.next_seq[peer] if "A" in flags else 0
        segment = TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack)
        if payload:
            segment = segment / Raw(payload)
        self.next_seq[me] = seq + len(payload) + ("S" in flags) + ("F" in flags)
        return frame(offset_ms, IP(src=src, dst=dst) / segment)


def event(**fields: object) -> str:
    """One JSONL event line; keys keep the order given."""
    return json.dumps(fields, ensure_ascii=False, separators=(",", ":"))


def pcap_bytes(frames: list[Frame]) -> bytes:
    chunks = [struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, SNAPLEN, LINKTYPE_ETHERNET)]
    for item in frames:
        seconds, millis = divmod(item.offset_ms, 1000)
        length = len(item.data)
        chunks.append(struct.pack("<IIII", BASE_TIME + seconds, millis * 1000, length, length))
        chunks.append(item.data)
    return b"".join(chunks)


def jsonl_bytes(lines: list[str]) -> bytes:
    return "".join(line + "\n" for line in lines).encode("utf-8")


def t01_http_url_decode() -> list[Frame]:
    conn = TcpConversation(server_port=HTTP_PORT)
    request = b"GET /search%20page?q=%27%20OR%201%3D1&x=a+b HTTP/1.1\r\nHost: example.com\r\n\r\n"
    return [conn.client(0, "PA", request)]


def http_response(body: bytes, content_type: str) -> bytes:
    return (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: " + content_type.encode() + b"\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"\r\n" + body
    )


def t02_html_entities() -> list[Frame]:
    conn = TcpConversation(server_port=HTTP_PORT)
    body = b"&lt;script&gt;alert(1)&lt;/script&gt; &amp; &#x27; &bogus;"
    return [conn.server(0, "PA", http_response(body, "text/html"))]


T03_SUBJECT = "Báo cáo tuần"
T03_BASE64_TEXT = "Xin chào, đây là phần Base64."
T03_QP_BODY = b"Caf=C3=A9 =3D 3 euro, soft=\r\nbreak."
T03_SINGLE = (
    b"From: Alice <alice@example.test>\r\n"
    b"To: Bob <bob@example.test>\r\n"
    b"Subject: single segment\r\n"
    b"MIME-Version: 1.0\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n"
    b"Content-Transfer-Encoding: quoted-printable\r\n"
    b"\r\n"
    b"Gi=E1=BB=9D h=E1=BB=8Dp l=C3=BAc 9h.\r\n"
    b"..dot-stuffed line\r\n"
    b".\r\n"
)


def t03_multipart_message() -> bytes:
    """DATA content of the first message, terminator included."""
    subject = base64.b64encode(T03_SUBJECT.encode()).decode()
    text = base64.b64encode(T03_BASE64_TEXT.encode()).decode()
    head = (
        "From: Alice <alice@example.test>\r\n"
        "To: Bob <bob@example.test>\r\n"
        f"Subject: =?UTF-8?B?{subject}?=\r\n"
        "MIME-Version: 1.0\r\n"
        'Content-Type: multipart/mixed; boundary="b1"\r\n'
        "\r\n"
        "--b1\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "Content-Transfer-Encoding: base64\r\n"
        "\r\n"
        f"{text}\r\n"
        "--b1\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "Content-Transfer-Encoding: quoted-printable\r\n"
        "\r\n"
    )
    return head.encode() + T03_QP_BODY + b"\r\n--b1--\r\n.\r\n"


def t03_smtp_mime() -> list[Frame]:
    conn = TcpConversation(server_port=SMTP_PORT)
    message = t03_multipart_message()
    split = message.rindex(b"--b1\r\n")  # second segment starts at the second part
    return [
        conn.client(0, "S"),
        conn.server(10, "SA"),
        conn.client(20, "A"),
        conn.server(30, "PA", b"220 mail.example.test ESMTP\r\n"),
        conn.client(40, "PA", b"EHLO client.example.test\r\n"),
        conn.server(50, "PA", b"250 mail.example.test\r\n"),
        conn.client(60, "PA", b"MAIL FROM:<alice@example.test>\r\n"),
        conn.server(70, "PA", b"250 2.1.0 Ok\r\n"),
        conn.client(80, "PA", b"RCPT TO:<bob@example.test>\r\n"),
        conn.server(90, "PA", b"250 2.1.5 Ok\r\n"),
        conn.client(100, "PA", b"DATA\r\n"),
        conn.server(110, "PA", b"354 End data with <CR><LF>.<CR><LF>\r\n"),
        conn.client(120, "PA", message[:split]),
        conn.client(130, "PA", message[split:]),
        conn.server(140, "PA", b"250 2.0.0 Ok: queued as A1\r\n"),
        conn.client(150, "PA", b"DATA\r\n"),
        conn.server(160, "PA", b"354 End data with <CR><LF>.<CR><LF>\r\n"),
        conn.client(170, "PA", T03_SINGLE),
        conn.server(180, "PA", b"250 2.0.0 Ok: queued as A2\r\n"),
        conn.client(190, "PA", b"QUIT\r\n"),
        conn.server(200, "PA", b"221 2.0.0 Bye\r\n"),
    ]


def t04_invalid_charset() -> list[Frame]:
    conn = TcpConversation(server_port=HTTP_PORT)
    broken = http_response(b"ok \xff\xfe bad \xe2\x82", "text/plain; charset=utf-8")
    valid = http_response("chào".encode(), "text/plain; charset=utf-8")
    return [conn.server(0, "PA", broken), conn.server(10, "PA", valid)]


T05_URI = "/Docs/./a/../B//index.html"
T05_HOST = "WWW.Example.COM:8080"


def t05_normalize_pcap() -> list[Frame]:
    conn = TcpConversation(server_port=HTTP_PORT)
    request = (
        f"GET {T05_URI} HTTP/1.1\r\n"
        f"HOST: {T05_HOST}\r\n"
        "User-AGENT: Mixed/1.0\r\n"
        "ACCEPT: */*\r\n"
        "\r\n"
    ).encode()
    query = DNS(id=0x1234, rd=1, qd=DNSQR(qname="WwW.ExAmple.CoM", qtype="A"))
    return [
        conn.client(500, "PA", request),
        udp(1000, CLIENT, 40000, SERVER, DNS_PORT, query),
    ]


def t05_http_event(
    packet_id: int,
    timestamp: float | str,
    src_ip: str,
    dst_ip: str,
    protocol: str,
    names: tuple[str, str, str],
) -> str:
    """The pcap's HTTP request as a loaded event, spelled differently each time."""
    values = (T05_HOST, "Mixed/1.0", "*/*")
    return event(
        schema_version=2,
        record_type="packet",
        packet_id=packet_id,
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        src_port=CLIENT_PORT,
        dst_port=HTTP_PORT,
        application={
            "protocol": "HTTP",
            "message": {
                "protocol": "HTTP",
                "kind": "request",
                "version": "HTTP/1.1",
                "start_line": f"GET {T05_URI} HTTP/1.1",
                "method": "GET",
                "uri": T05_URI,
                "headers": [
                    {"name": name, "value": value}
                    for name, value in zip(names, values, strict=True)
                ],
                "complete": True,
            },
        },
    )


def t05_normalize_events() -> list[str]:
    return [
        t05_http_event(
            1, 1759000000.5, "10.0.0.1", "10.0.0.2", "TCP", ("HOST", "User-AGENT", "ACCEPT")
        ),
        t05_http_event(
            2,
            "2025-09-27T19:06:40.500Z",
            "010.000.000.001",
            "010.000.000.002",
            "tcp",
            ("host", "user-agent", "accept"),
        ),
        t05_http_event(
            3, 1759000000500, " 10.0.0.1 ", "10.0.0.2", "Tcp", ("Host", "USER-AGENT", "Accept")
        ),
        event(
            schema_version=2,
            record_type="packet",
            packet_id=4,
            timestamp="2025-09-27T19:06:41+00:00",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            protocol="UDP",
            src_port=40000,
            dst_port=DNS_PORT,
            application={
                "protocol": "DNS",
                "message": {
                    "protocol": "DNS",
                    "kind": "query",
                    "id": 0x1234,
                    "questions": [
                        {
                            "name": "WWW.EXAMPLE.COM.",
                            "type": 1,
                            "type_name": "A",
                            "class": 1,
                            "class_name": "IN",
                        }
                    ],
                },
            },
        ),
    ]


def t06_missing_fields() -> list[str]:
    return [
        event(
            packet_id=1,
            timestamp=1759000000.0,
            src_ip=CLIENT,
            dst_ip=SERVER,
            protocol="TCP",
            src_port=CLIENT_PORT,
            dst_port=APP_PORT,
        ),
        event(
            packet_id=2,
            timestamp=1759000001.0,
            network={
                "protocol": "IPv4",
                "src_ip": CLIENT,
                "dst_ip": SERVER,
                "protocol_name": "UDP",
            },
            transport={"protocol": "UDP", "src_port": 40000, "dst_port": 5000},
        ),
        event(
            packet_id=3,
            timestamp=1759000002.0,
            src_ip=CLIENT,
            dst_ip=SERVER,
            protocol="TCP",
            src_port=51240,
            dst_port=HTTP_PORT,
            application={
                "protocol": "HTTP",
                "message": {"protocol": "HTTP", "kind": "request", "method": "GET", "uri": "/"},
            },
        ),
    ]


def t07_tcp_handshake() -> list[Frame]:
    conn = TcpConversation()
    return [conn.client(0, "S"), conn.server(10, "SA"), conn.client(20, "A")]


def t08_tcp_bidirectional() -> list[Frame]:
    conn = TcpConversation()
    return [
        conn.client(0, "S"),
        conn.server(10, "SA"),
        conn.client(20, "A"),
        conn.client(30, "PA", b"hello server\n"),
        conn.server(40, "A"),
        conn.server(50, "PA", b"hello client, here is a longer reply\n"),
        conn.client(60, "A"),
    ]


def t09_tcp_close_reset() -> list[Frame]:
    graceful = TcpConversation()
    aborted = TcpConversation(client_port=CLIENT_PORT + 1, client_isn=2000, server_isn=7000)
    reused = TcpConversation(client_isn=4000, server_isn=6000)
    return [
        graceful.client(0, "S"),
        graceful.server(10, "SA"),
        graceful.client(20, "A"),
        graceful.client(30, "PA", b"bye\n"),
        graceful.client(40, "FA"),
        graceful.server(50, "A"),
        graceful.server(60, "FA"),
        graceful.client(70, "A"),
        aborted.client(1000, "S"),
        aborted.server(1010, "SA"),
        aborted.client(1020, "A"),
        aborted.client(1030, "R"),
        reused.client(2000, "S"),
        reused.server(2010, "SA"),
        reused.client(2020, "A"),
    ]


def t10_udp_dns_flow() -> list[Frame]:
    question = DNSQR(qname="example.com", qtype="A")
    answer = DNSRR(rrname="example.com", type="A", ttl=300, rdata="93.184.216.34")
    response = DNS(id=0x2001, qr=1, rd=1, ra=1, qd=question, an=answer)
    return [
        udp(0, CLIENT, 40000, SERVER, DNS_PORT, DNS(id=0x2001, rd=1, qd=question)),
        udp(20, SERVER, DNS_PORT, CLIENT, 40000, response),
    ]


CASES: dict[str, Callable[[], list[Frame]] | Callable[[], list[str]]] = {
    "T01-http-url-decode.pcap": t01_http_url_decode,
    "T02-html-entities.pcap": t02_html_entities,
    "T03-smtp-mime.pcap": t03_smtp_mime,
    "T04-invalid-charset.pcap": t04_invalid_charset,
    "T05-normalize-pcap.pcap": t05_normalize_pcap,
    "T05-normalize-events.jsonl": t05_normalize_events,
    "T06-missing-fields.jsonl": t06_missing_fields,
    "T07-tcp-handshake.pcap": t07_tcp_handshake,
    "T08-tcp-bidirectional.pcap": t08_tcp_bidirectional,
    "T09-tcp-close-reset.pcap": t09_tcp_close_reset,
    "T10-udp-dns-flow.pcap": t10_udp_dns_flow,
}


def build(name: str) -> bytes:
    """Exact bytes of one fixture file."""
    items = CASES[name]()
    return jsonl_bytes(items) if name.endswith(".jsonl") else pcap_bytes(items)


def main() -> int:
    FIXTURES.mkdir(parents=True, exist_ok=True)
    for name in CASES:
        path = FIXTURES / name
        path.write_bytes(build(name))
        print(f"{path.relative_to(ROOT)}  bytes={path.stat().st_size}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
