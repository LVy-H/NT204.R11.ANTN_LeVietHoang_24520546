from __future__ import annotations

import base64
import json
import struct
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from scapy.all import IP, TCP, UDP, Ether, Raw

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


CASES: dict[str, Callable[[], list[Frame]] | Callable[[], list[str]]] = {
    "T01-http-url-decode.pcap": t01_http_url_decode,
    "T02-html-entities.pcap": t02_html_entities,
    "T03-smtp-mime.pcap": t03_smtp_mime,
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
