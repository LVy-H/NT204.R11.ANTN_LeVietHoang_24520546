from __future__ import annotations

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


CASES: dict[str, Callable[[], list[Frame]] | Callable[[], list[str]]] = {
    "T01-http-url-decode.pcap": t01_http_url_decode,
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
