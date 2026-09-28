from __future__ import annotations

import struct
from ipaddress import IPv4Address
from pathlib import Path

from scapy.all import DNS, DNSQR, DNSRR, Ether, IP, TCP, UDP, Raw, wrpcapng

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "TEST" / "fixtures"

LINKTYPE_ETHERNET = 1
BASE_TIME = 1759000000
SNAPLEN = 262144

CLIENT_MAC = "02:00:00:00:00:01"
SERVER_MAC = "02:00:00:00:00:02"
OTHER_MAC = "02:00:00:00:00:03"
CLIENT = "10.0.0.1"
SERVER = "10.0.0.2"

CLIENT_PORT = 51234
SERVER_PORT = 80
SMTP_PORT = 25
DNS_PORT = 53

NOISE = bytes.fromhex(
    "deadbeefcafebabe00112233445566778899aabbccddeeff0102030405060708"
    "a1a2a3a4a5a6a7a8b1b2b3b4b5b6b7b8c1c2c3c4c5c6c7c8"
)

ETH_TO_SERVER = bytes.fromhex("0200000000020200000000010800")


def server_frame(layers):
    return bytes(Ether(src=SERVER_MAC, dst=CLIENT_MAC) / layers)


def client_frame(layers):
    return bytes(Ether(src=CLIENT_MAC, dst=SERVER_MAC) / layers)


def tcp(**kwargs):
    defaults = {"sport": CLIENT_PORT, "dport": SERVER_PORT, "flags": "A", "seq": 1, "ack": 1}
    return TCP(**{**defaults, **kwargs})


def ip(layers, src=CLIENT, dst=SERVER, **kwargs):
    return IP(src=src, dst=dst, **kwargs) / layers


def ename(name: str) -> bytes:
    return b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\x00"


def ipv4_header(total_length, protocol, *, src=CLIENT, dst=SERVER, ihl=5, ttl=64, flags_fragment=0):
    return struct.pack(
        "!BBHHHBBH4s4s",
        0x40 | ihl,
        0,
        total_length,
        1,
        flags_fragment,
        ttl,
        protocol,
        0,
        IPv4Address(src).packed,
        IPv4Address(dst).packed,
    )


def tcp_header(*, data_offset=5, flags=0x18, payload=b""):
    return (
        struct.pack("!HHIIHHHH", CLIENT_PORT, SERVER_PORT, 1000, 0, (data_offset << 12) | flags, 8192, 0, 0)
        + payload
    )


def write_pcap(path: Path, records, linktype=LINKTYPE_ETHERNET, snaplen=SNAPLEN) -> None:
    with open(path, "wb") as handle:
        handle.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, linktype))
        for index, record in enumerate(records):
            data, declared = record if isinstance(record, tuple) else (record, None)
            captured = len(data) if declared is None else declared
            handle.write(struct.pack("<IIII", BASE_TIME + index, 100000 + index * 7919, captured, captured))
            handle.write(data)


def tcp_handshake():
    return [
        client_frame(ip(tcp(flags="S", seq=1000, ack=0))),
        server_frame(ip(tcp(sport=SERVER_PORT, dport=CLIENT_PORT, flags="SA", seq=5000, ack=1001),
                          src=SERVER, dst=CLIENT)),
        client_frame(ip(tcp(flags="A", seq=1001, ack=5001))),
    ]


def tcp_data():
    return [
        client_frame(ip(tcp(flags="PA", seq=1001, ack=5001) / Raw(b"PAYLOAD-01: tcp data segment\n"))),
        server_frame(ip(tcp(sport=SERVER_PORT, dport=CLIENT_PORT, flags="PA", seq=5001, ack=1030)
                          / Raw(bytes(range(32))), src=SERVER, dst=CLIENT)),
    ]


def udp_traffic():
    return [
        client_frame(ip(UDP(sport=40000, dport=40001) / Raw(b"udp payload one"))),
        server_frame(ip(UDP(sport=40001, dport=40000) / Raw(bytes(range(64))), src=SERVER, dst=CLIENT)),
        client_frame(ip(UDP(sport=40002, dport=40003))),
    ]


def http_get():
    request = (
        b"GET /index.html?q=ids&page=1 HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"User-Agent: pcparser-test/1.0\r\n"
        b"Accept: text/html,application/xhtml+xml\r\n"
        b"Cookie: session=abc123; theme=dark\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )
    return [
        client_frame(ip(tcp(flags="S", seq=1000, ack=0))),
        client_frame(ip(tcp(flags="PA", seq=1001, ack=1) / Raw(request))),
    ]


def http_post():
    body = b"username=alice&password=s3cr3t&remember=on"
    request = (
        b"POST /login HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"Cookie: session=abc123\r\n"
        b"\r\n" + body
    )
    return [client_frame(ip(tcp(flags="PA", seq=1001, ack=1) / Raw(request)))]


def http_response():
    body = b"<!doctype html><title>ok</title>"
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Server: nginx/1.24.0\r\n"
        b"Date: Sun, 28 Sep 2026 20:00:00 GMT\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"Set-Cookie: session=xyz789; HttpOnly\r\n"
        b"\r\n" + body
    )
    missing = b"HTTP/1.1 404 Not Found\r\nServer: nginx/1.24.0\r\nContent-Length: 0\r\n\r\n"
    return [
        server_frame(ip(tcp(sport=SERVER_PORT, dport=CLIENT_PORT, flags="PA", seq=5001, ack=1001)
                        / Raw(response), src=SERVER, dst=CLIENT)),
        server_frame(ip(tcp(sport=SERVER_PORT, dport=CLIENT_PORT, flags="PA",
                            seq=5001 + len(response), ack=1001) / Raw(missing), src=SERVER, dst=CLIENT)),
    ]


def dns_query():
    return [
        client_frame(ip(UDP(sport=40000, dport=DNS_PORT)
                        / DNS(id=0x1234, rd=1, qd=DNSQR(qname="example.com", qtype="A")))),
        client_frame(ip(UDP(sport=40000, dport=DNS_PORT)
                        / DNS(id=0x1235, rd=1, qd=DNSQR(qname="mail.example.com", qtype="MX")))),
        client_frame(ip(UDP(sport=40000, dport=DNS_PORT)
                        / DNS(id=0x1236, rd=1, qd=DNSQR(qname="1.1.168.192.in-addr.arpa", qtype="PTR")))),
    ]


def dns_response():
    return [
        server_frame(ip(UDP(sport=DNS_PORT, dport=40000)
                        / DNS(id=0x1234, qr=1, aa=1, rd=1, ra=1,
                              qd=DNSQR(qname="www.example.com", qtype="A"),
                              an=[DNSRR(rrname="www.example.com", type="CNAME", ttl=300,
                                        rdata=ename("example.com")),
                                  DNSRR(rrname="example.com", type="A", ttl=300,
                                        rdata="93.184.216.34")]),
                        src=SERVER, dst=CLIENT)),
        server_frame(ip(UDP(sport=DNS_PORT, dport=40000)
                        / DNS(id=0x1237, qr=1, aa=1, rd=1, ra=1, rcode=3,
                              qd=DNSQR(qname="does-not-exist.example.com", qtype="A")),
                        src=SERVER, dst=CLIENT)),
    ]


def smtp_command():
    return [
        client_frame(ip(tcp(flags="PA", seq=1001, ack=1) / Raw(b"EHLO client.example.test\r\n"))),
        client_frame(ip(tcp(flags="PA", seq=1029, ack=1) / Raw(b"MAIL FROM:<alice@example.test> SIZE=1024\r\n"))),
        client_frame(ip(tcp(flags="PA", seq=1071, ack=1) / Raw(b"RCPT TO:<bob@example.test>\r\n"))),
        client_frame(ip(tcp(flags="PA", seq=1098, ack=1) / Raw(b"DATA\r\n"))),
    ]


def smtp_response():
    replies = [
        b"220 mail.example.test ESMTP Postfix\r\n",
        b"250-mail.example.test\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250 AUTH LOGIN PLAIN\r\n",
        b"354 End data with <CR><LF>.<CR><LF>\r\n",
        b"550 5.1.1 <bob@example.test>: Recipient address rejected\r\n",
    ]
    records = []
    seq = 5001
    for reply in replies:
        records.append(
            server_frame(ip(tcp(sport=SMTP_PORT, dport=CLIENT_PORT, flags="PA", seq=seq, ack=1001)
                            / Raw(reply), src=SERVER, dst=CLIENT))
        )
        seq += len(reply)
    return records


def unknown_protocol():
    return [
        client_frame(ip(tcp(sport=40000, dport=9999) / Raw(NOISE))),
        server_frame(ip(tcp(sport=9999, dport=40000) / Raw(NOISE[:12]), src=SERVER, dst=CLIENT)),
        client_frame(ip(UDP(sport=40000, dport=4444) / Raw(NOISE))),
        client_frame(ip(IP(src=CLIENT, dst=SERVER, proto=1) / Raw(b"\x08\x00\x00\x00\x00\x01\x00\x01"))),
        bytes(Ether(src=CLIENT_MAC, dst=OTHER_MAC, type=0x1234) / Raw(NOISE)),
        bytes(Ether(src=CLIENT_MAC, dst=OTHER_MAC, type=0x0806) / Raw(b"\x00" * 28)),
    ]


def malformed():
    ipv6 = bytes.fromhex("6000000000003a40" + "20010db8" + "00000000" + "00000000" + "00000001"
                         + "20010db9" + "00000000" + "00000000" + "00000002")
    dns_pointer_loop = bytes.fromhex("123401000001000000000000") + b"\xc0\x0c" + bytes.fromhex("00010001")
    oversized_body = b"POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5000\r\n\r\nabc"
    stored = client_frame(ip(tcp(flags="PA", seq=1001, ack=1) / Raw(b"declared 200 bytes, only 24 stored")))
    return [
        b"\x02\x00\x00\x00\x00\x02",
        ETH_TO_SERVER + ipv4_header(40, 6, ihl=0) + tcp_header(),
        ETH_TO_SERVER + ipv4_header(60, 6) + tcp_header(),
        ETH_TO_SERVER + ipv4_header(40, 6) + tcp_header(data_offset=4),
        ETH_TO_SERVER + ipv4_header(30, 6) + tcp_header()[:10],
        ETH_TO_SERVER + ipv4_header(28, 17) + struct.pack("!HHHH", 40000, 40000, 4, 0),
        ETH_TO_SERVER + ipv4_header(56, 17) + struct.pack("!HHHH", 40000, 40000, 100, 0) + b"only12bytes",
        ETH_TO_SERVER + ipv4_header(40, 6, ihl=8)[:24],
        ETH_TO_SERVER + ipv6,
        ETH_TO_SERVER + ipv4_header(10, 6) + tcp_header(),
        client_frame(ip(UDP(sport=40000, dport=DNS_PORT) / Raw(dns_pointer_loop))),
        client_frame(ip(UDP(sport=40000, dport=DNS_PORT) / Raw(b"\x12\x34\x01"))),
        client_frame(ip(tcp(flags="PA", seq=1001, ack=1) / Raw(oversized_body))),
        (stored[:24], 200),
        b"",
    ]


def build_all() -> dict[str, list]:
    return {
        "01-tcp-handshake": tcp_handshake(),
        "02-tcp-data": tcp_data(),
        "03-udp": udp_traffic(),
        "04-http-get": http_get(),
        "05-http-post": http_post(),
        "06-http-response": http_response(),
        "07-dns-query": dns_query(),
        "08-dns-response": dns_response(),
        "09-smtp-command": smtp_command(),
        "10-smtp-response": smtp_response(),
        "11-unknown-protocol": unknown_protocol(),
        "12-malformed": malformed(),
    }


def main() -> int:
    FIXTURES.mkdir(parents=True, exist_ok=True)
    cases = build_all()
    for name, records in cases.items():
        path = FIXTURES / f"{name}.pcap"
        write_pcap(path, records)
        print(f"{path.relative_to(ROOT)}  records={len(records)}  bytes={path.stat().st_size}")

    pcapng = FIXTURES / "13-mixed.pcapng"
    packets = []
    for name in ("01-tcp-handshake", "04-http-get", "07-dns-query", "09-smtp-command"):
        for index, raw in enumerate(cases[name]):
            packet = Ether(raw)
            packet.time = BASE_TIME + index
            packets.append(packet)
    wrpcapng(str(pcapng), packets)
    print(f"{pcapng.relative_to(ROOT)}  records={len(packets)}  bytes={pcapng.stat().st_size}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
