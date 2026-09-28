CLIENT_MAC = "02:00:00:00:00:01"
SERVER_MAC = "02:00:00:00:00:02"
SRC = "10.0.0.1"
DST = "10.0.0.2"

TCP_SYN_OPTIONS = bytes.fromhex(
    "0200000000020200000000010800"
    "4500004010920000400656240a0000010a000002"
    "c8220050000003e800000000b0022000bfa60000"
    "020405b404020303070101080a0000006f00000000"
    "00000000"
)

TCP_DATA = bytes.fromhex(
    "0200000000020200000000010800"
    "4500003a00010000400666bb0a0000010a000002"
    "c8220050000003e90000138950182000bd320000"
    "474554202f20485454502f312e310d0a0d0a"
)

TCP_FIN = bytes.fromhex(
    "0200000000020200000000010800"
    "4500002800010000400666cd0a0000010a000002"
    "c8220050000007d00000000150192000ab850000"
)

UDP = bytes.fromhex(
    "0200000000020200000000010800"
    "4500002500010000401166c50a0000010a000002"
    "9c400035001160f4"
    "7061796c6f61643031"
)

VLAN = bytes.fromhex(
    "0200000000020200000000018100"
    "a02a"
    "0800"
    "4500002800010000400666cd0a0000010a000002"
    "000100020000000000000000500220007bdd0000"
)

IPV4_OPTIONS = bytes.fromhex(
    "0200000000020200000000010800"
    "470000300001000040064aa8"
    "0a0000010a000002"
    "0107070409090909"
    "000100020000000000000000500220007bdd0000"
)

IPV4_MF = bytes.fromhex(
    "0200000000020200000000010800"
    "4500003000012000400646c50a0000010a000002"
    "00010002000000000000000050022000ab000000"
    "3132333435363738"
)

ICMP = bytes.fromhex(
    "02000000000202000000000108004500001c00010000400166de0a0000010a0000020800f7ff00010001"
)

IPV6 = bytes.fromhex(
    "02000000000202000000000186dd"
    "6000000000003a4020010db8000000000000000000000001"
    "20010db9000000000000000000000002"
)

HTTP_GET = (
    b"GET /index.html?q=ids&page=1 HTTP/1.1\r\n"
    b"Host: example.com\r\n"
    b"User-Agent: test/1.0\r\n"
    b"Accept: */*\r\n\r\n"
)

HTTP_POST = (
    b"POST /login HTTP/1.1\r\n"
    b"Host: example.com\r\n"
    b"Content-Type: application/x-www-form-urlencoded\r\n"
    b"Content-Length: 34\r\n"
    b"\r\n"
    b"username=alice&password=s3cr3t&on=1"
)

HTTP_RESPONSE = (
    b"HTTP/1.1 301 Moved Permanently\r\n"
    b"Server: nginx/1.24.0\r\n"
    b"Location: https://example.com/\r\n"
    b"Content-Length: 2\r\n\r\nok"
)


def dns_name(name: str) -> bytes:
    return b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\x00"


DNS_QUERY = (
    bytes.fromhex("12340100")
    + bytes.fromhex("0001")
    + bytes.fromhex("0000") * 3
    + dns_name("example.com")
    + bytes.fromhex("0001")
    + bytes.fromhex("0001")
)

DNS_ANSWER = (
    bytes.fromhex("12348180")
    + bytes.fromhex("0001")
    + bytes.fromhex("0001")
    + bytes.fromhex("0000") * 2
    + dns_name("example.com")
    + bytes.fromhex("0001")
    + bytes.fromhex("0001")
    + b"\xc0\x0c"
    + bytes.fromhex("0001")
    + bytes.fromhex("0001")
    + bytes.fromhex("0000012c")
    + bytes.fromhex("0004")
    + bytes.fromhex("5db8d822")
)

DNS_POINTER_LOOP = (
    bytes.fromhex("12340100")
    + bytes.fromhex("0001")
    + bytes.fromhex("0000") * 3
    + b"\xc0\x0c"
    + bytes.fromhex("0001")
    + bytes.fromhex("0001")
)

SMTP_EHLO = b"EHLO client.example.test\r\n"
SMTP_MAIL_FROM = b"MAIL FROM:<alice@example.test> SIZE=1024\r\n"
SMTP_RCPT_TO = b"RCPT TO:<bob@example.test>\r\n"
SMTP_MULTILINE = (
    b"250-mail.example.test\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250 AUTH LOGIN PLAIN\r\n"
)
SMTP_GREETING = b"220 mail.example.test ESMTP Postfix\r\n"
SMTP_REJECT = b"550 5.1.1 <bob@example.test>: Recipient address rejected\r\n"
