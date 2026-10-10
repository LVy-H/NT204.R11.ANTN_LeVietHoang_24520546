import pytest

from ids.issues import Issues
from ids.parsers.registry import PROTOCOLS, STANDARD_PORTS, by_name


def test_protocol_order_is_http_dns_smtp():
    assert [protocol.name for protocol in PROTOCOLS] == ["HTTP", "DNS", "SMTP"]


def test_standard_ports_cover_every_protocol_port_once():
    assert sum(len(protocol.ports) for protocol in PROTOCOLS) == len(STANDARD_PORTS)
    assert set(STANDARD_PORTS.values()) == {"HTTP", "DNS", "SMTP"}


@pytest.mark.parametrize(
    "port,name",
    [
        (80, "HTTP"),
        (8080, "HTTP"),
        (3128, "HTTP"),
        (53, "DNS"),
        (5353, "DNS"),
        (25, "SMTP"),
        (587, "SMTP"),
    ],
)
def test_well_known_ports(port, name):
    assert STANDARD_PORTS[port] == name


def test_by_name_returns_a_protocol_that_parses_its_payload():
    smtp = by_name("SMTP")
    assert smtp is not None
    session = smtp.parse(b"EHLO client.test\r\n", tcp=True, issues=Issues("application"))
    assert session.kind == "command"
    assert smtp.score(b"EHLO client.test\r\n", True)[0] == 0.95


@pytest.mark.parametrize("name", ["FTP", "http", "", "UNKNOWN"])
def test_by_name_rejects_unknown_names(name):
    assert by_name(name) is None
