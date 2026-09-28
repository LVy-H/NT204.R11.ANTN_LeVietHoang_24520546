import time
from types import SimpleNamespace

import pytest

from pcparser.capture import live
from pcparser.capture.live import PERMISSION_HINT, LiveCapture, list_interfaces

FRAME_A = bytes.fromhex("0200000000020200000000010800") + b"\x45" + b"\x00" * 41
FRAME_B = bytes.fromhex("0200000000020200000000010800") + b"\x45" + b"\x01" * 41


class FakePacket:
    def __init__(self, raw, timestamp):
        self.raw = raw
        self.time = timestamp

    def __bytes__(self):
        return self.raw


class FakeSocket:
    def __init__(self, packets):
        self.packets = list(packets)
        self.closed = False

    def select(self, sockets, timeout):
        time.sleep(0.01)
        return [self] if self.packets else []

    def recv(self):
        return self.packets.pop(0) if self.packets else None

    def close(self):
        self.closed = True


class FakeInterface:
    def __init__(self, description, mac, ips):
        self.description = description
        self.mac = mac
        self.ips = ips


class FakeScapy:
    def __init__(self, packets=(), interfaces=("lo", "eth0"), denied=False, reject_filter=False):
        self.packets = list(packets)
        self.interfaces = list(interfaces)
        self.denied = denied
        self.reject_filter = reject_filter
        self.opened = []
        self.attempts = []
        self.sockets = []
        self.conf = SimpleNamespace(
            L2listen=self.listen,
            ifaces={
                "lo": FakeInterface("loopback", "00:00:00:00:00:00", {4: ["127.0.0.1"], 6: ["::1"]})
            },
        )

    def listen(self, iface=None, filter=None, promisc=None):
        self.attempts.append(filter)
        if self.denied:
            raise PermissionError(1, "Operation not permitted")
        if iface not in self.interfaces:
            raise OSError(f"no such interface {iface}")
        if filter and self.reject_filter and "badfilter" in filter:
            raise RuntimeError("filter compile failed")
        self.opened.append({"iface": iface, "filter": filter, "promisc": promisc})
        socket = FakeSocket(self.packets)
        self.sockets.append(socket)
        return socket

    def get_if_list(self):
        return list(self.interfaces)


@pytest.fixture
def fake(monkeypatch):
    def install(**kwargs):
        module = FakeScapy(**kwargs)
        monkeypatch.setattr(live, "scapy_module", lambda: module)
        return module

    return install


def test_packets_are_converted_to_raw_packets(fake):
    module = fake(packets=[FakePacket(FRAME_A, 1759000000.5), FakePacket(FRAME_B, 1759000001.25)])
    capture = LiveCapture("eth0", count=2)
    packets = list(capture.packets())
    assert module.opened == [{"iface": "eth0", "filter": None, "promisc": True}]
    assert [packet.packet_id for packet in packets] == [1, 2]
    assert packets[0].timestamp == pytest.approx(1759000000.5)
    assert packets[0].data == FRAME_A
    assert packets[0].source == "live"
    assert packets[0].origin == "eth0"
    assert packets[0].linktype == 1
    assert packets[0].truncated is False
    assert module.sockets[0].closed is True


def test_count_limit_stops_the_loop(fake):
    fake(packets=[FakePacket(FRAME_A, 1.0), FakePacket(FRAME_B, 2.0), FakePacket(FRAME_A, 3.0)])
    assert len(list(LiveCapture("eth0", count=2).packets())) == 2


def test_unparseable_timestamp_falls_back_to_wall_clock(fake):
    fake(packets=[FakePacket(FRAME_A, None)])
    packet = next(LiveCapture("eth0").packets())
    assert packet.timestamp > 1759000000


def test_unknown_interface_is_rejected_before_opening(fake):
    module = fake(packets=[], interfaces=("lo", "eth0"))
    with pytest.raises(RuntimeError) as caught:
        list(LiveCapture("wlan9").packets())
    assert "wlan9" in str(caught.value)
    assert "lo, eth0" in str(caught.value)
    assert module.opened == []


def test_permission_error_is_explained(fake):
    fake(denied=True)
    with pytest.raises(RuntimeError) as caught:
        list(LiveCapture("eth0").packets())
    assert str(caught.value) == PERMISSION_HINT


def test_rejected_bpf_filter_falls_back_to_no_filter(fake):
    module = fake(packets=[FakePacket(FRAME_A, 1.0)], reject_filter=True)
    capture = LiveCapture("eth0", bpf_filter="badfilter", count=1)
    list(capture.packets())
    assert module.attempts == ["badfilter", None]
    assert [entry["filter"] for entry in module.opened] == [None]
    assert any("without a filter" in warning for warning in capture.warnings)


def test_filter_and_promiscuity_are_forwarded(fake):
    module = fake(packets=[FakePacket(FRAME_A, 1.0)])
    list(LiveCapture("eth0", bpf_filter="tcp port 80", promiscuous=False, count=1).packets())
    assert module.opened == [{"iface": "eth0", "filter": "tcp port 80", "promisc": False}]


def test_idle_timeout_stops_the_capture(fake):
    fake(packets=[])
    capture = LiveCapture("eth0", idle_timeout=0.05, poll_interval=0.01)
    assert list(capture.packets()) == []
    assert any("without traffic" in warning for warning in capture.warnings)


def test_describe_contains_the_interface(fake):
    fake(packets=[])
    described = LiveCapture("eth0", bpf_filter="udp", count=5).describe()
    assert described["interface"] == "eth0"
    assert described["bpf_filter"] == "udp"
    assert described["count_limit"] == 5
    assert described["source"] == "live"


def test_list_interfaces_reports_addresses(fake):
    fake(interfaces=("lo",))
    assert list_interfaces() == [
        {
            "name": "lo",
            "description": "loopback",
            "mac": "00:00:00:00:00:00",
            "ips": ["127.0.0.1", "::1"],
        }
    ]


def test_scapy_module_reports_a_missing_dependency(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def blocked(name, *args, **kwargs):
        if name.startswith("scapy"):
            raise ImportError("no scapy")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", blocked)
    with pytest.raises(RuntimeError) as caught:
        live.scapy_module()
    assert "scapy is required" in str(caught.value)
