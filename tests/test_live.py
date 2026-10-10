from __future__ import annotations

import builtins
import json
import time

import pytest
from fake_scapy import FakePacket, FakeScapy
from golden import UDP

from ids.capture import live
from ids.capture.live import PERMISSION_HINT, LiveSource, list_interfaces
from ids.cli import main
from ids.model import RawPacket, Tick

FRAME_A = bytes.fromhex("0200000000020200000000010800") + b"\x45" + b"\x00" * 41
FRAME_B = bytes.fromhex("0200000000020200000000010800") + b"\x45" + b"\x01" * 41


class FakeCookedPacket(FakePacket):
    """Stands in for a scapy layer class registered under another DLT."""


@pytest.fixture
def fake(monkeypatch):
    def install(**kwargs):
        module = FakeScapy(**kwargs)
        monkeypatch.setattr(live, "scapy_module", lambda: module)
        return module

    return install


def test_packets_are_converted_to_raw_packets(fake):
    module = fake(packets=[FakePacket(FRAME_A, 1759000000.5), FakePacket(FRAME_B, 1759000001.25)])
    packets = list(LiveSource("eth0", count=2).items())
    assert module.opened == [{"iface": "eth0", "filter": None, "promisc": True}]
    assert [packet.packet_id for packet in packets] == [1, 2]
    assert packets[0].timestamp == pytest.approx(1759000000.5)
    assert packets[0].data == FRAME_A
    assert packets[0].source == "live"
    assert packets[0].origin == "eth0"
    assert packets[0].linktype == 1
    assert packets[0].truncated is False
    assert module.sockets[0].closed is True


def test_linktype_comes_from_the_scapy_layer_class(fake):
    fake(
        packets=[FakeCookedPacket(FRAME_A, 1.0), FakePacket(FRAME_B, 2.0)],
        layer2num={FakeCookedPacket: 113},
    )
    packets = list(LiveSource("eth0", count=2).items())
    assert [packet.linktype for packet in packets] == [113, 1]


def test_count_limit_stops_the_loop(fake):
    fake(packets=[FakePacket(FRAME_A, 1.0), FakePacket(FRAME_B, 2.0), FakePacket(FRAME_A, 3.0)])
    assert len(list(LiveSource("eth0", count=2).items())) == 2


def test_unparseable_timestamp_falls_back_to_wall_clock(fake):
    fake(packets=[FakePacket(FRAME_A, None)])
    packet = next(LiveSource("eth0").items())
    assert packet.timestamp > 1759000000


def test_unknown_interface_is_rejected_before_opening(fake):
    module = fake(packets=[], interfaces=("lo", "eth0"))
    with pytest.raises(RuntimeError) as caught:
        list(LiveSource("wlan9").items())
    assert "wlan9" in str(caught.value)
    assert "lo, eth0" in str(caught.value)
    assert module.opened == []


def test_permission_error_is_explained(fake):
    fake(denied=True)
    with pytest.raises(RuntimeError) as caught:
        list(LiveSource("eth0").items())
    assert str(caught.value) == PERMISSION_HINT


def test_rejected_bpf_filter_falls_back_to_no_filter(fake):
    module = fake(packets=[FakePacket(FRAME_A, 1.0)], reject_filter=True)
    source = LiveSource("eth0", bpf_filter="badfilter", count=1)
    list(source.items())
    assert module.attempts == ["badfilter", None]
    assert [entry["filter"] for entry in module.opened] == [None]
    assert any("without a filter" in warning for warning in source.warnings)


def test_filter_and_promiscuity_are_forwarded(fake):
    module = fake(packets=[FakePacket(FRAME_A, 1.0)])
    list(LiveSource("eth0", bpf_filter="tcp port 80", promiscuous=False, count=1).items())
    assert module.opened == [{"iface": "eth0", "filter": "tcp port 80", "promisc": False}]


def test_capture_idle_timeout_stops_the_capture(fake):
    fake(packets=[])
    source = LiveSource("eth0", capture_idle_timeout=0.05, poll_interval=0.01)
    assert list(source.items()) == []
    assert any("without traffic" in warning for warning in source.warnings)


def test_describe_contains_the_interface(fake):
    fake(packets=[])
    described = LiveSource("eth0", bpf_filter="udp", count=5, capture_idle_timeout=2.0).describe()
    assert described["interface"] == "eth0"
    assert described["bpf_filter"] == "udp"
    assert described["count_limit"] == 5
    assert described["capture_idle_timeout"] == 2.0
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
    real_import = builtins.__import__

    def blocked(name, *args, **kwargs):
        if name.startswith("scapy"):
            raise ImportError("no scapy")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", blocked)
    with pytest.raises(RuntimeError) as caught:
        live.scapy_module()
    assert "scapy is required" in str(caught.value)


def test_tick_mode_yields_ticks_while_the_interface_is_idle(fake):
    fake(packets=[FakePacket(UDP, 1759000000.5)])
    before = time.time()
    items = list(LiveSource("eth0", tick=True, capture_idle_timeout=0.05).items())
    after = time.time()
    assert isinstance(items[0], RawPacket)
    ticks = items[1:]
    assert ticks
    assert all(isinstance(item, Tick) and before <= item.now <= after for item in ticks)


def test_no_ticks_without_tick_mode(fake):
    fake(packets=[FakePacket(UDP, 1759000000.5)])
    items = list(LiveSource("eth0", capture_idle_timeout=0.05).items())
    assert [type(item) for item in items] == [RawPacket]


def test_live_run_expires_idle_flows_on_ticks(fake, tmp_path):
    fake(packets=[FakePacket(UDP, time.time() - 30)])
    out = tmp_path / "out.jsonl"
    argv = ["-i", "eth0", "-o", str(out), "-q", "--capture-idle-timeout", "0.2"]
    assert main([*argv, "--udp-idle-timeout", "1"]) == 0
    records = [json.loads(line) for line in out.read_text().splitlines()]
    assert [r["record_type"] for r in records] == ["packet", "flow"]
    assert records[1]["end_reason"] == "idle_timeout"
