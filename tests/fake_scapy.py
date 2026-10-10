"""Stand-in for the parts of `scapy.all` that ids.capture.live uses."""

from __future__ import annotations

import time
from types import SimpleNamespace


class FakePacket:
    def __init__(self, raw: bytes, timestamp: object) -> None:
        self.raw = raw
        self.time = timestamp

    def __bytes__(self) -> bytes:
        return self.raw


class FakeSocket:
    def __init__(self, packets: list[FakePacket]) -> None:
        self.packets = list(packets)
        self.closed = False

    def select(self, sockets: list[FakeSocket], timeout: float) -> list[FakeSocket]:
        time.sleep(0.01)
        return [self] if self.packets else []

    def recv(self) -> FakePacket | None:
        return self.packets.pop(0) if self.packets else None

    def close(self) -> None:
        self.closed = True


class FakeInterface:
    def __init__(self, description: str, mac: str, ips: dict[int, list[str]]) -> None:
        self.description = description
        self.mac = mac
        self.ips = ips


class FakeScapy:
    def __init__(
        self,
        packets: tuple[FakePacket, ...] | list[FakePacket] = (),
        interfaces: tuple[str, ...] = ("lo", "eth0"),
        denied: bool = False,
        reject_filter: bool = False,
        layer2num: dict[type, int] | None = None,
    ) -> None:
        self.packets = list(packets)
        self.interfaces = list(interfaces)
        self.denied = denied
        self.reject_filter = reject_filter
        self.opened: list[dict[str, object]] = []
        self.attempts: list[str | None] = []
        self.sockets: list[FakeSocket] = []
        self.conf = SimpleNamespace(
            L2listen=self.listen,
            ifaces={
                "lo": FakeInterface("loopback", "00:00:00:00:00:00", {4: ["127.0.0.1"], 6: ["::1"]})
            },
            l2types=SimpleNamespace(layer2num=dict(layer2num or {})),
        )

    def listen(
        self, iface: str | None = None, filter: str | None = None, promisc: bool | None = None
    ) -> FakeSocket:
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

    def get_if_list(self) -> list[str]:
        return list(self.interfaces)
