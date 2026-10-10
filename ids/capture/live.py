from __future__ import annotations

import time
from collections.abc import Iterator
from typing import Any

from ..model import RawPacket, Tick
from .base import DLT_EN10MB

PERMISSION_HINT = (
    "live capture requires CAP_NET_RAW (Linux) or administrator rights; "
    "run with sudo or grant the capability, or use --pcap instead"
)


def scapy_module() -> Any:
    try:
        import scapy.all as scapy_all
    except ImportError as exc:
        raise RuntimeError(
            "scapy is required for live capture; install it with `uv sync` or use --pcap"
        ) from exc
    return scapy_all


def list_interfaces() -> list[dict[str, object]]:
    scapy_all = scapy_module()
    interfaces: list[dict[str, object]] = []
    for name in scapy_all.get_if_list():
        entry = scapy_all.conf.ifaces.get(name)
        ips: list[str] = []
        if entry is not None:
            for family in (4, 6):
                ips.extend(entry.ips.get(family, []))
        interfaces.append(
            {
                "name": name,
                "description": getattr(entry, "description", "") or "",
                "mac": str(getattr(entry, "mac", "") or ""),
                "ips": ips,
            }
        )
    return interfaces


class LiveSource:
    source = "live"

    def __init__(
        self,
        interface: str,
        *,
        bpf_filter: str | None = None,
        count: int | None = None,
        promiscuous: bool = True,
        capture_idle_timeout: float | None = None,
        poll_interval: float = 1.0,
        tick: bool = False,
    ) -> None:
        self.interface = interface
        self.origin = interface
        self.bpf_filter = bpf_filter
        self.count = count
        self.promiscuous = promiscuous
        self.capture_idle_timeout = capture_idle_timeout
        self.poll_interval = poll_interval
        self.tick = tick
        self.warnings: list[str] = []

    def close(self) -> None:
        """The socket is opened and closed inside items(); nothing else is held."""

    def describe(self) -> dict[str, object]:
        return {
            "source": self.source,
            "origin": self.origin,
            "interface": self.interface,
            "bpf_filter": self.bpf_filter,
            "promiscuous": self.promiscuous,
            "count_limit": self.count,
            "capture_idle_timeout": self.capture_idle_timeout,
        }

    def _open_socket(self, scapy_all: Any) -> Any:
        available = scapy_all.get_if_list()
        if self.interface not in available:
            raise RuntimeError(
                f"interface {self.interface!r} not found; available: {', '.join(available)}"
            )
        try:
            try:
                return scapy_all.conf.L2listen(
                    iface=self.interface,
                    filter=self.bpf_filter,
                    promisc=self.promiscuous,
                )
            except PermissionError as exc:
                raise RuntimeError(PERMISSION_HINT) from exc
            except Exception as exc:
                if not self.bpf_filter:
                    raise
                self.warnings.append(f"BPF filter rejected ({exc}); capturing without a filter")
                return scapy_all.conf.L2listen(iface=self.interface, promisc=self.promiscuous)
        except PermissionError as exc:
            raise RuntimeError(PERMISSION_HINT) from exc

    def items(self) -> Iterator[RawPacket | Tick]:
        scapy_all = scapy_module()
        socket = self._open_socket(scapy_all)
        layer2num = scapy_all.conf.l2types.layer2num
        index = 0
        last_packet = time.monotonic()
        try:
            while self.count is None or index < self.count:
                if not socket.select([socket], self.poll_interval):
                    if (
                        self.capture_idle_timeout
                        and time.monotonic() - last_packet >= self.capture_idle_timeout
                    ):
                        self.warnings.append(
                            f"live capture stopped after {self.capture_idle_timeout}s"
                            " without traffic"
                        )
                        return
                    if self.tick:
                        yield Tick(time.time())  # lets the flow tracker expire idle flows
                    continue
                packet = socket.recv()
                if packet is None:
                    continue
                last_packet = time.monotonic()
                index += 1
                yield self._raw_packet(index, packet, layer2num.get(type(packet), DLT_EN10MB))
        finally:
            socket.close()

    def _raw_packet(self, index: int, packet: Any, linktype: int) -> RawPacket:
        try:
            timestamp = float(packet.time)
        except (TypeError, ValueError):
            timestamp = time.time()
        data = bytes(packet)
        return RawPacket(
            packet_id=index,
            timestamp=timestamp,
            data=data,
            linktype=linktype,
            source=self.source,
            origin=self.origin,
            original_length=len(data),
            declared_capture_length=len(data),
        )
