from __future__ import annotations

import time

from .base import DLT_EN10MB, RawPacket

PERMISSION_HINT = (
    "live capture requires CAP_NET_RAW (Linux) or administrator rights; "
    "run with sudo or grant the capability, or use --pcap instead"
)


def scapy_module():
    try:
        import scapy.all as scapy_all
    except ImportError as exc:
        raise RuntimeError(
            "scapy is required for live capture; install it with `uv sync` or use --pcap"
        ) from exc
    return scapy_all


def list_interfaces():
    scapy_all = scapy_module()
    interfaces = []
    for name in scapy_all.get_if_list():
        entry = scapy_all.conf.ifaces.get(name)
        ips = []
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


class LiveCapture:
    source = "live"
    linktype = DLT_EN10MB

    def __init__(
        self,
        interface,
        *,
        bpf_filter=None,
        count=None,
        promiscuous=True,
        idle_timeout=None,
        poll_interval=1.0,
    ):
        self.interface = interface
        self.origin = interface
        self.bpf_filter = bpf_filter
        self.count = count
        self.promiscuous = promiscuous
        self.idle_timeout = idle_timeout
        self.poll_interval = poll_interval
        self.warnings = []

    def close(self):
        pass

    def describe(self):
        return {
            "source": self.source,
            "origin": self.origin,
            "interface": self.interface,
            "linktype": self.linktype,
            "bpf_filter": self.bpf_filter,
            "promiscuous": self.promiscuous,
            "count_limit": self.count,
            "idle_timeout": self.idle_timeout,
        }

    def _open_socket(self):
        scapy_all = scapy_module()
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

    def packets(self):
        socket = self._open_socket()
        index = 0
        last_packet = time.monotonic()
        try:
            while True:
                if self.count is not None and index >= self.count:
                    return
                if not socket.select([socket], self.poll_interval):
                    if self.idle_timeout and time.monotonic() - last_packet >= self.idle_timeout:
                        self.warnings.append(
                            f"live capture stopped after {self.idle_timeout}s without traffic"
                        )
                        return
                    continue
                packet = socket.recv()
                if packet is None:
                    continue
                last_packet = time.monotonic()
                index += 1
                try:
                    timestamp = float(packet.time)
                except (TypeError, ValueError):
                    timestamp = time.time()
                data = bytes(packet)
                yield RawPacket(
                    packet_id=index,
                    timestamp=timestamp,
                    data=data,
                    linktype=self.linktype,
                    source=self.source,
                    origin=self.origin,
                    original_length=len(data),
                    declared_capture_length=len(data),
                )
        finally:
            socket.close()
