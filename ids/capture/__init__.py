from __future__ import annotations

from .base import CaptureSource, RawPacket, linktype_name
from .live import LiveCapture, list_interfaces
from .pcap import PcapFileCapture


def open_capture(*, interface=None, path=None, count=None, bpf_filter=None, idle_timeout=None):
    if interface and path:
        raise ValueError("choose either --interface or --pcap, not both")
    if interface:
        return LiveCapture(interface, count=count, bpf_filter=bpf_filter, idle_timeout=idle_timeout)
    if path:
        return PcapFileCapture(path, count=count)
    raise ValueError("one of --interface or --pcap is required")


__all__ = [
    "CaptureSource",
    "LiveCapture",
    "PcapFileCapture",
    "RawPacket",
    "linktype_name",
    "list_interfaces",
    "open_capture",
]
