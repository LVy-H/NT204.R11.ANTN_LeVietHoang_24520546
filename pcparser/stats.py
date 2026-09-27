from __future__ import annotations

from collections import Counter


class Stats:
    def __init__(self):
        self.packets = 0
        self.emitted = 0
        self.skipped = 0
        self.event_types = Counter()
        self.network_protocols = Counter()
        self.transport_protocols = Counter()
        self.application_protocols = Counter()
        self.detection_methods = Counter()
        self.error_codes = Counter()
        self.packets_with_errors = 0
        self.first_timestamp = None
        self.last_timestamp = None

    def observe(self, event: dict) -> None:
        self.packets += 1
        self.emitted += 1
        self.event_types[event["event_type"]] += 1
        self.network_protocols[event["network_protocol"] or "none"] += 1
        self.transport_protocols[event["transport_protocol"] or "none"] += 1
        self.application_protocols[event["application_protocol"]] += 1
        detection = event["application"]["detection"]
        if detection:
            self.detection_methods[detection["method"]] += 1
        if event["errors"]:
            self.packets_with_errors += 1
            for error in event["errors"]:
                self.error_codes[f"{error['stage']}/{error['code']}"] += 1
        timestamp = event["timestamp"]
        if self.first_timestamp is None:
            self.first_timestamp = timestamp
        self.last_timestamp = timestamp

    def skip(self) -> None:
        self.packets += 1
        self.skipped += 1

    def to_dict(self) -> dict:
        return {
            "packets_seen": self.packets,
            "events_written": self.emitted,
            "events_skipped": self.skipped,
            "packets_with_errors": self.packets_with_errors,
            "first_timestamp": self.first_timestamp,
            "last_timestamp": self.last_timestamp,
            "event_types": dict(self.event_types.most_common()),
            "network_protocols": dict(self.network_protocols.most_common()),
            "transport_protocols": dict(self.transport_protocols.most_common()),
            "application_protocols": dict(self.application_protocols.most_common()),
            "detection_methods": dict(self.detection_methods.most_common()),
            "error_codes": dict(self.error_codes.most_common()),
        }
