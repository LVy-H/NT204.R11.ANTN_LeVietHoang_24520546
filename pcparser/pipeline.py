from __future__ import annotations

from .capture.base import linktype_name
from .errors import ErrorCollector, PacketParseError, TruncatedPacketError
from .event import UNKNOWN, build_event
from .payload import describe
from .parsers import dns, http, smtp
from .parsers.detector import detect
from .parsers.link import parse_link
from .parsers.network import parse_ipv4
from .parsers.transport import parse_transport

UNKNOWN_POLICIES = ("emit", "skip")
TRANSPORT_PROTOCOLS = (6, 17)


def parse_application(protocol: str, payload: bytes, tcp: bool):
    if protocol == "DNS":
        return dns.parse(payload, tcp=tcp)
    if protocol == "HTTP":
        return http.parse(payload)
    if protocol == "SMTP":
        return smtp.parse(payload)
    raise ValueError(f"no application parser registered for {protocol}")


class Pipeline:
    def __init__(self, *, unknown_policy="emit", preview_limit=None):
        if unknown_policy not in UNKNOWN_POLICIES:
            raise ValueError(f"unknown_policy must be one of {UNKNOWN_POLICIES}")
        self.unknown_policy = unknown_policy
        self.preview_limit = preview_limit

    def _summary(self, data: bytes) -> dict:
        if self.preview_limit is None:
            return describe(data)
        return describe(data, limit=self.preview_limit)

    def process(self, raw):
        try:
            event = self._build(raw)
        except Exception as error:  # noqa: BLE001 - the capture loop must survive anything
            event = self._fallback(raw, error)
        if self.unknown_policy == "skip" and event["application_protocol"] == UNKNOWN:
            return None
        return event

    def _fallback(self, raw, error: BaseException) -> dict:
        collector = ErrorCollector()
        collector.add_exception(error, "pipeline")
        return build_event(
            raw,
            capture=self._capture_block(raw, ErrorCollector()),
            link=None,
            network=None,
            transport=None,
            payload=self._summary(b""),
            detection=None,
            application=None,
            errors=collector.records,
        )

    def _capture_block(self, raw, errors) -> dict:
        if raw.truncated:
            errors.add(
                TruncatedPacketError(
                    "the capture file holds fewer bytes than the record declares",
                    declared=raw.declared_capture_length,
                    captured=raw.captured_length,
                )
            )
        return {
            "source": raw.source,
            "origin": raw.origin,
            "linktype": raw.linktype,
            "linktype_name": linktype_name(raw.linktype),
            "captured_length": raw.captured_length,
            "original_length": raw.original_length,
            "declared_capture_length": raw.declared_capture_length,
            "truncated_by_capture": raw.truncated,
        }

    def _build(self, raw) -> dict:
        errors = ErrorCollector()
        capture = self._capture_block(raw, errors)

        link_info = None
        network_info = None
        transport_info = None
        detection = None
        application = None
        payload_bytes = raw.data

        parsed = self._stage(errors, "link", parse_link, raw.data, raw.linktype)
        if parsed is not None:
            link_info = parsed.info
            payload_bytes = parsed.payload

        if parsed is not None and parsed.network_protocol == "IPv4":
            network = self._stage(errors, "network", parse_ipv4, parsed.payload)
            if network is not None:
                network_info = network.info
                payload_bytes = network.payload
                if network_info["captured_truncated"]:
                    errors.add(
                        TruncatedPacketError(
                            "captured bytes are shorter than the IPv4 total length",
                            declared=network_info["total_length"],
                            captured=len(parsed.payload) + network_info["header_length"],
                        )
                    )

        if network_info is not None and network_info["protocol_number"] in TRANSPORT_PROTOCOLS:
            transport = self._stage(
                errors,
                "transport",
                parse_transport,
                network_info["protocol_number"],
                payload_bytes,
                src_ip=network_info["src_ip"],
                dst_ip=network_info["dst_ip"],
                declared_length=network_info["declared_payload_length"],
                fragment_offset=network_info["fragment_offset"],
                more_fragments=network_info["flags"]["mf"],
            )
            if transport is not None:
                transport_info = transport.info
                payload_bytes = transport.payload

        if transport_info is not None:
            tcp = transport_info["protocol"] == "TCP"
            detection = detect(
                payload_bytes,
                src_port=transport_info["src_port"],
                dst_port=transport_info["dst_port"],
                tcp=tcp,
            )
            if detection.protocol != UNKNOWN and payload_bytes:
                application = self._stage(
                    errors, "application", parse_application, detection.protocol, payload_bytes, tcp
                )
                if isinstance(application, dict):
                    errors.extend(application.pop("errors", []))

        return build_event(
            raw,
            capture=capture,
            link=link_info,
            network=network_info,
            transport=transport_info,
            payload=self._summary(payload_bytes),
            detection=detection,
            application=application,
            errors=errors.records,
        )

    @staticmethod
    def _stage(errors, stage, function, *args, **kwargs):
        try:
            return function(*args, **kwargs)
        except PacketParseError as error:
            errors.add(error)
        except Exception as error:  # noqa: BLE001 - one bad parser must not stop the capture
            errors.add_exception(error, stage)
        return None
