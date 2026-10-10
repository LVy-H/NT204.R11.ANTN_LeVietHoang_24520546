from __future__ import annotations

import argparse
import json
import math
import sys
from collections.abc import Sequence

from . import __version__
from .capture import EventsSource, LiveSource, PcapSource, list_interfaces
from .decoder import DecoderConfig, DecoderStage
from .issues import ParseError
from .parsers import PacketParser, ParserConfig
from .pipeline import UNKNOWN_POLICIES, Runner, Stage
from .sink import JsonlSink
from .stats import Stats

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_INTERRUPTED = 130
WARNING_PREVIEW = 3


def _parse_int(text: str) -> int:
    try:
        return int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not an integer: {text!r}") from None


def non_negative_int(text: str) -> int:
    value = _parse_int(text)
    if value < 0:
        raise argparse.ArgumentTypeError(f"must be >= 0, got {value}")
    return value


def positive_int(text: str) -> int:
    value = _parse_int(text)
    if value < 1:
        raise argparse.ArgumentTypeError(f"must be > 0, got {value}")
    return value


def non_negative_float(text: str) -> float:
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a number: {text!r}") from None
    if not math.isfinite(value) or value < 0:
        raise argparse.ArgumentTypeError(f"must be a finite number >= 0, got {text}")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ids",
        description="IDS pipeline: packet capture and parsing, then the analysis stages",
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--interface", "-i", metavar="NAME", help="capture live traffic from a network interface"
    )
    source.add_argument(
        "--pcap", "-r", metavar="FILE", help="read packets from a pcap or pcapng file"
    )
    source.add_argument(
        "--events",
        "-e",
        metavar="FILE",
        help="read schema v2 packet events from a JSON Lines file ('-' = stdin)",
    )
    source.add_argument(
        "--list-interfaces", "-L", action="store_true", help="list usable interfaces and exit"
    )
    parser.add_argument(
        "--output",
        "-o",
        metavar="FILE",
        default="-",
        help="JSON Lines output file (default: stdout)",
    )
    parser.add_argument(
        "--count",
        "-c",
        type=positive_int,
        default=None,
        metavar="N",
        help="stop after N input records",
    )
    parser.add_argument(
        "--filter",
        dest="bpf_filter",
        metavar="EXPR",
        default=None,
        help="BPF filter applied by the capture library (live capture only)",
    )
    parser.add_argument(
        "--capture-idle-timeout",
        type=non_negative_float,
        default=None,
        metavar="SECONDS",
        help="stop live capture after SECONDS without traffic (0: never)",
    )
    parser.add_argument(
        "--max-payload-bytes",
        type=non_negative_int,
        default=65535,
        metavar="BYTES",
        help="payload bytes kept in payload.data_b64 (default: 65535)",
    )
    parser.add_argument(
        "--preview-limit",
        type=non_negative_int,
        default=256,
        metavar="BYTES",
        help="payload bytes rendered in payload.preview (default: 256)",
    )
    parser.add_argument(
        "--max-decoded-bytes",
        type=non_negative_int,
        default=1_048_576,
        metavar="BYTES",
        help="UTF-8 bytes kept per decoded text field (default: 1048576)",
    )
    parser.add_argument(
        "--unknown-policy",
        choices=UNKNOWN_POLICIES,
        default="emit",
        help="emit packets whose application protocol is UNKNOWN, or skip them",
    )
    parser.add_argument("--stats", action="store_true", help="print a JSON run summary to stderr")
    parser.add_argument(
        "--quiet", "-q", action="store_true", help="suppress status messages on stderr"
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def build_stages(args: argparse.Namespace) -> list[Stage]:
    return [DecoderStage(DecoderConfig(max_decoded_bytes=args.max_decoded_bytes))]


def _note(quiet: bool, message: str) -> None:
    if not quiet:
        print(message, file=sys.stderr, flush=True)


def _print_interfaces() -> int:
    try:
        interfaces = list_interfaces()
    except RuntimeError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_ERROR
    if not interfaces:
        print("no interfaces found", file=sys.stderr)
        return EXIT_ERROR
    width = max(len(entry["name"]) for entry in interfaces)
    for entry in interfaces:
        addresses = ", ".join(entry["ips"]) or "-"
        print(f"{entry['name']:<{width}}  {entry['mac'] or '-':<17}  {addresses}")
    return EXIT_OK


def _open_source(args: argparse.Namespace) -> PcapSource | LiveSource | EventsSource:
    if args.interface is not None:
        return LiveSource(
            args.interface,
            bpf_filter=args.bpf_filter,
            count=args.count,
            capture_idle_timeout=args.capture_idle_timeout,
        )
    if args.events is not None:
        return EventsSource(args.events, count=args.count)
    return PcapSource(args.pcap, count=args.count)


def _report(
    args: argparse.Namespace, source: PcapSource | LiveSource | EventsSource, stats: Stats
) -> None:
    warnings = source.warnings
    for warning in warnings[:WARNING_PREVIEW]:
        print(f"warning: {warning}", file=sys.stderr)
    hidden = len(warnings) - WARNING_PREVIEW
    if hidden > 0:
        print(f"warning: {hidden} more warnings not shown", file=sys.stderr)
    _note(
        args.quiet,
        f"wrote {stats.written} records from {stats.packets_seen} packets"
        f" ({stats.dropped_count} dropped, {stats.skipped_count} skipped,"
        f" {stats.packets_with_issues} with issues)",
    )
    if args.stats:
        summary = stats.to_dict()
        summary["source"] = source.describe()
        print(json.dumps(summary, indent=2), file=sys.stderr)


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.list_interfaces:
        return _print_interfaces()

    source = _open_source(args)
    stats = Stats()
    stages = build_stages(args)
    packet_parser = PacketParser(
        ParserConfig(max_payload_bytes=args.max_payload_bytes, preview_limit=args.preview_limit)
    )
    interrupted = False

    _note(args.quiet, f"source: {source.source} {source.origin}")
    try:
        with JsonlSink(args.output) as sink:
            runner = Runner(packet_parser, stages, sink, stats, unknown_policy=args.unknown_policy)
            try:
                runner.run(source.items())
            except KeyboardInterrupt:
                interrupted = True
                _note(args.quiet, "interrupted, flushing what has been processed so far")
    except (ParseError, OSError, RuntimeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_ERROR
    finally:
        source.close()

    _report(args, source, stats)
    return EXIT_INTERRUPTED if interrupted else EXIT_OK
