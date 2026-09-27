from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .capture import list_interfaces, open_capture
from .logger import JsonlWriter
from .pipeline import UNKNOWN_POLICIES, Pipeline
from .stats import Stats

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
PROGRESS_EVERY = 10000
WARNING_PREVIEW = 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pcparser",
        description="Packet Capture & Parser module for the IDS project",
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--interface", "-i", metavar="NAME", help="capture live traffic from a network interface"
    )
    source.add_argument(
        "--pcap", "-r", metavar="FILE", help="read packets from a pcap or pcapng file"
    )
    source.add_argument(
        "--list-interfaces", "-L", action="store_true", help="list usable interfaces and exit"
    )
    parser.add_argument(
        "--output", "-o", metavar="FILE", default="-", help="JSON Lines output file (default: stdout)"
    )
    parser.add_argument("--count", "-c", type=int, default=None, metavar="N", help="stop after N packets")
    parser.add_argument(
        "--filter", dest="bpf_filter", metavar="EXPR", default=None,
        help="BPF filter applied by the capture library (live capture only)",
    )
    parser.add_argument(
        "--unknown-policy", choices=UNKNOWN_POLICIES, default="emit",
        help="emit packets with an undetected protocol, or skip them",
    )
    parser.add_argument(
        "--idle-timeout", type=float, default=None, metavar="SECONDS",
        help="stop live capture after N seconds without traffic",
    )
    parser.add_argument(
        "--preview-limit", type=int, default=None, metavar="BYTES",
        help="maximum number of payload bytes kept in the preview",
    )
    parser.add_argument("--stats", action="store_true", help="print a run summary to stderr")
    parser.add_argument("--quiet", "-q", action="store_true", help="suppress progress messages")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


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


def _run(source, pipeline, writer, stats, quiet) -> None:
    for raw in source.packets():
        event = pipeline.process(raw)
        if event is None:
            stats.skip()
        else:
            stats.observe(event)
            writer.write(event)
        if not quiet and stats.packets % PROGRESS_EVERY == 0:
            _note(quiet, f"... {stats.packets} packets processed")


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    if args.list_interfaces:
        return _print_interfaces()

    try:
        source = open_capture(
            interface=args.interface,
            path=args.pcap,
            count=args.count,
            bpf_filter=args.bpf_filter,
            idle_timeout=args.idle_timeout,
        )
    except (ValueError, OSError, RuntimeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE if isinstance(error, ValueError) else EXIT_ERROR

    pipeline = Pipeline(unknown_policy=args.unknown_policy, preview_limit=args.preview_limit)
    stats = Stats()
    writer = JsonlWriter(args.output)
    interrupted = False

    _note(args.quiet, f"source: {source.describe()}")
    try:
        _run(source, pipeline, writer, stats, args.quiet)
    except KeyboardInterrupt:
        interrupted = True
        _note(args.quiet, "interrupted, flushing what has been parsed so far")
    except (OSError, RuntimeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_ERROR
    finally:
        writer.close()
        source.close()

    for warning in getattr(source, "warnings", [])[:WARNING_PREVIEW]:
        print(f"warning: {warning}", file=sys.stderr)
    _note(
        args.quiet,
        f"parsed {stats.emitted} events from {stats.packets} packets"
        f" ({stats.skipped} skipped, {stats.packets_with_errors} with errors)",
    )
    if args.stats:
        print(json.dumps(stats.to_dict(), indent=2), file=sys.stderr)

    return EXIT_OK if not interrupted else 130
