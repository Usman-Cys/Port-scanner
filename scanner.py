#!/usr/bin/env python3
"""
scanner.py — PyPortScanner main CLI entry point.

Usage:
    python scanner.py -t <target> [options]

Run `python scanner.py --help` for full usage.

⚠️  FOR AUTHORIZED SECURITY TESTING AND EDUCATIONAL PURPOSES ONLY.
   Scanning networks without explicit permission may be illegal.
"""

from __future__ import annotations

import argparse
import signal
import sys
from typing import List, Optional

from config import (
    APP_NAME,
    APP_VERSION,
    DEFAULT_TIMEOUT,
    MAX_THREADS,
    DEFAULT_DELAY,
    DISCLAIMER,
    TOP_PORTS_COUNT,
)
from core.banner_grabber import BannerGrabber
from core.models import ScanResult, PortStatus
from core.service_detector import ServiceDetector
from core.tcp_scanner import TCPScanner
from core.udp_scanner import UDPScanner
from utils.logger import get_logger, set_verbose
from utils.network_utils import NetworkParseError, is_private_ip, parse_ports, parse_targets
from utils.output_formatter import OutputFormatter

logger = get_logger(__name__)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scanner.py",
        description=(
            f"{APP_NAME} v{APP_VERSION} — TCP/UDP port scanner\n\n"
            f"{DISCLAIMER}"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python scanner.py -t 192.168.1.1\n"
            "  python scanner.py -t 192.168.1.1 -p 1-1000 --banner -T 200\n"
            "  python scanner.py -t 192.168.1.0/24 -p 22,80,443 --csv out.csv\n"
            "  python scanner.py -t 10.0.0.1 -p 53,161,123 --udp\n"
            "  sudo python scanner.py -t 192.168.1.1 -p 1-1000 --syn\n"
            "  python scanner.py -t 192.168.1.1 --dry-run\n"
        ),
    )

    # --- Target ---
    parser.add_argument(
        "-t", "--target",
        required=True,
        metavar="TARGET",
        help=(
            "Target(s): single IP, comma-separated IPs, CIDR (192.168.1.0/24), "
            "or hostname.  Multiple targets: -t 10.0.0.1,10.0.0.2"
        ),
    )

    # --- Port spec ---
    parser.add_argument(
        "-p", "--ports",
        default=None,
        metavar="PORTS",
        help=(
            "Ports to scan.  Formats: single (80), range (1-1000), "
            "list (22,80,443), mixed (22,80,100-200).  "
            f"Default: top {TOP_PORTS_COUNT} well-known ports."
        ),
    )

    # --- Scan type ---
    scan_group = parser.add_mutually_exclusive_group()
    scan_group.add_argument(
        "--udp",
        action="store_true",
        help="Perform UDP scan instead of TCP.",
    )
    scan_group.add_argument(
        "--syn",
        action="store_true",
        help="TCP SYN (stealth) scan — requires root/admin (uses scapy).",
    )

    # --- Speed / timing ---
    parser.add_argument(
        "-T", "--threads",
        type=int,
        default=MAX_THREADS,
        metavar="N",
        help=f"Number of concurrent threads (default: {MAX_THREADS}).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        metavar="SECS",
        help=f"Per-port socket timeout in seconds (default: {DEFAULT_TIMEOUT}).",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=DEFAULT_DELAY,
        metavar="SECS",
        help=f"Delay between probes for rate limiting (default: {DEFAULT_DELAY}).",
    )

    # --- Feature flags ---
    parser.add_argument(
        "--banner",
        action="store_true",
        help="Attempt banner grabbing on open TCP ports.",
    )
    parser.add_argument(
        "--show-closed",
        action="store_true",
        help="Also show CLOSED ports in output (hidden by default).",
    )

    # --- Output ---
    parser.add_argument(
        "--json",
        metavar="FILE",
        help="Export results to a JSON file.",
    )
    parser.add_argument(
        "--csv",
        metavar="FILE",
        help="Export results to a CSV file.",
    )

    # --- Safety / misc ---
    parser.add_argument(
        "--no-safe-check",
        action="store_true",
        help="Disable warning when scanning public IP addresses.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what WOULD be scanned without sending any packets.",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose/debug logging to console.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {APP_VERSION}",
    )

    return parser


def _top_ports(count: int) -> List[int]:
    """Return the first *count* well-known TCP ports from the services DB."""
    import json
    from pathlib import Path

    services_path = Path(__file__).parent / "data" / "common_services.json"
    if not services_path.exists():
        # Fallback: the most common 20 ports
        return [21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
                143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]

    with open(services_path, "r", encoding="utf-8") as fh:
        db = json.load(fh)

    ports = sorted({int(e["port"]) for e in db.values() if e.get("protocol") == "tcp"})
    return ports[:count]


def _warn_public_ip(targets: List[str]) -> None:
    """Print a warning if any target is a public (non-private) IP."""
    public = [ip for ip in targets if not is_private_ip(ip)]
    if public:
        print(
            "\n⚠️  WARNING: The following targets appear to be public IP addresses:\n"
            + "   " + ", ".join(public)
            + "\nEnsure you have EXPLICIT WRITTEN PERMISSION before scanning.\n"
        )


def _dry_run_output(targets: List[str], ports: List[int], args: argparse.Namespace) -> None:
    """Print a human-readable summary of what would be scanned."""
    mode = "UDP" if args.udp else ("SYN" if args.syn else "TCP Connect")
    print(f"\n{'=' * 60}")
    print(f"  DRY RUN — {APP_NAME} v{APP_VERSION}")
    print(f"{'=' * 60}")
    print(f"  Mode        : {mode}")
    print(f"  Targets     : {len(targets)} host(s)")
    for t in targets[:10]:
        print(f"               {t}")
    if len(targets) > 10:
        print(f"               … and {len(targets) - 10} more")
    print(f"  Ports       : {len(ports)} port(s)  [{min(ports)}–{max(ports)}]")
    print(f"  Threads     : {args.threads}")
    print(f"  Timeout     : {args.timeout}s")
    print(f"  Delay       : {args.delay}s")
    print(f"  Banner grab : {args.banner}")
    total = len(targets) * len(ports)
    print(f"  Total probes: {total}")
    print(f"{'=' * 60}\n")


def main(argv: Optional[List[str]] = None) -> int:
    """Main entry point.

    Args:
        argv: Argument list (defaults to sys.argv[1:]).

    Returns:
        Exit code (0 = success, non-zero = error).
    """
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.verbose:
        set_verbose(True)

    print(f"\n{APP_NAME} v{APP_VERSION}")
    print(DISCLAIMER)

    # --- Parse targets ---
    try:
        targets = parse_targets(args.target)
    except NetworkParseError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    # --- Safety check ---
    if not args.no_safe_check:
        _warn_public_ip(targets)

    # --- Parse ports ---
    if args.ports:
        try:
            ports = parse_ports(args.ports)
        except NetworkParseError as exc:
            print(f"[ERROR] {exc}", file=sys.stderr)
            return 1
    else:
        ports = _top_ports(TOP_PORTS_COUNT)

    # --- Dry run ---
    if args.dry_run:
        _dry_run_output(targets, ports, args)
        return 0

    # --- Set up graceful Ctrl+C ---
    scanner_ref: list = []

    def _sigint_handler(signum, frame):  # type: ignore[no-untyped-def]
        print("\n\n[!] Scan interrupted by user (Ctrl+C). Stopping…", file=sys.stderr)
        for s in scanner_ref:
            s.stop()

    signal.signal(signal.SIGINT, _sigint_handler)

    # --- Run scan ---
    formatter = OutputFormatter()
    detector = ServiceDetector()
    results: List[ScanResult] = []

    if args.udp:
        scanner = UDPScanner(
            timeout=args.timeout,
            threads=args.threads,
            delay=args.delay,
        )
        scanner_ref.append(scanner)
        results = scanner.scan(targets, ports)
    else:
        scanner = TCPScanner(
            timeout=args.timeout,
            threads=args.threads,
            delay=args.delay,
            syn_scan=args.syn,
        )
        scanner_ref.append(scanner)
        results = scanner.scan(targets, ports)

    # --- Banner grabbing (TCP only) ---
    if args.banner and not args.udp:
        grabber = BannerGrabber(timeout=args.timeout + 1)
        open_results = [r for r in results if r.status == PortStatus.OPEN]
        print(f"[*] Grabbing banners from {len(open_results)} open port(s)…")
        for result in open_results:
            result.banner = grabber.grab(result.host, result.port)

    # --- Service detection ---
    for result in results:
        info = detector.detect(result.port, result.banner, result.protocol)
        result.service = info.name
        result.version = info.version

    # --- Print table ---
    formatter.print_table(results, show_closed=args.show_closed)

    # --- Export ---
    if args.json:
        formatter.to_json(results, args.json)
        print(f"[+] JSON results saved to {args.json}")

    if args.csv:
        formatter.to_csv(results, args.csv)
        print(f"[+] CSV results saved to {args.csv}")

    open_count = sum(1 for r in results if r.status == PortStatus.OPEN)
    print(f"\n[+] Scan complete. {open_count} open port(s) found across {len(targets)} host(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
