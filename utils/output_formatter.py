"""
utils/output_formatter.py — CLI table, JSON, and CSV output for scan results.

Output modes:
  * ``print_table``  — pretty Rich table to stdout (colours: green/red/yellow)
  * ``to_json``      — write JSON array to a file
  * ``to_csv``       — write CSV file with a header row
"""

from __future__ import annotations

import csv
import json
import os
from dataclasses import asdict
from typing import List, Optional

from core.models import ScanResult, PortStatus
from utils.logger import get_logger

logger = get_logger(__name__)


class OutputFormatter:
    """Formats and writes scan results to various outputs.

    Example:
        >>> fmt = OutputFormatter()
        >>> fmt.print_table(results)
        >>> fmt.to_json(results, "output.json")
        >>> fmt.to_csv(results, "output.csv")
    """

    # ------------------------------------------------------------------
    # Terminal table (using Rich if available, tabulate as fallback)
    # ------------------------------------------------------------------

    def print_table(self, results: List[ScanResult], show_closed: bool = False) -> None:
        """Print a colourised summary table to stdout.

        Args:
            results:      List of ScanResult objects.
            show_closed:  If False (default) hide CLOSED ports.
        """
        rows = [r for r in results if show_closed or r.status != PortStatus.CLOSED]
        rows.sort(key=lambda r: (r.host, r.port))

        try:
            self._print_rich(rows)
        except ImportError:
            self._print_tabulate(rows)

    # ------------------------------------------------------------------
    # JSON
    # ------------------------------------------------------------------

    def to_json(self, results: List[ScanResult], path: str) -> None:
        """Write *results* as a JSON array to *path*.

        Args:
            results: List of ScanResult objects.
            path:    Output file path.
        """
        data = [self._result_to_dict(r) for r in results]
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        logger.info("JSON report written to %s (%d records).", path, len(data))

    # ------------------------------------------------------------------
    # CSV
    # ------------------------------------------------------------------

    def to_csv(self, results: List[ScanResult], path: str) -> None:
        """Write *results* as a CSV file to *path*.

        Args:
            results: List of ScanResult objects.
            path:    Output file path.
        """
        if not results:
            logger.warning("No results to write.")
            return

        fieldnames = ["host", "port", "protocol", "status", "service", "version", "banner", "scan_time"]
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            for r in results:
                writer.writerow(self._result_to_dict(r))
        logger.info("CSV report written to %s (%d records).", path, len(results))

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _result_to_dict(r: ScanResult) -> dict:
        d = {
            "host": r.host,
            "port": r.port,
            "protocol": r.protocol,
            "status": r.status.value if hasattr(r.status, "value") else str(r.status),
            "service": r.service,
            "version": r.version,
            "banner": r.banner,
            "scan_time": round(r.scan_time, 4),
        }
        return d

    @staticmethod
    def _status_style(status: PortStatus) -> str:
        """Return a Rich style string for a given PortStatus."""
        mapping = {
            PortStatus.OPEN: "bold green",
            PortStatus.CLOSED: "red",
            PortStatus.FILTERED: "yellow",
            PortStatus.OPEN_FILTERED: "bold yellow",
        }
        return mapping.get(status, "white")

    def _print_rich(self, rows: List[ScanResult]) -> None:
        """Render using the Rich library."""
        from rich.console import Console  # type: ignore
        from rich.table import Table  # type: ignore

        console = Console()
        table = Table(title="PyPortScanner Results", show_header=True, header_style="bold magenta")
        table.add_column("Host", style="cyan")
        table.add_column("Port", justify="right")
        table.add_column("Proto")
        table.add_column("Status")
        table.add_column("Service")
        table.add_column("Version")
        table.add_column("Banner", max_width=60, no_wrap=False, overflow="fold")

        for r in rows:
            style = self._status_style(r.status)
            status_val = r.status.value if hasattr(r.status, "value") else str(r.status)
            table.add_row(
                r.host,
                str(r.port),
                r.protocol,
                f"[{style}]{status_val}[/{style}]",
                r.service,
                r.version,
                r.banner[:80] if r.banner else "",
            )

        console.print(table)
        open_count = sum(1 for r in rows if r.status == PortStatus.OPEN)
        console.print(f"\n[bold]Open ports: {open_count} / {len(rows)} shown[/bold]")

    @staticmethod
    def _print_tabulate(rows: List[ScanResult]) -> None:
        """Fallback renderer using tabulate."""
        try:
            from tabulate import tabulate  # type: ignore
        except ImportError:
            # Last-resort: plain print
            print(f"{'HOST':<20} {'PORT':>6} {'PROTO':<6} {'STATUS':<15} {'SERVICE':<15} {'VERSION'}")
            print("-" * 80)
            for r in rows:
                status_val = r.status.value if hasattr(r.status, "value") else str(r.status)
                print(f"{r.host:<20} {r.port:>6} {r.protocol:<6} {status_val:<15} {r.service:<15} {r.version}")
            return

        headers = ["Host", "Port", "Proto", "Status", "Service", "Version", "Banner"]
        table_data = []
        for r in rows:
            status_val = r.status.value if hasattr(r.status, "value") else str(r.status)
            table_data.append([
                r.host,
                r.port,
                r.protocol,
                status_val,
                r.service,
                r.version,
                (r.banner[:60] + "…") if len(r.banner) > 60 else r.banner,
            ])
        print(tabulate(table_data, headers=headers, tablefmt="grid"))
