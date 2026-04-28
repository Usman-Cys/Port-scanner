"""
core/models.py — Shared data models for PyPortScanner.

Keeping models in a separate module prevents circular imports between
the scanner modules and the output formatters.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict


class PortStatus(str, Enum):
    """Human-readable port state."""

    OPEN = "OPEN"
    CLOSED = "CLOSED"
    FILTERED = "FILTERED"
    OPEN_FILTERED = "OPEN|FILTERED"


@dataclass
class ScanResult:
    """Represents the scan result for a single (host, port) pair.

    Attributes:
        host:        Target hostname or IP address.
        port:        TCP/UDP port number.
        status:      One of the PortStatus enum values.
        service:     Detected service name (populated by ServiceDetector).
        banner:      Raw banner text grabbed from the port.
        version:     Parsed version string from the banner.
        scan_time:   How long the probe took in seconds.
        protocol:    "tcp" or "udp".
        extra:       Additional key/value metadata.
    """

    host: str
    port: int
    status: PortStatus = PortStatus.FILTERED
    service: str = ""
    banner: str = ""
    version: str = ""
    scan_time: float = 0.0
    protocol: str = "tcp"
    extra: Dict[str, str] = field(default_factory=dict)
