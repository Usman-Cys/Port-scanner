"""
core/service_detector.py — Service and version fingerprinting.

Detection strategy (in order of confidence):
  1. Exact well-known port lookup in common_services.json
  2. Banner regex matching against known service signatures
  3. Fall back to the port-lookup name with LOW confidence

Confidence levels:
  HIGH   — banner matched a known signature
  MEDIUM — exact port number found in well-known services table
  LOW    — heuristic / no match
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from utils.logger import get_logger

logger = get_logger(__name__)

# Path to the embedded services database
_DATA_DIR = Path(__file__).parent.parent / "data"
_SERVICES_JSON = _DATA_DIR / "common_services.json"


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class ServiceInfo:
    """Result of service detection for a single port.

    Attributes:
        name:       Service name (e.g. "ssh", "http").
        version:    Parsed version string (may be empty).
        confidence: How confident we are in the detection.
        details:    Human-readable detection notes.
    """

    name: str = ""
    version: str = ""
    confidence: Confidence = Confidence.LOW
    details: str = ""


# ---------------------------------------------------------------------------
# Banner signature patterns
# Each entry: (regex_pattern, service_name, version_group_index_or_None)
# ---------------------------------------------------------------------------

_SIGNATURES: List[Tuple[re.Pattern, str, Optional[int]]] = [
    # SSH  — "SSH-2.0-OpenSSH_8.9"
    (re.compile(r"^SSH-\d+\.\d+-(\S+)", re.IGNORECASE), "ssh", 1),
    # FTP  — "220 ... FTP ..."
    (re.compile(r"^220[- ].*vsFTPd\s+([\d.]+)", re.IGNORECASE), "ftp", 1),
    (re.compile(r"^220[- ].*FileZilla Server\s+([\d.]+)", re.IGNORECASE), "ftp", 1),
    (re.compile(r"^220[- ].*FTP", re.IGNORECASE), "ftp", None),
    # SMTP — "220 ... ESMTP ..."
    (re.compile(r"^220[- ].*Postfix", re.IGNORECASE), "smtp", None),
    (re.compile(r"^220[- ].*Exim\s+([\d.]+)", re.IGNORECASE), "smtp", 1),
    (re.compile(r"^220[- ].*ESMTP", re.IGNORECASE), "smtp", None),
    # HTTP
    (re.compile(r"^HTTP/\d\.\d \d+", re.IGNORECASE), "http", None),
    (re.compile(r"Server:\s+Apache/([\d.]+)", re.IGNORECASE), "http", 1),
    (re.compile(r"Server:\s+nginx/([\d.]+)", re.IGNORECASE), "http", 1),
    (re.compile(r"Server:\s+Microsoft-IIS/([\d.]+)", re.IGNORECASE), "http", 1),
    # POP3
    (re.compile(r"^\+OK.*POP3", re.IGNORECASE), "pop3", None),
    # IMAP
    (re.compile(r"^\* OK.*IMAP", re.IGNORECASE), "imap", None),
    # MySQL
    (re.compile(r"mysql", re.IGNORECASE), "mysql", None),
    # PostgreSQL — sends binary greeting
    (re.compile(r"PostgreSQL", re.IGNORECASE), "postgresql", None),
    # Telnet — often no banner, but some systems send OS info
    (re.compile(r"login:", re.IGNORECASE), "telnet", None),
    # RDP / MS-RDP
    (re.compile(r"rdp|remote desktop", re.IGNORECASE), "rdp", None),
    # Redis
    (re.compile(r"^\-ERR.*Redis|PONG", re.IGNORECASE), "redis", None),
    # Memcached
    (re.compile(r"^VERSION\s+([\d.]+)", re.IGNORECASE), "memcached", 1),
    # MongoDB
    (re.compile(r"MongoDB", re.IGNORECASE), "mongodb", None),
    # Elasticsearch
    (re.compile(r"elasticsearch", re.IGNORECASE), "elasticsearch", None),
]


class ServiceDetector:
    """Detect service name and version from port number and/or banner.

    Args:
        services_db: Path to common_services.json.  Defaults to the bundled
                     data/common_services.json.
    """

    def __init__(self, services_db: Optional[Path] = None) -> None:
        self._db: Dict[str, str] = {}
        db_path = services_db or _SERVICES_JSON
        self._load_db(db_path)

    def detect(self, port: int, banner: str = "", protocol: str = "tcp") -> ServiceInfo:
        """Identify the service running on *port*.

        Detection logic:
          1. Try banner signature matching (HIGH confidence).
          2. Fall back to port-number lookup (MEDIUM confidence).
          3. Return empty ServiceInfo with LOW confidence if unknown.

        Args:
            port:     Port number.
            banner:   Optional banner text (empty string if not grabbed).
            protocol: "tcp" or "udp".

        Returns:
            ServiceInfo with best available information.
        """
        if banner:
            info = self._match_banner(banner)
            if info:
                return info

        # Port-number lookup
        db_key = f"{protocol}/{port}"
        service_name = self._db.get(db_key, "")
        if service_name:
            return ServiceInfo(
                name=service_name,
                confidence=Confidence.MEDIUM,
                details=f"Port {port}/{protocol} well-known",
            )

        return ServiceInfo(name="unknown", confidence=Confidence.LOW)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _match_banner(self, banner: str) -> Optional[ServiceInfo]:
        """Try every signature pattern against *banner*.

        Returns the first matching ServiceInfo or None.
        """
        for pattern, service, version_group in _SIGNATURES:
            match = pattern.search(banner)
            if match:
                version = ""
                if version_group is not None:
                    try:
                        version = match.group(version_group)
                    except IndexError:
                        pass
                return ServiceInfo(
                    name=service,
                    version=version,
                    confidence=Confidence.HIGH,
                    details=f"Banner matched /{pattern.pattern}/",
                )
        return None

    def _load_db(self, path: Path) -> None:
        """Load the common_services.json into a dict keyed by 'proto/port'."""
        if not path.exists():
            logger.warning("Services DB not found at %s — port names unavailable.", path)
            return
        try:
            with open(path, "r", encoding="utf-8") as fh:
                raw: Dict[str, dict] = json.load(fh)
            for entry in raw.values():
                # Each entry: {"port": 22, "protocol": "tcp", "name": "ssh", ...}
                p = str(entry.get("port", ""))
                proto = str(entry.get("protocol", "tcp")).lower()
                name = str(entry.get("name", ""))
                if p and name:
                    self._db[f"{proto}/{p}"] = name
            logger.debug("Loaded %d service definitions.", len(self._db))
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            logger.error("Failed to parse services DB: %s", exc)
