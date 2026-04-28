"""
utils/network_utils.py — IP range parsing and port range parsing.

Supports:
  * Single IP:       "192.168.1.1"
  * Comma-separated: "10.0.0.1,10.0.0.2,10.0.0.3"
  * CIDR notation:   "192.168.1.0/24"
  * Hostname:        "scanme.nmap.org"

  * Single port:   "80"
  * Port list:     "22,80,443"
  * Port range:    "1-1000"
  * Mixed:         "22,80,100-200,443"
"""

from __future__ import annotations

import ipaddress
import socket
from typing import List

from config import MIN_PORT, MAX_PORT
from utils.logger import get_logger

logger = get_logger(__name__)


class NetworkParseError(ValueError):
    """Raised when a target or port string cannot be parsed."""


def parse_targets(target_str: str) -> List[str]:
    """Parse a comma-separated list of targets into a flat list of IP strings.

    Handles:
      * Single IPv4 addresses
      * CIDR subnets (host bits are included — callers receive every host IP)
      * Hostnames (resolved via DNS)
      * Comma-separated combinations of the above

    Args:
        target_str: Raw target string from CLI, e.g. "192.168.1.0/24,10.0.0.1".

    Returns:
        Flat list of unique IPv4 address strings.

    Raises:
        NetworkParseError: If a target cannot be resolved or parsed.

    Example:
        >>> parse_targets("192.168.1.0/30")
        ['192.168.1.0', '192.168.1.1', '192.168.1.2', '192.168.1.3']
    """
    results: List[str] = []
    seen: set = set()

    for token in _split_and_strip(target_str):
        # Try CIDR first
        if "/" in token:
            try:
                network = ipaddress.IPv4Network(token, strict=False)
                for ip in network.hosts():
                    ip_str = str(ip)
                    if ip_str not in seen:
                        seen.add(ip_str)
                        results.append(ip_str)
                # /32 network has no "hosts()" but the address itself is valid
                if not list(network.hosts()):
                    ip_str = str(network.network_address)
                    if ip_str not in seen:
                        seen.add(ip_str)
                        results.append(ip_str)
                continue
            except ValueError:
                pass  # fall through to hostname resolution

        # Try plain IPv4
        try:
            ip = ipaddress.IPv4Address(token)
            ip_str = str(ip)
            if ip_str not in seen:
                seen.add(ip_str)
                results.append(ip_str)
            continue
        except ValueError:
            pass

        # Try hostname resolution
        try:
            resolved = socket.gethostbyname(token)
            if resolved not in seen:
                seen.add(resolved)
                results.append(resolved)
            logger.debug("Resolved hostname %s → %s", token, resolved)
        except socket.gaierror as exc:
            raise NetworkParseError(
                f"Cannot resolve target '{token}': {exc}"
            ) from exc

    if not results:
        raise NetworkParseError(f"No valid targets found in '{target_str}'.")

    return results


def parse_ports(port_str: str) -> List[int]:
    """Parse a port specification string into a sorted list of port integers.

    Supports:
      * Single port:  "80"
      * Range:        "1-1024"
      * List:         "22,80,443"
      * Mixed:        "22,80,100-200,443"

    Args:
        port_str: Raw port string from CLI.

    Returns:
        Sorted list of unique port integers in [1, 65535].

    Raises:
        NetworkParseError: If any token is not a valid port or range.

    Example:
        >>> parse_ports("1-3,5")
        [1, 2, 3, 5]
    """
    ports: set = set()

    for token in _split_and_strip(port_str):
        if "-" in token:
            parts = token.split("-", 1)
            if len(parts) != 2:
                raise NetworkParseError(f"Invalid port range: '{token}'")
            start, end = _parse_single_port(parts[0]), _parse_single_port(parts[1])
            if start > end:
                raise NetworkParseError(
                    f"Port range start ({start}) must be ≤ end ({end})."
                )
            ports.update(range(start, end + 1))
        else:
            ports.add(_parse_single_port(token))

    if not ports:
        raise NetworkParseError(f"No valid ports found in '{port_str}'.")

    return sorted(ports)


def is_private_ip(ip_str: str) -> bool:
    """Return True if *ip_str* is an RFC-1918 private address.

    Args:
        ip_str: IPv4 address string.

    Returns:
        True for 10.x, 172.16-31.x, 192.168.x, and loopback addresses.
    """
    try:
        addr = ipaddress.IPv4Address(ip_str)
        return addr.is_private or addr.is_loopback
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _split_and_strip(value: str) -> List[str]:
    """Split *value* by commas and strip whitespace from each token."""
    return [t.strip() for t in value.split(",") if t.strip()]


def _parse_single_port(token: str) -> int:
    """Convert a single port string to an integer, validating range.

    Args:
        token: String representation of a port number.

    Returns:
        Integer port number.

    Raises:
        NetworkParseError: If *token* is not a valid port number.
    """
    try:
        port = int(token)
    except ValueError:
        raise NetworkParseError(f"'{token}' is not a valid port number.")
    if not (MIN_PORT <= port <= MAX_PORT):
        raise NetworkParseError(
            f"Port {port} is out of range [{MIN_PORT}, {MAX_PORT}]."
        )
    return port
