"""
core/udp_scanner.py — UDP port scanning.

UDP BEHAVIOUR PRIMER
--------------------
Unlike TCP, UDP is *connectionless*: there is no handshake.  We send a
datagram to the target port and wait for one of:

  1. A UDP reply        → port is OPEN  (the service responded)
  2. ICMP "Port Unreachable" (type 3, code 3) → port is CLOSED
  3. ICMP "Administratively Prohibited" (type 3, code 13) → FILTERED
  4. No reply at all    → OPEN|FILTERED  (can't tell without more probes)

Because there is no RST equivalent, UDP scanning is inherently slower and
less reliable than TCP scanning.  We mitigate this with service-specific
probes (DNS query, SNMP GetRequest, NTP poll) that elicit replies from
common open UDP services.
"""

from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional

from config import UDP_TIMEOUT, MAX_THREADS, DEFAULT_DELAY
from core.models import PortStatus, ScanResult
from utils.logger import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Service-specific UDP probes
# Each value is the raw bytes to send to that port.
# ---------------------------------------------------------------------------

_UDP_PROBES: Dict[int, bytes] = {
    # DNS standard query for "version.bind" (chaos class) — port 53
    53: (
        b"\xab\xcd"  # transaction ID
        b"\x00\x00"  # flags: standard query
        b"\x00\x01"  # QDCOUNT = 1
        b"\x00\x00\x00\x00\x00\x00"  # ANCOUNT, NSCOUNT, ARCOUNT
        b"\x07version\x04bind\x00"  # QNAME
        b"\x00\x10"  # QTYPE = TXT
        b"\x00\x03"  # QCLASS = CHAOS
    ),
    # SNMP v1 GetRequest OID 1.3.6.1.2.1.1.1.0 (sysDescr) — port 161
    161: (
        b"\x30\x26"  # SEQUENCE
        b"\x02\x01\x00"  # INTEGER version = 0 (v1)
        b"\x04\x06public"  # OCTET STRING community = "public"
        b"\xa0\x19"  # GetRequest PDU
        b"\x02\x01\x00"  # request-id
        b"\x02\x01\x00"  # error-status
        b"\x02\x01\x00"  # error-index
        b"\x30\x0e\x30\x0c"  # variable bindings
        b"\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00"  # OID 1.3.6.1.2.1.1.1.0
        b"\x05\x00"  # NULL value
    ),
    # NTP v4 client request — port 123
    123: b"\x1b" + b"\x00" * 47,
    # NetBIOS Name Service node status request — port 137
    137: (
        b"\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00"
        b"\x00\x21\x00\x01"
    ),
}

_DEFAULT_PROBE = b"\x00"  # generic empty probe


class UDPScanner:
    """Multi-threaded UDP port scanner.

    Args:
        timeout:  Socket receive timeout per probe (seconds).
        threads:  Maximum concurrent worker threads.
        delay:    Inter-probe delay (seconds).
        retries:  How many times to retry before marking as OPEN|FILTERED.
    """

    def __init__(
        self,
        timeout: float = UDP_TIMEOUT,
        threads: int = MAX_THREADS,
        delay: float = DEFAULT_DELAY,
        retries: int = 2,
    ) -> None:
        self.timeout = timeout
        self.threads = threads
        self.delay = delay
        self.retries = retries
        self._stop = False

    def scan(self, hosts: List[str], ports: List[int]) -> List[ScanResult]:
        """Scan *ports* on every host in *hosts* concurrently (UDP).

        Args:
            hosts:  List of IP strings or hostnames.
            ports:  List of integer port numbers.

        Returns:
            List of ScanResult (protocol="udp").
        """
        results: List[ScanResult] = []
        tasks = [(h, p) for h in hosts for p in ports]
        logger.info(
            "UDP scan: %d host(s) × %d port(s) = %d tasks",
            len(hosts),
            len(ports),
            len(tasks),
        )

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_map = {
                executor.submit(self._probe, host, port): (host, port)
                for host, port in tasks
            }
            try:
                for future in as_completed(future_map):
                    if self._stop:
                        executor.shutdown(wait=False, cancel_futures=True)
                        break
                    results.append(future.result())
            except KeyboardInterrupt:
                logger.warning("KeyboardInterrupt — stopping UDP scan.")
                self._stop = True
                executor.shutdown(wait=False, cancel_futures=True)

        return results

    def stop(self) -> None:
        """Signal the scanner to stop."""
        self._stop = True

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _probe(self, host: str, port: int) -> ScanResult:
        """Send a UDP probe and infer port state from the response."""
        if self.delay > 0:
            time.sleep(self.delay)

        probe_data = _UDP_PROBES.get(port, _DEFAULT_PROBE)
        status = PortStatus.OPEN_FILTERED  # default if we get no reply
        start = time.monotonic()

        for attempt in range(self.retries):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(self.timeout)
                    sock.sendto(probe_data, (host, port))
                    try:
                        sock.recvfrom(1024)
                        # If we receive anything back the port is OPEN
                        status = PortStatus.OPEN
                        break
                    except socket.timeout:
                        # No reply: could be open|filtered — try again
                        status = PortStatus.OPEN_FILTERED
            except OSError as exc:
                # ICMP "port unreachable" surfaces as a socket error on some OSes
                err = exc.args[0] if exc.args else 0
                import errno

                if err in (errno.ECONNREFUSED,):
                    status = PortStatus.CLOSED
                    break
                logger.debug("UDP OSError %s:%d attempt %d — %s", host, port, attempt, exc)

        elapsed = time.monotonic() - start
        logger.debug("UDP %s:%d → %s (%.3fs)", host, port, status, elapsed)
        return ScanResult(
            host=host,
            port=port,
            status=status,
            scan_time=elapsed,
            protocol="udp",
        )
