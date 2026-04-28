"""
core/tcp_scanner.py — TCP port scanning (connect-scan and optional SYN scan).

TCP HANDSHAKE PRIMER
--------------------
A standard TCP connection goes through three steps (the "three-way handshake"):

  Client  ──SYN──►  Server     (I want to connect)
  Client  ◄─SYN/ACK─  Server   (OK, I accept)
  Client  ──ACK──►  Server     (Great, connection established)

Connect scan (what we use by default):
  We let the OS complete the full handshake.  If it succeeds the port is OPEN.
  If the server replies with RST the port is CLOSED.
  If we get no reply within the timeout the port is FILTERED (firewall/drop).

SYN (stealth) scan (requires root / raw-socket privileges):
  We send only the initial SYN packet.
  SYN/ACK back → OPEN  (we then send RST ourselves — never complete the handshake).
  RST back      → CLOSED.
  No reply      → FILTERED.
  Because the OS never sees a completed connection this avoids many application
  logs — hence "stealth".
"""

from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional

from config import DEFAULT_TIMEOUT, MAX_THREADS, DEFAULT_DELAY
from core.models import PortStatus, ScanResult
from utils.logger import get_logger

logger = get_logger(__name__)


class ScanError(Exception):
    """Raised when a scanning operation fails for a non-network reason."""


class TCPScanner:
    """Multi-threaded TCP port scanner.

    Supports:
      * connect scan  — full three-way handshake (no special privileges needed)
      * SYN scan      — raw-socket half-open scan (requires root/admin)

    Args:
        timeout:      Per-connection socket timeout (seconds).
        threads:      Maximum concurrent worker threads.
        delay:        Sleep between probes (seconds, 0 = no rate limiting).
        syn_scan:     If True attempt a SYN scan via scapy (requires root).
    """

    def __init__(
        self,
        timeout: float = DEFAULT_TIMEOUT,
        threads: int = MAX_THREADS,
        delay: float = DEFAULT_DELAY,
        syn_scan: bool = False,
    ) -> None:
        self.timeout = timeout
        self.threads = threads
        self.delay = delay
        self.syn_scan = syn_scan
        self._stop = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(self, hosts: List[str], ports: List[int]) -> List[ScanResult]:
        """Scan *ports* on every host in *hosts* concurrently.

        Args:
            hosts:  List of resolved IP strings (or hostnames).
            ports:  List of integer port numbers to probe.

        Returns:
            List of ScanResult objects, one per (host, port) pair.
        """
        results: List[ScanResult] = []
        tasks = [(h, p) for h in hosts for p in ports]
        logger.info(
            "TCP scan: %d host(s) × %d port(s) = %d tasks, threads=%d",
            len(hosts),
            len(ports),
            len(tasks),
            self.threads,
        )

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_map = {
                executor.submit(self._probe, host, port): (host, port)
                for host, port in tasks
            }
            try:
                for future in as_completed(future_map):
                    if self._stop:
                        executor.shutdown(wait=False)
                        break
                    result = future.result()
                    results.append(result)
            except KeyboardInterrupt:
                logger.warning("KeyboardInterrupt received — stopping scan.")
                self._stop = True
                executor.shutdown(wait=False)

        return results

    def stop(self) -> None:
        """Signal the scanner to stop after the current batch."""
        self._stop = True

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _probe(self, host: str, port: int) -> ScanResult:
        """Probe a single (host, port) and return a ScanResult."""
        if self.delay > 0:
            time.sleep(self.delay)

        if self.syn_scan:
            return self._syn_probe(host, port)
        return self._connect_probe(host, port)

    def _connect_probe(self, host: str, port: int) -> ScanResult:
        """Full-connect TCP probe (no special privileges required).

        We attempt ``socket.connect_ex`` which returns 0 on success.
        Any OS error code means the port is closed or filtered.
        """
        start = time.monotonic()
        status = PortStatus.FILTERED

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                error_code = sock.connect_ex((host, port))
                if error_code == 0:
                    status = PortStatus.OPEN
                else:
                    # ECONNREFUSED → CLOSED; timeout → FILTERED
                    import errno

                    if error_code in (errno.ECONNREFUSED, errno.ECONNRESET):
                        status = PortStatus.CLOSED
                    else:
                        status = PortStatus.FILTERED
        except socket.timeout:
            status = PortStatus.FILTERED
        except OSError as exc:
            logger.debug("OSError probing %s:%d — %s", host, port, exc)
            status = PortStatus.FILTERED

        elapsed = time.monotonic() - start
        logger.debug("TCP connect %s:%d → %s (%.3fs)", host, port, status, elapsed)
        return ScanResult(host=host, port=port, status=status, scan_time=elapsed)

    def _syn_probe(self, host: str, port: int) -> ScanResult:
        """Half-open SYN scan using scapy raw sockets.

        Requires root/administrator privileges.  Falls back to connect scan
        if scapy is unavailable or if privileges are insufficient.
        """
        try:
            # Import lazily so scapy is optional
            from scapy.all import IP, TCP, sr1, conf  # type: ignore

            conf.verb = 0  # suppress scapy output

            start = time.monotonic()
            pkt = IP(dst=host) / TCP(dport=port, flags="S")
            reply = sr1(pkt, timeout=self.timeout)
            elapsed = time.monotonic() - start

            if reply is None:
                status = PortStatus.FILTERED
            elif reply.haslayer(TCP):
                tcp_flags = reply[TCP].flags
                if tcp_flags == 0x12:  # SYN-ACK
                    # Send RST to close the half-open connection
                    from scapy.all import send  # type: ignore

                    send(IP(dst=host) / TCP(dport=port, flags="R"), verbose=0)
                    status = PortStatus.OPEN
                elif tcp_flags == 0x14:  # RST-ACK
                    status = PortStatus.CLOSED
                else:
                    status = PortStatus.FILTERED
            else:
                status = PortStatus.FILTERED

            return ScanResult(host=host, port=port, status=status, scan_time=elapsed)

        except ImportError:
            logger.warning(
                "scapy not installed — falling back to connect scan for %s:%d",
                host,
                port,
            )
            return self._connect_probe(host, port)
        except PermissionError:
            raise ScanError(
                "SYN scan requires root/admin privileges. "
                "Run with sudo or omit the --syn flag."
            )
