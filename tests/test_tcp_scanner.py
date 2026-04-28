"""
tests/test_tcp_scanner.py — Unit tests for core/tcp_scanner.py.

All network calls are mocked so no real connections are made.
"""

from __future__ import annotations

import errno
import socket
from unittest.mock import MagicMock, patch

import pytest

from core.models import PortStatus, ScanResult
from core.tcp_scanner import TCPScanner


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _make_scanner(**kwargs) -> TCPScanner:
    return TCPScanner(timeout=0.1, threads=4, **kwargs)


# ---------------------------------------------------------------------------
# _connect_probe
# ---------------------------------------------------------------------------


class TestConnectProbe:
    def test_open_port(self):
        scanner = _make_scanner()
        with patch("socket.socket") as mock_socket_cls:
            mock_sock = MagicMock()
            mock_sock.__enter__ = lambda s: s
            mock_sock.__exit__ = MagicMock(return_value=False)
            mock_sock.connect_ex.return_value = 0  # success
            mock_socket_cls.return_value = mock_sock

            result = scanner._connect_probe("192.168.1.1", 80)

        assert result.status == PortStatus.OPEN
        assert result.port == 80
        assert result.host == "192.168.1.1"

    def test_closed_port_connection_refused(self):
        scanner = _make_scanner()
        with patch("socket.socket") as mock_socket_cls:
            mock_sock = MagicMock()
            mock_sock.__enter__ = lambda s: s
            mock_sock.__exit__ = MagicMock(return_value=False)
            mock_sock.connect_ex.return_value = errno.ECONNREFUSED
            mock_socket_cls.return_value = mock_sock

            result = scanner._connect_probe("192.168.1.1", 9999)

        assert result.status == PortStatus.CLOSED

    def test_filtered_port_timeout(self):
        scanner = _make_scanner()
        with patch("socket.socket") as mock_socket_cls:
            mock_sock = MagicMock()
            mock_sock.__enter__ = lambda s: s
            mock_sock.__exit__ = MagicMock(return_value=False)
            mock_sock.connect_ex.side_effect = socket.timeout
            mock_socket_cls.return_value = mock_sock

            result = scanner._connect_probe("192.168.1.1", 8888)

        assert result.status == PortStatus.FILTERED

    def test_result_has_scan_time(self):
        scanner = _make_scanner()
        with patch("socket.socket") as mock_socket_cls:
            mock_sock = MagicMock()
            mock_sock.__enter__ = lambda s: s
            mock_sock.__exit__ = MagicMock(return_value=False)
            mock_sock.connect_ex.return_value = 0
            mock_socket_cls.return_value = mock_sock

            result = scanner._connect_probe("10.0.0.1", 22)

        assert result.scan_time >= 0.0
        assert result.protocol == "tcp"


# ---------------------------------------------------------------------------
# scan (thread pool)
# ---------------------------------------------------------------------------


class TestScan:
    def test_returns_list_of_results(self):
        scanner = _make_scanner()
        with patch.object(scanner, "_connect_probe") as mock_probe:
            mock_probe.side_effect = lambda h, p: ScanResult(
                host=h, port=p, status=PortStatus.OPEN
            )
            results = scanner.scan(["192.168.1.1"], [22, 80, 443])

        assert len(results) == 3
        ports = {r.port for r in results}
        assert ports == {22, 80, 443}

    def test_multiple_hosts(self):
        scanner = _make_scanner()
        with patch.object(scanner, "_connect_probe") as mock_probe:
            mock_probe.side_effect = lambda h, p: ScanResult(
                host=h, port=p, status=PortStatus.OPEN
            )
            results = scanner.scan(["10.0.0.1", "10.0.0.2"], [80])

        hosts = {r.host for r in results}
        assert hosts == {"10.0.0.1", "10.0.0.2"}
        assert len(results) == 2

    def test_keyboard_interrupt_stops_scan(self):
        """Sending stop() should cause the scanner to terminate cleanly."""
        scanner = _make_scanner()
        scanner.stop()  # pre-flag stop
        with patch.object(scanner, "_connect_probe") as mock_probe:
            mock_probe.return_value = ScanResult(
                host="1.1.1.1", port=80, status=PortStatus.OPEN
            )
            # Should not raise, should return whatever partial results exist
            results = scanner.scan(["1.1.1.1"], [80])
        assert isinstance(results, list)


# ---------------------------------------------------------------------------
# ScanResult dataclass
# ---------------------------------------------------------------------------


class TestScanResult:
    def test_defaults(self):
        r = ScanResult(host="127.0.0.1", port=22)
        assert r.status == PortStatus.FILTERED
        assert r.banner == ""
        assert r.service == ""
        assert r.protocol == "tcp"

    def test_custom_values(self):
        r = ScanResult(
            host="10.0.0.1",
            port=443,
            status=PortStatus.OPEN,
            service="https",
            banner="HTTP/1.1 200 OK",
            protocol="tcp",
        )
        assert r.status == PortStatus.OPEN
        assert r.service == "https"
