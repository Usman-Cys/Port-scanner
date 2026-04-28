"""
tests/test_udp_scanner.py — Unit tests for core/udp_scanner.py.

All socket operations are mocked — no real packets are sent.
"""

from __future__ import annotations

import errno
import socket
from unittest.mock import MagicMock, patch, call

import pytest

from core.models import PortStatus, ScanResult
from core.udp_scanner import UDPScanner


def _make_scanner(**kwargs) -> UDPScanner:
    defaults = {"timeout": 0.1, "threads": 4, "retries": 2}
    defaults.update(kwargs)
    return UDPScanner(**defaults)


class TestUDPProbe:
    def test_open_port_receives_data(self):
        scanner = _make_scanner()
        with patch("socket.socket") as mock_socket_cls:
            mock_sock = MagicMock()
            mock_sock.__enter__ = lambda s: s
            mock_sock.__exit__ = MagicMock(return_value=False)
            mock_sock.recvfrom.return_value = (b"some data", ("192.168.1.1", 53))
            mock_socket_cls.return_value = mock_sock

            result = scanner._probe("192.168.1.1", 53)

        assert result.status == PortStatus.OPEN
        assert result.protocol == "udp"
        assert result.port == 53

    def test_no_reply_is_open_filtered(self):
        scanner = _make_scanner(retries=1)
        with patch("socket.socket") as mock_socket_cls:
            mock_sock = MagicMock()
            mock_sock.__enter__ = lambda s: s
            mock_sock.__exit__ = MagicMock(return_value=False)
            mock_sock.recvfrom.side_effect = socket.timeout
            mock_socket_cls.return_value = mock_sock

            result = scanner._probe("192.168.1.1", 161)

        assert result.status == PortStatus.OPEN_FILTERED

    def test_connection_refused_is_closed(self):
        scanner = _make_scanner(retries=1)
        with patch("socket.socket") as mock_socket_cls:
            mock_sock = MagicMock()
            mock_sock.__enter__ = lambda s: s
            mock_sock.__exit__ = MagicMock(return_value=False)
            mock_sock.recvfrom.side_effect = OSError(errno.ECONNREFUSED, "refused")
            mock_socket_cls.return_value = mock_sock

            result = scanner._probe("192.168.1.1", 9999)

        assert result.status == PortStatus.CLOSED

    def test_scan_returns_results_for_all_hosts_ports(self):
        scanner = _make_scanner()
        with patch.object(scanner, "_probe") as mock_probe:
            mock_probe.side_effect = lambda h, p: ScanResult(
                host=h, port=p, status=PortStatus.OPEN, protocol="udp"
            )
            results = scanner.scan(["10.0.0.1", "10.0.0.2"], [53, 123])

        assert len(results) == 4
        hosts = {r.host for r in results}
        assert hosts == {"10.0.0.1", "10.0.0.2"}
        ports = {r.port for r in results}
        assert ports == {53, 123}

    def test_result_protocol_is_udp(self):
        scanner = _make_scanner()
        with patch("socket.socket") as mock_socket_cls:
            mock_sock = MagicMock()
            mock_sock.__enter__ = lambda s: s
            mock_sock.__exit__ = MagicMock(return_value=False)
            mock_sock.recvfrom.return_value = (b"response", ("1.1.1.1", 53))
            mock_socket_cls.return_value = mock_sock

            result = scanner._probe("1.1.1.1", 53)

        assert result.protocol == "udp"

    def test_stop_method_sets_flag(self):
        scanner = _make_scanner()
        assert scanner._stop is False
        scanner.stop()
        assert scanner._stop is True
