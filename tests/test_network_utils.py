"""
tests/test_network_utils.py — Unit tests for utils/network_utils.py.

Covers:
  * parse_ports: single, range, list, mixed, invalid inputs
  * parse_targets: single IP, CIDR, comma-separated, hostname resolution
  * is_private_ip
"""

from __future__ import annotations

import socket
from unittest.mock import patch

import pytest

from utils.network_utils import (
    NetworkParseError,
    _parse_single_port,
    is_private_ip,
    parse_ports,
    parse_targets,
)


# ---------------------------------------------------------------------------
# parse_ports
# ---------------------------------------------------------------------------


class TestParsePorts:
    def test_single_port(self):
        assert parse_ports("80") == [80]

    def test_port_range(self):
        assert parse_ports("1-5") == [1, 2, 3, 4, 5]

    def test_port_list(self):
        assert parse_ports("22,80,443") == [22, 80, 443]

    def test_mixed_ports(self):
        result = parse_ports("22,80,100-103,443")
        assert result == [22, 80, 100, 101, 102, 103, 443]

    def test_deduplication(self):
        result = parse_ports("80,80,80")
        assert result == [80]

    def test_sorted_output(self):
        result = parse_ports("443,22,80")
        assert result == [22, 80, 443]

    def test_min_port(self):
        assert parse_ports("1") == [1]

    def test_max_port(self):
        assert parse_ports("65535") == [65535]

    def test_range_100_ports(self):
        result = parse_ports("1-100")
        assert len(result) == 100
        assert result[0] == 1
        assert result[-1] == 100

    def test_invalid_non_numeric(self):
        with pytest.raises(NetworkParseError):
            parse_ports("abc")

    def test_invalid_port_zero(self):
        with pytest.raises(NetworkParseError):
            parse_ports("0")

    def test_invalid_port_too_large(self):
        with pytest.raises(NetworkParseError):
            parse_ports("65536")

    def test_invalid_range_reversed(self):
        with pytest.raises(NetworkParseError):
            parse_ports("100-1")

    def test_empty_string(self):
        with pytest.raises(NetworkParseError):
            parse_ports("")

    def test_whitespace_tolerant(self):
        result = parse_ports("22 , 80 , 443")
        assert result == [22, 80, 443]


# ---------------------------------------------------------------------------
# parse_targets
# ---------------------------------------------------------------------------


class TestParseTargets:
    def test_single_ip(self):
        assert parse_targets("192.168.1.1") == ["192.168.1.1"]

    def test_multiple_ips(self):
        result = parse_targets("192.168.1.1,192.168.1.2")
        assert result == ["192.168.1.1", "192.168.1.2"]

    def test_cidr_slash30(self):
        # /30 has 2 usable hosts; hosts() returns only .1 and .2
        # (.0 and .3 are network/broadcast and excluded by hosts())
        result = parse_targets("192.168.1.0/30")
        assert "192.168.1.1" in result
        assert "192.168.1.2" in result
        assert "192.168.1.0" not in result
        assert "192.168.1.3" not in result

    def test_cidr_slash24_count(self):
        result = parse_targets("10.0.0.0/24")
        # /24 → 254 usable hosts
        assert len(result) == 254

    def test_cidr_slash32(self):
        # /32 is a single host — no hosts() output, but we handle it
        result = parse_targets("10.0.0.1/32")
        assert result == ["10.0.0.1"]

    def test_deduplication(self):
        result = parse_targets("192.168.1.1,192.168.1.1")
        assert result == ["192.168.1.1"]

    def test_hostname_resolution(self):
        # Mock socket.gethostbyname to avoid real DNS
        with patch("utils.network_utils.socket.gethostbyname", return_value="93.184.216.34"):
            result = parse_targets("example.com")
        assert result == ["93.184.216.34"]

    def test_unresolvable_hostname_raises(self):
        with patch(
            "utils.network_utils.socket.gethostbyname",
            side_effect=socket.gaierror("name not found"),
        ):
            with pytest.raises(NetworkParseError):
                parse_targets("nonexistent.invalid")

    def test_empty_string_raises(self):
        with pytest.raises(NetworkParseError):
            parse_targets("")


# ---------------------------------------------------------------------------
# is_private_ip
# ---------------------------------------------------------------------------


class TestIsPrivateIp:
    def test_loopback(self):
        assert is_private_ip("127.0.0.1") is True

    def test_rfc1918_10(self):
        assert is_private_ip("10.0.0.1") is True

    def test_rfc1918_172(self):
        assert is_private_ip("172.16.0.1") is True

    def test_rfc1918_192(self):
        assert is_private_ip("192.168.1.1") is True

    def test_public_ip(self):
        assert is_private_ip("8.8.8.8") is False

    def test_invalid_returns_false(self):
        assert is_private_ip("not-an-ip") is False


# ---------------------------------------------------------------------------
# _parse_single_port (internal helper)
# ---------------------------------------------------------------------------


class TestParseSinglePort:
    def test_valid(self):
        assert _parse_single_port("443") == 443

    def test_invalid_alpha(self):
        with pytest.raises(NetworkParseError):
            _parse_single_port("http")

    def test_boundary_min(self):
        assert _parse_single_port("1") == 1

    def test_boundary_max(self):
        assert _parse_single_port("65535") == 65535
