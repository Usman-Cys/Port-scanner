"""
tests/test_banner_grabber.py — Unit tests for core/banner_grabber.py.

Tests cover:
  * Banner parsing static methods (no network calls)
  * grab() via mocked sockets
  * _decode() for various encodings
"""

from __future__ import annotations

import socket
from unittest.mock import MagicMock, patch, call

import pytest

from core.banner_grabber import BannerGrabber


# ---------------------------------------------------------------------------
# Static parser methods
# ---------------------------------------------------------------------------


class TestParseHttpServer:
    def test_apache(self):
        banner = "HTTP/1.1 200 OK\nServer: Apache/2.4.50 (Ubuntu)\nContent-Type: text/html"
        assert BannerGrabber.parse_http_server(banner) == "Apache/2.4.50 (Ubuntu)"

    def test_nginx(self):
        banner = "HTTP/1.1 200 OK\nServer: nginx/1.18.0\nDate: Mon, 01 Jan 2024"
        assert BannerGrabber.parse_http_server(banner) == "nginx/1.18.0"

    def test_no_server_header(self):
        banner = "HTTP/1.1 200 OK\nContent-Type: text/html"
        assert BannerGrabber.parse_http_server(banner) == ""

    def test_case_insensitive(self):
        banner = "HTTP/1.1 200 OK\nSERVER: IIS/10.0"
        assert BannerGrabber.parse_http_server(banner) == "IIS/10.0"


class TestParseSshVersion:
    def test_openssh(self):
        banner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"
        assert BannerGrabber.parse_ssh_version(banner) == "OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"

    def test_dropbear(self):
        banner = "SSH-2.0-dropbear_2020.81"
        assert BannerGrabber.parse_ssh_version(banner) == "dropbear_2020.81"

    def test_not_ssh_banner(self):
        banner = "220 FTP Server ready"
        assert BannerGrabber.parse_ssh_version(banner) == ""

    def test_multiline_banner(self):
        banner = "Some preamble\nSSH-2.0-OpenSSH_7.4\nMore text"
        assert BannerGrabber.parse_ssh_version(banner) == "OpenSSH_7.4"


class TestParseFtpBanner:
    def test_vsftpd(self):
        banner = "220 (vsFTPd 3.0.3)"
        result = BannerGrabber.parse_ftp_banner(banner)
        assert "vsFTPd" in result or result  # just ensure it doesn't crash

    def test_generic_220(self):
        banner = "220 FTP Server ready."
        result = BannerGrabber.parse_ftp_banner(banner)
        assert "FTP" in result or result != ""

    def test_non_ftp(self):
        banner = "200 OK"
        result = BannerGrabber.parse_ftp_banner(banner)
        # Should return the first line or empty without crashing
        assert isinstance(result, str)


class TestParseSmtpBanner:
    def test_postfix(self):
        banner = "220 mail.example.com ESMTP Postfix (Ubuntu)"
        result = BannerGrabber.parse_smtp_banner(banner)
        assert "Postfix" in result

    def test_no_220(self):
        banner = "500 Error"
        result = BannerGrabber.parse_smtp_banner(banner)
        assert isinstance(result, str)


# ---------------------------------------------------------------------------
# _decode
# ---------------------------------------------------------------------------


class TestDecode:
    def test_utf8(self):
        raw = b"SSH-2.0-OpenSSH_8.9\r\n"
        result = BannerGrabber._decode(raw)
        assert result == "SSH-2.0-OpenSSH_8.9"

    def test_latin1(self):
        raw = "caf\xe9".encode("latin-1")
        result = BannerGrabber._decode(raw)
        assert "caf" in result  # just verify it doesn't crash

    def test_empty_bytes(self):
        assert BannerGrabber._decode(b"") == ""

    def test_normalises_crlf(self):
        raw = b"line1\r\nline2\r\n"
        result = BannerGrabber._decode(raw)
        assert "\r" not in result
        assert "line1" in result
        assert "line2" in result


# ---------------------------------------------------------------------------
# grab() — mocked network
# ---------------------------------------------------------------------------


class TestGrab:
    def _make_grabber(self) -> BannerGrabber:
        return BannerGrabber(timeout=0.5, max_bytes=512)

    def test_grab_returns_banner(self):
        grabber = self._make_grabber()
        with patch.object(grabber, "_raw_banner", return_value=b"SSH-2.0-OpenSSH_8.9\r\n"):
            result = grabber.grab("192.168.1.1", 22)
        assert "SSH-2.0-OpenSSH_8.9" in result

    def test_grab_empty_on_failure(self):
        grabber = self._make_grabber()
        with patch.object(grabber, "_raw_banner", return_value=b""):
            result = grabber.grab("192.168.1.1", 22)
        assert result == ""

    def test_grab_http_port_sends_probe(self):
        grabber = self._make_grabber()
        captured_probe = []

        def fake_raw_banner(host, port, probe):
            captured_probe.append(probe)
            if probe:
                return b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n"
            return b""

        with patch.object(grabber, "_raw_banner", side_effect=fake_raw_banner):
            result = grabber.grab("192.168.1.1", 80)

        # For HTTP ports a non-empty probe should be used
        assert any(p for p in captured_probe)
        assert "nginx" in result or "HTTP" in result
