"""
core/banner_grabber.py — Banner grabbing from open TCP ports.

WHY BANNER GRABBING WORKS
--------------------------
Many network services send a greeting string immediately after a TCP
connection is established — before the client has sent anything.  This
"banner" typically includes the service name and version, e.g.:

    SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1
    220 mail.example.com ESMTP Postfix (Ubuntu)
    +OK POP3 server ready

For HTTP we send a minimal HTTP/1.0 HEAD request and parse the Server
header from the response.

Banners are grabbed with a short timeout (default 2 s) to keep scanning
fast.  Unicode decode errors are handled gracefully — raw bytes are
hex-encoded when they can't be decoded as UTF-8.
"""

from __future__ import annotations

import socket
from typing import Dict, Optional

from config import BANNER_TIMEOUT, BANNER_MAX_BYTES
from utils.logger import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Per-service probes that elicit a response for banner grabbing.
# ---------------------------------------------------------------------------

_BANNER_PROBES: Dict[int, bytes] = {
    # HTTP — send a minimal HEAD request
    80: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    443: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    8443: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    8000: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    8888: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
}

# Generic probe: send nothing, just read whatever the service sends first.
_DEFAULT_PROBE: bytes = b""


class BannerGrabber:
    """Grabs banners from open TCP ports.

    Args:
        timeout:   How long to wait for banner data (seconds).
        max_bytes: Maximum bytes to read per banner.
    """

    def __init__(
        self,
        timeout: float = BANNER_TIMEOUT,
        max_bytes: int = BANNER_MAX_BYTES,
    ) -> None:
        self.timeout = timeout
        self.max_bytes = max_bytes

    def grab(self, host: str, port: int) -> str:
        """Connect to *host:port*, optionally send a probe, and read the banner.

        Args:
            host: Target IP or hostname.
            port: Target port number.

        Returns:
            The decoded banner string, or an empty string on failure.
        """
        probe = _BANNER_PROBES.get(port, _DEFAULT_PROBE)
        raw_banner = self._raw_banner(host, port, probe)
        if not raw_banner:
            # For HTTP ports, if the first probe got nothing, try again
            if probe == _DEFAULT_PROBE:
                return ""
            # Try without probe (some services close on unexpected data)
            raw_banner = self._raw_banner(host, port, b"")

        return self._decode(raw_banner)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _raw_banner(self, host: str, port: int, probe: bytes) -> bytes:
        """Low-level: connect, optionally send *probe*, read response bytes."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect((host, port))
                if probe:
                    sock.sendall(probe)
                data = b""
                while True:
                    try:
                        chunk = sock.recv(self.max_bytes - len(data))
                        if not chunk:
                            break
                        data += chunk
                        if len(data) >= self.max_bytes:
                            break
                    except socket.timeout:
                        break
                return data
        except OSError as exc:
            logger.debug("Banner grab failed for %s:%d — %s", host, port, exc)
            return b""

    @staticmethod
    def _decode(raw: bytes) -> str:
        """Decode *raw* bytes to a clean string.

        Tries UTF-8 first, falls back to latin-1, and finally hex-encodes any
        remaining non-printable bytes so the output is always safe to display.
        """
        if not raw:
            return ""
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            try:
                text = raw.decode("latin-1")
            except UnicodeDecodeError:
                text = raw.hex()

        # Normalise line endings and strip leading/trailing whitespace
        return text.replace("\r\n", "\n").replace("\r", "\n").strip()

    # ------------------------------------------------------------------
    # Parsers for common service banners
    # ------------------------------------------------------------------

    @staticmethod
    def parse_http_server(banner: str) -> str:
        """Extract the Server header value from an HTTP response banner.

        Args:
            banner: Raw HTTP response text.

        Returns:
            Server header value, or empty string if not found.

        Example:
            >>> BannerGrabber.parse_http_server("HTTP/1.1 200 OK\\nServer: nginx/1.18.0\\n")
            'nginx/1.18.0'
        """
        for line in banner.splitlines():
            if line.lower().startswith("server:"):
                return line.split(":", 1)[1].strip()
        return ""

    @staticmethod
    def parse_ssh_version(banner: str) -> str:
        """Extract the SSH software version from an SSH banner.

        SSH banners look like: ``SSH-2.0-OpenSSH_8.9``

        Args:
            banner: Raw banner text from port 22.

        Returns:
            Software version string, or empty string.

        Example:
            >>> BannerGrabber.parse_ssh_version("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1")
            'OpenSSH_8.9p1 Ubuntu-3ubuntu0.1'
        """
        for line in banner.splitlines():
            if line.startswith("SSH-"):
                parts = line.split("-", 2)
                if len(parts) >= 3:
                    return parts[2].strip()
        return ""

    @staticmethod
    def parse_ftp_banner(banner: str) -> str:
        """Extract the greeting message from an FTP banner.

        FTP servers start with a 220 greeting, e.g.:
        ``220 FTP Server (vsftpd 3.0.3) ready.``

        Args:
            banner: Raw banner text from port 21.

        Returns:
            Greeting text after the response code, or the full first line.
        """
        for line in banner.splitlines():
            if line.startswith("220"):
                return line[3:].lstrip(" -").strip()
        return banner.splitlines()[0] if banner else ""

    @staticmethod
    def parse_smtp_banner(banner: str) -> str:
        """Extract the greeting from an SMTP banner.

        SMTP banners: ``220 mail.example.com ESMTP Postfix``

        Args:
            banner: Raw banner text from port 25/587/465.

        Returns:
            Greeting message or first line.
        """
        for line in banner.splitlines():
            if line.startswith("220"):
                return line[3:].lstrip(" ").strip()
        return banner.splitlines()[0] if banner else ""
