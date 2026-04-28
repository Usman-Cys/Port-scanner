"""
config.py — Global constants for PyPortScanner.

Centralising every magic number here makes the codebase easier to tune
without hunting through multiple source files.
"""

# ---------------------------------------------------------------------------
# Network / timing
# ---------------------------------------------------------------------------

# Default per-connection socket timeout in seconds
DEFAULT_TIMEOUT: float = 1.0

# Default number of worker threads in the ThreadPoolExecutor
MAX_THREADS: int = 100

# Default inter-probe delay in seconds (0 = no delay)
DEFAULT_DELAY: float = 0.0

# How long to wait for banner data after a TCP connection (seconds)
BANNER_TIMEOUT: float = 2.0

# Maximum banner bytes to read per service
BANNER_MAX_BYTES: int = 1024

# Default UDP probe timeout
UDP_TIMEOUT: float = 2.0

# ---------------------------------------------------------------------------
# Port ranges
# ---------------------------------------------------------------------------

# Ports scanned when no -p flag is supplied ("top 1000" like nmap default)
TOP_PORTS_COUNT: int = 1000

# Absolute port boundaries
MIN_PORT: int = 1
MAX_PORT: int = 65535

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

LOG_FILE: str = "pyportscanner.log"
LOG_MAX_BYTES: int = 5 * 1024 * 1024   # 5 MB per log file
LOG_BACKUP_COUNT: int = 3

# ---------------------------------------------------------------------------
# Misc
# ---------------------------------------------------------------------------

APP_NAME: str = "PyPortScanner"
APP_VERSION: str = "1.0.0"
DISCLAIMER: str = (
    "⚠️  FOR AUTHORIZED SECURITY TESTING AND EDUCATIONAL PURPOSES ONLY.\n"
    "   Scanning networks without explicit permission may be illegal.\n"
    "   The authors accept no liability for misuse of this tool.\n"
)
