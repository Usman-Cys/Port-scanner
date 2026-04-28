"""
utils/logger.py — Centralised logging configuration for PyPortScanner.

Features:
  * Console handler (INFO and above, colourised where supported)
  * Rotating file handler (DEBUG and above, max 5 MB × 3 files)
  * One call to ``get_logger(__name__)`` from any module gives a correctly
    configured logger without manual setup.
"""

from __future__ import annotations

import logging
import logging.handlers
import os
from typing import Optional

from config import LOG_FILE, LOG_MAX_BYTES, LOG_BACKUP_COUNT

_configured = False


def _configure_root_logger(log_file: Optional[str] = None, verbose: bool = False) -> None:
    """Set up handlers on the root logger (called once at startup).

    Args:
        log_file: Path to the rotating log file.  Defaults to LOG_FILE.
        verbose:  If True, set console level to DEBUG.
    """
    global _configured
    if _configured:
        return
    _configured = True

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)  # root captures everything; handlers filter

    # ------------------------------------------------------------------
    # Console handler
    # ------------------------------------------------------------------
    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG if verbose else logging.WARNING)
    console.setFormatter(
        logging.Formatter("%(levelname)-8s %(name)s — %(message)s")
    )
    root.addHandler(console)

    # ------------------------------------------------------------------
    # Rotating file handler
    # ------------------------------------------------------------------
    path = log_file or LOG_FILE
    try:
        file_handler = logging.handlers.RotatingFileHandler(
            path,
            maxBytes=LOG_MAX_BYTES,
            backupCount=LOG_BACKUP_COUNT,
            encoding="utf-8",
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s %(levelname)-8s %(name)s — %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        root.addHandler(file_handler)
    except OSError as exc:
        # Don't crash the application if we can't open the log file
        console.setLevel(logging.DEBUG)
        root.warning("Cannot open log file '%s': %s — logging to console only.", path, exc)


def get_logger(name: str) -> logging.Logger:
    """Return a named logger, ensuring the root logger is configured.

    This is the only function callers need to import.

    Args:
        name: Logger name — typically ``__name__`` of the calling module.

    Returns:
        A :class:`logging.Logger` instance.

    Example:
        >>> logger = get_logger(__name__)
        >>> logger.info("Scanning started.")
    """
    _configure_root_logger()
    return logging.getLogger(name)


def set_verbose(verbose: bool = True) -> None:
    """Raise (or lower) the console handler level to DEBUG / WARNING.

    Call this after parsing CLI arguments so that ``-v`` / ``--verbose``
    flags take effect.

    Args:
        verbose: If True, show DEBUG messages on the console.
    """
    root = logging.getLogger()
    for handler in root.handlers:
        if isinstance(handler, logging.StreamHandler) and not isinstance(
            handler, logging.FileHandler
        ):
            handler.setLevel(logging.DEBUG if verbose else logging.WARNING)
