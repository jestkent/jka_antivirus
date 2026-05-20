"""Structured logging: rich handler for console, rotating file handler for persistence."""

from __future__ import annotations

import logging
import logging.handlers
from pathlib import Path

from rich.console import Console
from rich.logging import RichHandler

_console = Console(stderr=True)


def setup_logging(
    log_level: str = "INFO",
    log_dir: Path | None = None,
    max_bytes: int = 10 * 1024 * 1024,
    backup_count: int = 5,
) -> logging.Logger:
    """Configure root logger with a rich console handler and optional rotating file handler.

    Args:
        log_level: Logging level string (DEBUG/INFO/WARNING/ERROR/CRITICAL).
        log_dir: Directory for rotating log files. Pass None to skip file logging.
        max_bytes: Max size per log file before rotation (default 10 MB).
        backup_count: Number of rotated backup files to keep.

    Returns:
        The configured root logger.
    """
    level = logging.getLevelName(log_level.upper())
    root = logging.getLogger()
    root.setLevel(level)

    # Remove any handlers added by earlier calls or third-party imports.
    root.handlers.clear()

    rich_handler = RichHandler(
        console=_console,
        show_time=True,
        show_level=True,
        show_path=True,
        rich_tracebacks=True,
        markup=False,
    )
    rich_handler.setLevel(level)
    root.addHandler(rich_handler)

    if log_dir is not None:
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / "jka_antivirus.log"
        file_formatter = logging.Formatter(
            fmt="%(asctime)s %(levelname)-8s %(name)s %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
        file_handler = logging.handlers.RotatingFileHandler(
            filename=log_file,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        file_handler.setLevel(level)
        file_handler.setFormatter(file_formatter)
        root.addHandler(file_handler)

    return root


def get_logger(name: str) -> logging.Logger:
    """Return a named child logger. Call after setup_logging."""
    return logging.getLogger(name)
