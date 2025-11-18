"""
Sooty Logging Module

Provides centralized logging configuration for the application with support
for both console and file output.
"""

import logging
import sys
from pathlib import Path
from typing import Optional


# Default logging configuration
DEFAULT_LOG_LEVEL = logging.INFO
DEFAULT_LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
DEFAULT_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# Global flag to track if logging has been initialized
_initialized = False


def setup_logging(
    level: str = "INFO",
    log_file: Optional[str] = None,
    console: bool = True
) -> None:
    """
    Configure global logging settings.

    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional path to log file
        console: Whether to output to console
    """
    global _initialized

    # Convert string level to logging constant
    numeric_level = getattr(logging, level.upper(), logging.INFO)

    # Get root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)

    # Remove existing handlers
    root_logger.handlers.clear()

    # Create formatter
    formatter = logging.Formatter(DEFAULT_LOG_FORMAT, DEFAULT_DATE_FORMAT)

    # Add console handler
    if console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(numeric_level)
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)

    # Add file handler if specified
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(numeric_level)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)

    _initialized = True


def get_logger(
    name: str,
    level: Optional[int] = None,
    log_format: Optional[str] = None,
) -> logging.Logger:
    """
    Get a configured logger instance.

    Args:
        name: Logger name (typically __name__)
        level: Logging level (defaults to INFO)
        log_format: Custom log format string

    Returns:
        Configured logger instance
    """
    # Initialize with defaults if not already done
    if not _initialized:
        setup_logging()

    logger = logging.getLogger(name)

    # Only configure if specific settings are requested and no handlers exist
    if (level or log_format) and not logger.handlers:
        # Set level
        logger.setLevel(level or DEFAULT_LOG_LEVEL)

        # Create console handler
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(level or DEFAULT_LOG_LEVEL)

        # Create formatter
        formatter = logging.Formatter(
            log_format or DEFAULT_LOG_FORMAT,
            datefmt=DEFAULT_DATE_FORMAT,
        )
        handler.setFormatter(formatter)

        # Add handler to logger
        logger.addHandler(handler)

    return logger


def set_log_level(level: int) -> None:
    """
    Set global log level for all Sooty loggers.

    Args:
        level: Logging level (e.g., logging.DEBUG, logging.INFO)
    """
    logging.getLogger("sooty").setLevel(level)
    for handler in logging.getLogger("sooty").handlers:
        handler.setLevel(level)
