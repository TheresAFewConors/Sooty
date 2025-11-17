"""
Sooty Logging Module

Provides centralized logging configuration for the application.
"""

import logging
import sys
from typing import Optional


# Default logging configuration
DEFAULT_LOG_LEVEL = logging.INFO
DEFAULT_LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
DEFAULT_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


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
    logger = logging.getLogger(name)

    # Only configure if not already configured
    if not logger.handlers:
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


def set_log_level(level: int):
    """
    Set global log level for all Sooty loggers.

    Args:
        level: Logging level (e.g., logging.DEBUG, logging.INFO)
    """
    logging.getLogger("sooty").setLevel(level)
    for handler in logging.getLogger("sooty").handlers:
        handler.setLevel(level)
