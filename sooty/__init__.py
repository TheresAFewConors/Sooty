"""
Sooty - SOC Analyst CLI Workflow Tool

A comprehensive toolkit for SOC analysts to automate and speed up their workflow.
Provides tools and utilities for analyzing emails, URLs, IPs, hashes, and more.
"""

__version__ = "2.0.0"

from sooty.exceptions import (
    SootyError,
    APIError,
    APIConnectionError,
    APIAuthenticationError,
    APIRateLimitError,
    APITimeoutError,
    ValidationError,
    ConfigurationError,
    NetworkError,
)

from sooty.logger import get_logger, setup_logging, set_log_level

__all__ = [
    # Version
    "__version__",
    # Exceptions
    "SootyError",
    "APIError",
    "APIConnectionError",
    "APIAuthenticationError",
    "APIRateLimitError",
    "APITimeoutError",
    "ValidationError",
    "ConfigurationError",
    "NetworkError",
    # Logger
    "get_logger",
    "setup_logging",
    "set_log_level",
]
