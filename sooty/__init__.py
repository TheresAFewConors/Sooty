"""
Sooty - SOC Analyst Toolkit

A collection of tools and utilities for SOC analysts.
"""

from sooty.email_analyzer import EmailAnalyzer
from sooty.exceptions import (
    SootyError,
    ValidationError,
    APIError,
    ConfigurationError,
    NetworkError,
)
from sooty.logger import get_logger, setup_logging

__version__ = "1.0.0"

__all__ = [
    "EmailAnalyzer",
    "SootyError",
    "ValidationError",
    "APIError",
    "ConfigurationError",
    "NetworkError",
    "get_logger",
    "setup_logging",
]
