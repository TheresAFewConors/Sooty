"""
Sooty - SOC Analyst CLI Workflow Tool

A comprehensive toolkit for SOC analysts to automate and speed up their workflow.
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
)

from sooty.logger import get_logger, set_log_level

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
    # Logger
    "get_logger",
    "set_log_level",
]
