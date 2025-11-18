"""
Custom exceptions for Sooty.

Provides a hierarchy of exception classes for better error handling
throughout the application.
"""


class SootyError(Exception):
    """Base exception class for all Sooty-related errors."""
    pass


class ValidationError(SootyError):
    """Raised when input validation fails."""
    pass


class APIError(SootyError):
    """Raised when an API request fails."""

    def __init__(self, message: str, status_code: int = None, response: str = None):
        """
        Initialize API error.

        Args:
            message: Error message
            status_code: HTTP status code (if applicable)
            response: Response body (if applicable)
        """
        super().__init__(message)
        self.status_code = status_code
        self.response = response

    def __str__(self):
        if self.status_code:
            return f"{super().__str__()} (status: {self.status_code})"
        return super().__str__()


class ConfigurationError(SootyError):
    """Raised when configuration is invalid or missing."""
    pass


class NetworkError(SootyError):
    """Raised when network operations fail."""
    pass
