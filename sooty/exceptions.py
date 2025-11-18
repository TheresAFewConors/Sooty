"""
Sooty Exception Classes

Custom exceptions for error handling across the application.
Provides a hierarchy of exception classes for better error handling
throughout the application.
"""


class SootyError(Exception):
    """Base exception class for all Sooty-related errors."""
    pass


class APIError(SootyError):
    """Base exception for API-related errors."""

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


class APIConnectionError(APIError):
    """Raised when unable to connect to an API."""
    pass


class APIAuthenticationError(APIError):
    """Raised when API authentication fails (401/403)."""
    pass


class APIRateLimitError(APIError):
    """Raised when API rate limit is exceeded (429)."""
    pass


class APITimeoutError(APIError):
    """Raised when API request times out."""
    pass


class ValidationError(SootyError):
    """Raised when input validation fails."""
    pass


class ConfigurationError(SootyError):
    """Raised when configuration is missing or invalid."""
    pass


class NetworkError(SootyError):
    """Raised when network operations fail."""
    pass
