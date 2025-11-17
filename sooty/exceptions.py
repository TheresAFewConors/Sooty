"""
Sooty Exception Classes

Custom exceptions for error handling across the application.
"""


class SootyError(Exception):
    """Base exception class for all Sooty errors"""
    pass


class APIError(SootyError):
    """Base exception for API-related errors"""
    pass


class APIConnectionError(APIError):
    """Raised when unable to connect to an API"""
    pass


class APIAuthenticationError(APIError):
    """Raised when API authentication fails (401/403)"""
    pass


class APIRateLimitError(APIError):
    """Raised when API rate limit is exceeded (429)"""
    pass


class APITimeoutError(APIError):
    """Raised when API request times out"""
    pass


class ValidationError(SootyError):
    """Raised when input validation fails"""
    pass


class ConfigurationError(SootyError):
    """Raised when configuration is missing or invalid"""
    pass
