"""
Base API Client Module

Provides foundation for all external API integrations with:
- Automatic retries with exponential backoff
- Timeout handling
- Error classification
- Response validation
- Logging
"""

from typing import Optional, Dict, Any
from abc import ABC, abstractmethod
import time
import logging
from datetime import datetime
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from sooty.exceptions import (
    APIError,
    APIConnectionError,
    APIAuthenticationError,
    APIRateLimitError,
    APITimeoutError,
)
from sooty.logger import get_logger

logger = get_logger(__name__)


class BaseAPIClient(ABC):
    """Abstract base class for all API clients"""

    def __init__(
        self,
        api_key: Optional[str] = None,
        timeout: int = 30,
        max_retries: int = 3,
        retry_delay: float = 1.0,
    ):
        """
        Initialize API client.

        Args:
            api_key: API authentication key
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts
            retry_delay: Initial delay between retries in seconds
        """
        self.api_key = api_key
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.session = self._create_session()
        self.last_request_time = None
        self.last_response_status = None

    def _create_session(self) -> requests.Session:
        """Create requests session with retry strategy"""
        session = requests.Session()

        # Configure retry strategy
        retry_strategy = Retry(
            total=self.max_retries,
            backoff_factor=1,  # Exponential backoff
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "PUT", "DELETE"],
        )

        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        return session

    @abstractmethod
    def validate_api_key(self) -> bool:
        """Validate that API key is configured"""
        pass

    def _get_headers(self) -> Dict[str, str]:
        """Get common headers for requests"""
        return {
            "User-Agent": "Sooty/2.0",
        }

    def _handle_response(
        self,
        response: requests.Response,
        operation: str,
    ) -> Dict[str, Any]:
        """
        Handle API response with error classification.

        Args:
            response: Response object from requests
            operation: Description of operation for logging

        Returns:
            Parsed response data

        Raises:
            APIAuthenticationError: 401/403
            APIRateLimitError: 429
            APIError: Other errors
        """
        self.last_response_status = response.status_code

        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            if response.status_code == 401:
                logger.error(f"Authentication failed for {operation}")
                raise APIAuthenticationError(
                    f"Invalid API key for {operation}"
                ) from e
            elif response.status_code == 403:
                logger.error(f"Access denied for {operation}")
                raise APIAuthenticationError(
                    f"Access denied for {operation}"
                ) from e
            elif response.status_code == 429:
                retry_after = response.headers.get("Retry-After", "unknown")
                logger.warning(f"Rate limit exceeded for {operation}")
                raise APIRateLimitError(
                    f"Rate limit exceeded. Retry after {retry_after}s"
                ) from e
            elif response.status_code >= 500:
                logger.error(f"Server error ({response.status_code}) for {operation}")
                raise APIError(f"Server error: {response.status_code}") from e
            else:
                logger.error(f"HTTP error ({response.status_code}) for {operation}")
                raise APIError(f"HTTP error: {response.status_code}") from e
        except requests.exceptions.Timeout as e:
            logger.error(f"Timeout during {operation}")
            raise APITimeoutError(f"Request timeout for {operation}") from e
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection error during {operation}")
            raise APIConnectionError(f"Connection error for {operation}") from e

        try:
            return response.json()
        except ValueError as e:
            logger.error(f"Failed to parse JSON response from {operation}")
            raise APIError(f"Invalid JSON response from {operation}") from e

    def get(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        operation: str = "GET request",
    ) -> Dict[str, Any]:
        """
        Make GET request with error handling.

        Args:
            url: Endpoint URL
            params: Query parameters
            operation: Description of operation for logging

        Returns:
            Parsed JSON response
        """
        try:
            logger.debug(f"GET {url} with params: {params}")
            response = self.session.get(
                url,
                params=params,
                headers=self._get_headers(),
                timeout=self.timeout,
            )
            self.last_request_time = datetime.now()
            return self._handle_response(response, operation)
        except APIError:
            raise
        except Exception as e:
            logger.exception(f"Unexpected error during {operation}")
            raise APIError(f"Unexpected error: {str(e)}") from e

    def post(
        self,
        url: str,
        data: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
        operation: str = "POST request",
    ) -> Dict[str, Any]:
        """
        Make POST request with error handling.

        Args:
            url: Endpoint URL
            data: Form data
            json: JSON body
            operation: Description of operation for logging

        Returns:
            Parsed JSON response
        """
        try:
            logger.debug(f"POST {url}")
            response = self.session.post(
                url,
                data=data,
                json=json,
                headers=self._get_headers(),
                timeout=self.timeout,
            )
            self.last_request_time = datetime.now()
            return self._handle_response(response, operation)
        except APIError:
            raise
        except Exception as e:
            logger.exception(f"Unexpected error during {operation}")
            raise APIError(f"Unexpected error: {str(e)}") from e

    def close(self):
        """Close the session"""
        self.session.close()

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()
