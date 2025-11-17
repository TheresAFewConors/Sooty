"""PhishTank API Integration"""

from typing import Optional, Dict, Any
import urllib.parse
from sooty.api.base import BaseAPIClient
from sooty.exceptions import ValidationError
from sooty.logger import get_logger

logger = get_logger(__name__)


class PhishTankClient(BaseAPIClient):
    """PhishTank API client"""

    BASE_URL = "https://checkurl.phishtank.com/checkurl/"

    def __init__(self, api_key: Optional[str] = None, app_name: str = "Sooty", **kwargs):
        """
        Initialize PhishTank client.

        Args:
            api_key: PhishTank API key (optional)
            app_name: Application name for user agent
        """
        super().__init__(api_key=api_key, **kwargs)
        self.app_name = app_name

    def validate_api_key(self) -> bool:
        """
        Test API key validity.

        Note: PhishTank doesn't require API keys for basic checks.
        """
        try:
            self.check_url("https://example.com")
            return True
        except Exception:
            return False

    def _get_headers(self) -> Dict[str, str]:
        """Get headers with custom user agent"""
        headers = super()._get_headers()
        headers["User-Agent"] = f"{self.app_name}/Sooty 2.0"
        return headers

    def check_url(self, url: str) -> Dict[str, Any]:
        """
        Check if URL is a known phishing site.

        Args:
            url: URL to check

        Returns:
            PhishTank response with:
            - in_database: boolean
            - phish_id: ID if it's a known phish
            - verified: boolean if verified phish
            - valid: boolean if currently active

        Raises:
            ValidationError: If URL is empty
        """
        if not url:
            raise ValidationError("URL cannot be empty")

        logger.info(f"Checking URL with PhishTank: {url[:50]}...")

        # Encode URL
        encoded_url = urllib.parse.quote(url, safe='')

        # Build POST data
        data = {
            "url": encoded_url,
            "format": "json",
        }

        if self.api_key:
            data["app_key"] = self.api_key

        return self.post(
            self.BASE_URL,
            data=data,
            operation="PhishTank URL check"
        )

    def is_phishing(self, url: str) -> bool:
        """
        Simple boolean check if URL is phishing.

        Args:
            url: URL to check

        Returns:
            True if URL is a verified phishing site
        """
        try:
            result = self.check_url(url)
            results_data = result.get("results", {})

            in_database = results_data.get("in_database", False)
            verified = results_data.get("verified", False)
            valid = results_data.get("valid", False)

            return in_database and verified and valid

        except Exception as e:
            logger.error(f"Error checking phishing status: {e}")
            return False
