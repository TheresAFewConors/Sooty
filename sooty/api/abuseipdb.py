"""AbuseIPDB API Integration"""

from typing import Optional, Dict, Any
from sooty.api.base import BaseAPIClient
from sooty.exceptions import ValidationError
from sooty.logger import get_logger

logger = get_logger(__name__)


class AbuseIPDBClient(BaseAPIClient):
    """AbuseIPDB API client"""

    BASE_URL = "https://api.abuseipdb.com/api/v2"

    def __init__(self, api_key: str, **kwargs):
        if not api_key:
            raise ValidationError("AbuseIPDB API key is required")
        super().__init__(api_key=api_key, **kwargs)

    def validate_api_key(self) -> bool:
        """Test API key validity"""
        try:
            self.check_ip("8.8.8.8")  # Google DNS - should be clean
            return True
        except Exception:
            return False

    def _get_headers(self) -> Dict[str, str]:
        """Get headers with API key"""
        headers = super()._get_headers()
        headers["Key"] = self.api_key
        headers["Accept"] = "application/json"
        return headers

    def check_ip(
        self,
        ip_address: str,
        max_age_days: int = 90,
        verbose: bool = False,
    ) -> Dict[str, Any]:
        """
        Check IP reputation.

        Args:
            ip_address: IP to check
            max_age_days: Maximum days since last report
            verbose: Include full report history

        Returns:
            Reputation data
        """
        if not ip_address:
            raise ValidationError("IP address cannot be empty")

        logger.info(f"Checking IP with AbuseIPDB: {ip_address}")

        endpoint = f"{self.BASE_URL}/check"
        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": max_age_days,
            "verbose": verbose,
        }

        return self.get(endpoint, params=params, operation="AbuseIPDB IP check")

    def report_ip(
        self,
        ip_address: str,
        categories: str,
        comment: str,
    ) -> Dict[str, Any]:
        """
        Report abusive IP.

        Args:
            ip_address: IP to report
            categories: Comma-separated category IDs
            comment: Abuse details

        Returns:
            Report confirmation
        """
        if not ip_address or not comment:
            raise ValidationError("IP address and comment are required")

        logger.info(f"Reporting IP to AbuseIPDB: {ip_address}")

        endpoint = f"{self.BASE_URL}/report"
        data = {
            "ip": ip_address,
            "categories": categories,
            "comment": comment,
        }

        return self.post(
            endpoint,
            data=data,
            operation="AbuseIPDB IP report"
        )

    def get_blacklist(
        self,
        confidence_minimum: int = 90,
        limit: int = 10000,
    ) -> Dict[str, Any]:
        """
        Get blacklist of known abusive IPs.

        Args:
            confidence_minimum: Minimum confidence score (0-100)
            limit: Maximum number of results

        Returns:
            List of blacklisted IPs
        """
        logger.info(f"Fetching AbuseIPDB blacklist (confidence >= {confidence_minimum})")

        endpoint = f"{self.BASE_URL}/blacklist"
        params = {
            "confidenceMinimum": confidence_minimum,
            "limit": limit,
        }

        return self.get(endpoint, params=params, operation="AbuseIPDB blacklist fetch")
