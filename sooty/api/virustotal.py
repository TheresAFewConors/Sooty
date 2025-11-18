"""VirusTotal API Integration"""

from typing import Optional, Dict, Any
from sooty.api.base import BaseAPIClient
from sooty.exceptions import ValidationError
from sooty.logger import get_logger

logger = get_logger(__name__)


class VirusTotalClient(BaseAPIClient):
    """VirusTotal API v2 client"""

    BASE_URL = "https://www.virustotal.com/vtapi/v2"

    def __init__(self, api_key: str, **kwargs):
        if not api_key:
            raise ValidationError("VirusTotal API key is required")
        super().__init__(api_key=api_key, **kwargs)

    def validate_api_key(self) -> bool:
        """Test API key validity"""
        try:
            # Simple test - try to check a benign hash
            self.check_file_hash("d41d8cd98f00b204e9800998ecf8427e")  # Empty file MD5
            return True
        except Exception:
            return False

    def check_url(self, url: str) -> Dict[str, Any]:
        """
        Check URL reputation.

        Args:
            url: URL to check

        Returns:
            Detection results
        """
        if not url:
            raise ValidationError("URL cannot be empty")

        logger.info(f"Checking URL with VirusTotal: {url[:50]}...")

        endpoint = f"{self.BASE_URL}/url/report"
        params = {
            "apikey": self.api_key,
            "resource": url,
        }

        return self.get(endpoint, params=params, operation="VirusTotal URL check")

    def check_file_hash(self, file_hash: str) -> Dict[str, Any]:
        """
        Check file hash reputation.

        Args:
            file_hash: MD5, SHA-1, or SHA-256 hash

        Returns:
            Detection results
        """
        if not file_hash:
            raise ValidationError("File hash cannot be empty")

        logger.info(f"Checking hash with VirusTotal: {file_hash}")

        endpoint = f"{self.BASE_URL}/file/report"
        params = {
            "apikey": self.api_key,
            "resource": file_hash,
        }

        return self.get(endpoint, params=params, operation="VirusTotal hash check")

    def check_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Check IP address reputation.

        Args:
            ip_address: IP address to check

        Returns:
            Detection results
        """
        if not ip_address:
            raise ValidationError("IP address cannot be empty")

        logger.info(f"Checking IP with VirusTotal: {ip_address}")

        endpoint = f"{self.BASE_URL}/ip-address/report"
        params = {
            "apikey": self.api_key,
            "ip": ip_address,
        }

        return self.get(endpoint, params=params, operation="VirusTotal IP check")

    def check_domain(self, domain: str) -> Dict[str, Any]:
        """
        Check domain reputation.

        Args:
            domain: Domain to check

        Returns:
            Detection results
        """
        if not domain:
            raise ValidationError("Domain cannot be empty")

        logger.info(f"Checking domain with VirusTotal: {domain}")

        endpoint = f"{self.BASE_URL}/domain/report"
        params = {
            "apikey": self.api_key,
            "domain": domain,
        }

        return self.get(endpoint, params=params, operation="VirusTotal domain check")

    def submit_url(self, url: str) -> Dict[str, Any]:
        """
        Submit URL for scanning.

        Args:
            url: URL to scan

        Returns:
            Submission response with scan ID
        """
        if not url:
            raise ValidationError("URL cannot be empty")

        logger.info(f"Submitting URL to VirusTotal: {url[:50]}...")

        endpoint = f"{self.BASE_URL}/url/scan"
        data = {
            "apikey": self.api_key,
            "url": url,
        }

        return self.post(
            endpoint,
            data=data,
            operation="VirusTotal URL submission"
        )
