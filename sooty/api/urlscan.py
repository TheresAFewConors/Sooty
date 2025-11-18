"""URLScan.io API Integration"""

from typing import Optional, Dict, Any
import time
from sooty.api.base import BaseAPIClient
from sooty.exceptions import ValidationError, APIError
from sooty.logger import get_logger

logger = get_logger(__name__)


class URLScanClient(BaseAPIClient):
    """URLScan.io API client"""

    BASE_URL = "https://urlscan.io/api/v1"

    def __init__(self, api_key: Optional[str] = None, **kwargs):
        """
        Initialize URLScan client.

        Note: API key is optional for searching, but required for submissions.
        """
        super().__init__(api_key=api_key, **kwargs)

    def validate_api_key(self) -> bool:
        """Test API key validity"""
        if not self.api_key:
            return False
        try:
            # Try to submit a scan
            self.submit_url("https://example.com", public=False)
            return True
        except Exception:
            return False

    def _get_headers(self) -> Dict[str, str]:
        """Get headers with API key if available"""
        headers = super()._get_headers()
        if self.api_key:
            headers["API-Key"] = self.api_key
        headers["Content-Type"] = "application/json"
        return headers

    def submit_url(
        self,
        url: str,
        public: bool = True,
        tags: Optional[list] = None,
    ) -> Dict[str, Any]:
        """
        Submit URL for scanning.

        Args:
            url: URL to scan
            public: Make scan results public
            tags: Optional tags for categorization

        Returns:
            Submission response with UUID
        """
        if not url:
            raise ValidationError("URL cannot be empty")

        if not self.api_key:
            raise ValidationError("API key required for URL submission")

        logger.info(f"Submitting URL to URLScan.io: {url[:50]}...")

        endpoint = f"{self.BASE_URL}/scan/"
        payload = {
            "url": url,
            "visibility": "public" if public else "private",
        }

        if tags:
            payload["tags"] = tags

        return self.post(
            endpoint,
            json=payload,
            operation="URLScan URL submission"
        )

    def get_result(self, uuid: str) -> Dict[str, Any]:
        """
        Get scan results by UUID.

        Args:
            uuid: Scan UUID from submission

        Returns:
            Scan results
        """
        if not uuid:
            raise ValidationError("UUID cannot be empty")

        logger.info(f"Fetching URLScan.io results: {uuid}")

        endpoint = f"{self.BASE_URL}/result/{uuid}/"

        return self.get(endpoint, operation="URLScan result fetch")

    def search(
        self,
        query: str,
        size: int = 100,
    ) -> Dict[str, Any]:
        """
        Search URLScan.io database.

        Args:
            query: Search query (domain, IP, etc.)
            size: Number of results to return

        Returns:
            Search results
        """
        if not query:
            raise ValidationError("Search query cannot be empty")

        logger.info(f"Searching URLScan.io: {query}")

        endpoint = f"{self.BASE_URL}/search/"
        params = {
            "q": query,
            "size": size,
        }

        return self.get(endpoint, params=params, operation="URLScan search")

    def submit_and_wait(
        self,
        url: str,
        public: bool = True,
        max_wait: int = 60,
        poll_interval: int = 5,
    ) -> Dict[str, Any]:
        """
        Submit URL and wait for results.

        Args:
            url: URL to scan
            public: Make scan results public
            max_wait: Maximum seconds to wait
            poll_interval: Seconds between result checks

        Returns:
            Complete scan results

        Raises:
            APIError: If scan doesn't complete in time
        """
        # Submit scan
        submission = self.submit_url(url, public=public)
        uuid = submission.get("uuid")

        if not uuid:
            raise APIError("No UUID returned from submission")

        logger.info(f"Waiting for scan completion (UUID: {uuid})...")

        # Poll for results
        elapsed = 0
        while elapsed < max_wait:
            try:
                result = self.get_result(uuid)
                logger.info(f"Scan completed for {url}")
                return result
            except Exception as e:
                if elapsed + poll_interval >= max_wait:
                    raise APIError(f"Scan did not complete within {max_wait}s") from e

                time.sleep(poll_interval)
                elapsed += poll_interval

        raise APIError(f"Scan timeout after {max_wait}s")
