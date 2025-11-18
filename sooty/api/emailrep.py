"""EmailRep.io API Integration"""

from typing import Optional, Dict, Any
from sooty.api.base import BaseAPIClient
from sooty.exceptions import ValidationError
from sooty.logger import get_logger

logger = get_logger(__name__)


class EmailRepClient(BaseAPIClient):
    """EmailRep.io API client"""

    BASE_URL = "https://emailrep.io"

    def __init__(self, api_key: Optional[str] = None, **kwargs):
        """
        Initialize EmailRep client.

        Note: API key is optional but provides higher rate limits.
        """
        super().__init__(api_key=api_key, **kwargs)

    def validate_api_key(self) -> bool:
        """Test API key validity"""
        if not self.api_key:
            return False
        try:
            # Try a simple query
            self.check_email("test@example.com")
            return True
        except Exception:
            return False

    def _get_headers(self) -> Dict[str, str]:
        """Get headers with API key if available"""
        headers = super()._get_headers()
        if self.api_key:
            headers["Key"] = self.api_key
        return headers

    def check_email(self, email: str) -> Dict[str, Any]:
        """
        Check email reputation.

        Args:
            email: Email address to check

        Returns:
            Reputation data including:
            - reputation: suspicious/low/medium/high
            - suspicious: boolean
            - references: number of breach references
            - details: breach and malicious activity details
        """
        if not email:
            raise ValidationError("Email address cannot be empty")

        # Basic email validation
        if "@" not in email or "." not in email:
            raise ValidationError("Invalid email address format")

        logger.info(f"Checking email reputation: {email}")

        endpoint = f"{self.BASE_URL}/{email}"

        return self.get(endpoint, operation="EmailRep check")

    def report_email(
        self,
        email: str,
        tags: list,
        description: str,
    ) -> Dict[str, Any]:
        """
        Report malicious email.

        Args:
            email: Email address to report
            tags: List of tags (spam, phishing, malware, etc.)
            description: Details about the malicious activity

        Returns:
            Report confirmation
        """
        if not email or not tags or not description:
            raise ValidationError("Email, tags, and description are required")

        if not self.api_key:
            raise ValidationError("API key required for reporting")

        logger.info(f"Reporting email: {email}")

        endpoint = f"{self.BASE_URL}/report"
        payload = {
            "email": email,
            "tags": tags,
            "description": description,
        }

        return self.post(
            endpoint,
            json=payload,
            operation="EmailRep report"
        )
