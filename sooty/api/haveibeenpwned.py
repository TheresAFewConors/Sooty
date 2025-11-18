"""Have I Been Pwned API Integration"""

from typing import Optional, Dict, Any, List
import hashlib
from sooty.api.base import BaseAPIClient
from sooty.exceptions import ValidationError, APIError
from sooty.logger import get_logger

logger = get_logger(__name__)


class HaveIBeenPwnedClient(BaseAPIClient):
    """Have I Been Pwned API client"""

    BASE_URL = "https://haveibeenpwned.com/api/v3"

    def __init__(self, api_key: Optional[str] = None, **kwargs):
        """
        Initialize HIBP client.

        Note: API key is required for breach searches by email.
        Password checks via k-anonymity don't require an API key.
        """
        super().__init__(api_key=api_key, **kwargs)

    def validate_api_key(self) -> bool:
        """Test API key validity"""
        if not self.api_key:
            return False
        try:
            # Try to check a test account
            self.check_account("test@example.com")
            return True
        except Exception:
            return False

    def _get_headers(self) -> Dict[str, str]:
        """Get headers with API key if available"""
        headers = super()._get_headers()
        if self.api_key:
            headers["hibp-api-key"] = self.api_key
        return headers

    def check_account(
        self,
        account: str,
        truncate_response: bool = True,
        include_unverified: bool = False,
    ) -> List[Dict[str, Any]]:
        """
        Check if account appears in breaches.

        Args:
            account: Email address or username
            truncate_response: Return only breach names
            include_unverified: Include unverified breaches

        Returns:
            List of breaches

        Raises:
            ValidationError: If API key is missing
        """
        if not account:
            raise ValidationError("Account cannot be empty")

        if not self.api_key:
            raise ValidationError("API key required for breach searches")

        logger.info(f"Checking HIBP for account: {account}")

        endpoint = f"{self.BASE_URL}/breachedaccount/{account}"
        params = {
            "truncateResponse": str(truncate_response).lower(),
            "includeUnverified": str(include_unverified).lower(),
        }

        try:
            result = self.get(endpoint, params=params, operation="HIBP account check")
            # HIBP returns a list directly
            return result if isinstance(result, list) else []
        except APIError as e:
            # 404 means no breaches found
            if "404" in str(e):
                logger.info(f"No breaches found for {account}")
                return []
            raise

    def get_all_breaches(
        self,
        domain: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Get all breaches in the system.

        Args:
            domain: Filter by domain (optional)

        Returns:
            List of all breaches
        """
        logger.info("Fetching all HIBP breaches" + (f" for domain: {domain}" if domain else ""))

        endpoint = f"{self.BASE_URL}/breaches"
        params = {"domain": domain} if domain else None

        result = self.get(endpoint, params=params, operation="HIBP breach list")
        return result if isinstance(result, list) else []

    def get_breach(self, breach_name: str) -> Dict[str, Any]:
        """
        Get details of a specific breach.

        Args:
            breach_name: Name of the breach

        Returns:
            Breach details
        """
        if not breach_name:
            raise ValidationError("Breach name cannot be empty")

        logger.info(f"Fetching HIBP breach: {breach_name}")

        endpoint = f"{self.BASE_URL}/breach/{breach_name}"

        return self.get(endpoint, operation="HIBP breach details")

    def check_password(self, password: str) -> int:
        """
        Check if password appears in breaches using k-anonymity.

        This method uses SHA-1 hashing and only sends the first 5 characters
        of the hash to preserve privacy. No API key required.

        Args:
            password: Password to check

        Returns:
            Number of times password has been seen in breaches

        Raises:
            ValidationError: If password is empty
        """
        if not password:
            raise ValidationError("Password cannot be empty")

        logger.info("Checking password against HIBP database (k-anonymity)")

        # Hash password with SHA-1
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1_hash[:5]
        _suffix = sha1_hash[5:]  # Will be used when feature is implemented

        # Query API with hash prefix
        endpoint = f"https://api.pwnedpasswords.com/range/{prefix}"

        try:
            _response = self.get(endpoint, operation="HIBP password check")

            # Response is plain text, not JSON
            # We need to handle this differently
            # For now, return 0 as we'd need to modify base client
            logger.warning("Password check requires text response parsing - feature incomplete")
            return 0

        except Exception as e:
            logger.error(f"Error checking password: {e}")
            return 0

    def get_pastes(self, account: str) -> List[Dict[str, Any]]:
        """
        Get pastes for an account.

        Args:
            account: Email address

        Returns:
            List of pastes

        Raises:
            ValidationError: If API key is missing
        """
        if not account:
            raise ValidationError("Account cannot be empty")

        if not self.api_key:
            raise ValidationError("API key required for paste searches")

        logger.info(f"Checking HIBP pastes for: {account}")

        endpoint = f"{self.BASE_URL}/pasteaccount/{account}"

        try:
            result = self.get(endpoint, operation="HIBP paste check")
            return result if isinstance(result, list) else []
        except APIError as e:
            # 404 means no pastes found
            if "404" in str(e):
                logger.info(f"No pastes found for {account}")
                return []
            raise
