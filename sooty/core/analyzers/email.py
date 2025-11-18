"""
Email Analyzer Module

Analyzes email addresses and domains for breach history and reputation.
"""

from typing import Dict, Any, List, Optional
import re
from sooty.api import EmailRepClient, HaveIBeenPwnedClient, DNSClient
from sooty.exceptions import ValidationError, APIError
from sooty.logger import get_logger

logger = get_logger(__name__)


class EmailAnalyzer:
    """Analyze email addresses using breach and reputation databases"""

    def __init__(self, emailrep_key: Optional[str], hibp_key: str):
        """
        Initialize email analyzer with API keys.

        Args:
            emailrep_key: EmailRep.io API key (optional, some features work without)
            hibp_key: Have I Been Pwned API key (required)

        Raises:
            ValidationError: If HIBP API key is missing
        """
        if not hibp_key:
            raise ValidationError("Have I Been Pwned API key is required")

        self.emailrep = EmailRepClient(api_key=emailrep_key)
        self.hibp = HaveIBeenPwnedClient(api_key=hibp_key)
        self.dns = DNSClient()

        logger.info("Email Analyzer initialized")

    def _validate_email_format(self, email: str) -> bool:
        """
        Validate email address format.

        Args:
            email: Email address to validate

        Returns:
            True if email format is valid

        Raises:
            ValidationError: If email format is invalid
        """
        if not email:
            raise ValidationError("Email address cannot be empty")

        # Basic email regex pattern
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

        if not re.match(pattern, email):
            raise ValidationError(f"Invalid email address format: {email}")

        return True

    def analyze_email(self, email: str) -> Dict[str, Any]:
        """
        Perform comprehensive email address analysis.

        Args:
            email: Email address to analyze

        Returns:
            Dictionary containing:
            - email: The email address
            - is_valid: Whether email format is valid
            - reputation: EmailRep reputation score (if available)
            - suspicious: Whether flagged as suspicious
            - breaches: List of breaches containing this email
            - breach_count: Number of breaches
            - pastes: List of paste occurrences
            - paste_count: Number of pastes
            - domain: Domain extracted from email
            - domain_reputation: Domain analysis results
            - errors: List of any errors encountered

        Raises:
            ValidationError: If email format is invalid
        """
        # Validate email format
        self._validate_email_format(email)

        logger.info(f"Analyzing email: {email}")

        result = {
            "email": email,
            "is_valid": True,
            "reputation": None,
            "suspicious": False,
            "breaches": [],
            "breach_count": 0,
            "pastes": [],
            "paste_count": 0,
            "domain": None,
            "domain_reputation": None,
            "errors": []
        }

        # Extract domain
        result["domain"] = email.split("@")[1] if "@" in email else None

        # Check EmailRep reputation
        try:
            emailrep_data = self.emailrep.check_email(email)
            if emailrep_data:
                result["reputation"] = emailrep_data.get("reputation")
                result["suspicious"] = emailrep_data.get("suspicious", False)

                if result["suspicious"]:
                    logger.warning(f"Email {email} flagged as suspicious by EmailRep")

        except APIError as e:
            logger.error(f"EmailRep check failed: {e}")
            result["errors"].append(f"EmailRep: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error in EmailRep check: {e}")
            result["errors"].append(f"EmailRep: {str(e)}")

        # Check Have I Been Pwned breaches
        try:
            breaches = self.get_breaches(email)
            result["breaches"] = breaches
            result["breach_count"] = len(breaches)

            if result["breach_count"] > 0:
                logger.warning(f"Email {email} found in {result['breach_count']} breach(es)")

        except APIError as e:
            logger.debug(f"HIBP breach check: {e}")
            # 404 errors are expected for accounts with no breaches
        except Exception as e:
            logger.error(f"Unexpected error in HIBP breach check: {e}")
            result["errors"].append(f"HIBP breaches: {str(e)}")

        # Check Have I Been Pwned pastes
        try:
            pastes = self.get_pastes(email)
            result["pastes"] = pastes
            result["paste_count"] = len(pastes)

            if result["paste_count"] > 0:
                logger.warning(f"Email {email} found in {result['paste_count']} paste(s)")

        except APIError as e:
            logger.debug(f"HIBP paste check: {e}")
            # 404 errors are expected for accounts with no pastes
        except Exception as e:
            logger.error(f"Unexpected error in HIBP paste check: {e}")
            result["errors"].append(f"HIBP pastes: {str(e)}")

        # Analyze domain
        if result["domain"]:
            try:
                result["domain_reputation"] = self.analyze_domain(email)
            except Exception as e:
                logger.error(f"Domain analysis failed: {e}")
                result["errors"].append(f"Domain analysis: {str(e)}")

        logger.info(
            f"Email analysis complete: Breaches={result['breach_count']}, "
            f"Pastes={result['paste_count']}, Suspicious={result['suspicious']}"
        )

        return result

    def get_breaches(self, email: str) -> List[Dict[str, Any]]:
        """
        Get all breaches containing the email address.

        Args:
            email: Email address to check

        Returns:
            List of breach details, each containing:
            - Name: Breach name
            - Title: Breach title
            - Domain: Breached domain
            - BreachDate: Date of breach
            - PwnCount: Number of accounts affected
            - Description: Breach description
            - DataClasses: Types of data compromised

        Raises:
            ValidationError: If email format is invalid
        """
        self._validate_email_format(email)

        logger.info(f"Checking breaches for: {email}")

        try:
            breaches = self.hibp.check_account(email, truncate_response=False)
            logger.debug(f"Found {len(breaches)} breach(es) for {email}")
            return breaches if breaches else []
        except APIError as e:
            # 404 means no breaches found
            if "404" in str(e):
                logger.debug(f"No breaches found for {email}")
                return []
            raise

    def get_pastes(self, email: str) -> List[Dict[str, Any]]:
        """
        Get all paste occurrences for the email address.

        Args:
            email: Email address to check

        Returns:
            List of paste details

        Raises:
            ValidationError: If email format is invalid
        """
        self._validate_email_format(email)

        logger.info(f"Checking pastes for: {email}")

        try:
            pastes = self.hibp.get_pastes(email)
            logger.debug(f"Found {len(pastes)} paste(s) for {email}")
            return pastes if pastes else []
        except APIError as e:
            # 404 means no pastes found
            if "404" in str(e):
                logger.debug(f"No pastes found for {email}")
                return []
            raise

    def analyze_domain(self, email: str) -> Dict[str, Any]:
        """
        Analyze the domain from an email address.

        Args:
            email: Email address (domain will be extracted)

        Returns:
            Dictionary containing:
            - domain: The domain name
            - has_mx_records: Whether MX records exist
            - is_suspicious: Heuristic check for suspicious patterns
            - suspicious_indicators: List of suspicious indicators found

        Raises:
            ValidationError: If email format is invalid
        """
        self._validate_email_format(email)

        domain = email.split("@")[1]

        logger.debug(f"Analyzing domain: {domain}")

        result = {
            "domain": domain,
            "has_mx_records": False,
            "is_suspicious": False,
            "suspicious_indicators": []
        }

        # Check for suspicious patterns
        suspicious_patterns = [
            (r'\d{5,}', "Long number sequence in domain"),
            (r'[-_.]{2,}', "Multiple consecutive special characters"),
            (r'^[^a-z]', "Domain starts with non-letter"),
            (r'(temp|tmp|test|fake|spam)', "Suspicious keyword in domain"),
        ]

        domain_lower = domain.lower()
        for pattern, indicator in suspicious_patterns:
            if re.search(pattern, domain_lower):
                result["suspicious_indicators"].append(indicator)
                result["is_suspicious"] = True

        # Try to get MX records (requires dnspython for full support)
        try:
            mx_records = self.dns.get_mx_records(domain)
            result["has_mx_records"] = len(mx_records) > 0
        except Exception as e:
            logger.debug(f"MX record check failed for {domain}: {e}")

        if result["is_suspicious"]:
            logger.warning(
                f"Domain {domain} has suspicious indicators: "
                f"{', '.join(result['suspicious_indicators'])}"
            )

        return result

    def is_compromised(self, email: str) -> bool:
        """
        Quick check if email has been compromised.

        Args:
            email: Email address to check

        Returns:
            True if email found in any breaches

        Raises:
            ValidationError: If email format is invalid
        """
        breaches = self.get_breaches(email)
        return len(breaches) > 0

    def close(self):
        """Close all API client sessions"""
        self.emailrep.close()
        self.hibp.close()

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()
