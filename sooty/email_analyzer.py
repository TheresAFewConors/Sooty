"""
Email Analyzer Module

Analyzes email addresses and domains:
- EmailRep: Email reputation and malicious activity
- HaveIBeenPwned: Breach history and paste site occurrences
- Domain analysis: Age, TLD reputation, suspicious patterns
"""

import re
from typing import Dict, Any, List, Optional

from sooty.api import EmailRepClient, HaveIBeenPwnedClient, DNSClient
from sooty.exceptions import ValidationError, APIError
from sooty.logger import get_logger

logger = get_logger(__name__)


class EmailAnalyzer:
    """
    Analyzer for email addresses.

    Provides comprehensive email analysis including:
    - Email reputation (EmailRep)
    - Breach detection (HaveIBeenPwned)
    - Paste site occurrences
    - Domain reputation analysis
    """

    # Email regex for validation
    EMAIL_REGEX = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

    def __init__(
        self,
        emailrep_key: Optional[str] = None,
        hibp_key: Optional[str] = None,
        timeout: int = 30,
    ):
        """
        Initialize email analyzer.

        Args:
            emailrep_key: EmailRep API key (optional)
            hibp_key: HaveIBeenPwned API key (optional)
            timeout: Request timeout in seconds
        """
        self.emailrep = EmailRepClient(emailrep_key, timeout=timeout) if emailrep_key else None
        self.hibp = HaveIBeenPwnedClient(hibp_key, timeout=timeout) if hibp_key else None
        self.dns = DNSClient(timeout=timeout)

        if not self.emailrep and not self.hibp:
            logger.warning("No API keys provided - limited functionality")

        logger.debug("Email analyzer initialized")

    def _validate_email(self, email: str) -> None:
        """
        Validate email format.

        Args:
            email: Email to validate

        Raises:
            ValidationError: If invalid
        """
        if not email:
            raise ValidationError("Email cannot be empty")

        if not re.match(self.EMAIL_REGEX, email.lower()):
            raise ValidationError(f"Invalid email format: {email}")

    def analyze_email(self, email: str) -> Dict[str, Any]:
        """
        Perform comprehensive email analysis.

        Args:
            email: Email address to analyze

        Returns:
            Dictionary with analysis results:
                - email: The analyzed email
                - reputation: 0-100 reputation score (EmailRep)
                - suspicious: Boolean from EmailRep
                - breaches: List of breaches (HIBP)
                - pastes: List of paste occurrences (HIBP)
                - domain: Domain analysis results
                - errors: List of any errors encountered

        Raises:
            ValidationError: If email is invalid
        """
        self._validate_email(email)

        logger.info(f"Analyzing email: {email}")

        result = {
            "email": email,
            "reputation": None,
            "suspicious": False,
            "breaches": [],
            "pastes": [],
            "domain": None,
            "errors": [],
        }

        # Check EmailRep
        if self.emailrep:
            try:
                emailrep_data = self.emailrep.check_email(email)
                result["reputation"] = emailrep_data.get("reputation")
                result["suspicious"] = emailrep_data.get("suspicious", False)

                if result["suspicious"] or result["reputation"] < 50:
                    logger.warning(
                        f"EmailRep: {email} flagged as suspicious "
                        f"(reputation={result['reputation']})"
                    )
            except APIError as e:
                logger.warning(f"EmailRep check failed: {e}")
                result["errors"].append(f"EmailRep: {str(e)}")

        # Check HaveIBeenPwned
        if self.hibp:
            # Check breaches
            try:
                breaches = self.hibp.check_email(email)
                result["breaches"] = breaches
                if breaches:
                    logger.warning(f"HIBP: {email} found in {len(breaches)} breach(es)")
            except APIError as e:
                logger.warning(f"HIBP breach check failed: {e}")
                result["errors"].append(f"HIBP breaches: {str(e)}")

            # Check pastes
            try:
                pastes = self.hibp.get_pastes(email)
                result["pastes"] = pastes
                if pastes:
                    logger.warning(f"HIBP: {email} found in {len(pastes)} paste(s)")
            except APIError as e:
                logger.debug(f"HIBP paste check failed: {e}")

        # Analyze domain
        try:
            domain_analysis = self.analyze_domain(email)
            result["domain"] = domain_analysis
        except Exception as e:
            logger.warning(f"Domain analysis failed: {e}")
            result["errors"].append(f"Domain: {str(e)}")

        return result

    def analyze_domain(self, email: str) -> Dict[str, Any]:
        """
        Analyze domain from email address.

        Args:
            email: Email address

        Returns:
            Dictionary with domain analysis
        """
        self._validate_email(email)

        domain = email.split('@')[1].lower()
        logger.info(f"Analyzing domain: {domain}")

        result = {
            "domain": domain,
            "mx_records": [],
            "txt_records": [],
            "spf": None,
            "dmarc": None,
        }

        # Get MX records
        try:
            mx_records = self.dns.get_mx_records(domain)
            result["mx_records"] = mx_records
            if mx_records:
                logger.debug(f"Found {len(mx_records)} MX records for {domain}")
        except Exception as e:
            logger.debug(f"MX lookup failed: {e}")

        # Get TXT records (SPF, DKIM, DMARC)
        try:
            txt_records = self.dns.get_txt_records(domain)
            result["txt_records"] = txt_records

            # Extract SPF
            for txt in txt_records:
                if txt.startswith("v=spf1"):
                    result["spf"] = txt
                if txt.startswith("v=DMARC1"):
                    result["dmarc"] = txt

            if result["spf"] or result["dmarc"]:
                logger.debug(f"Found SPF/DMARC records for {domain}")
        except Exception as e:
            logger.debug(f"TXT lookup failed: {e}")

        return result

    def get_breaches(self, email: str) -> List[Dict[str, Any]]:
        """
        Get all breaches containing email.

        Args:
            email: Email address

        Returns:
            List of breach dictionaries
        """
        if not self.hibp:
            raise ValidationError("HaveIBeenPwned API key required")

        self._validate_email(email)

        try:
            return self.hibp.check_email(email)
        except APIError as e:
            logger.error(f"Failed to get breaches: {e}")
            return []

    def get_pastes(self, email: str) -> List[Dict[str, Any]]:
        """
        Get paste site occurrences.

        Args:
            email: Email address

        Returns:
            List of paste entries
        """
        if not self.hibp:
            raise ValidationError("HaveIBeenPwned API key required")

        self._validate_email(email)

        try:
            return self.hibp.get_pastes(email)
        except APIError as e:
            logger.error(f"Failed to get pastes: {e}")
            return []
