"""
API clients for external services.

Provides client classes for:
- EmailRep: Email reputation service
- HaveIBeenPwned: Breach and paste detection
- DNS: Domain name system lookups
"""

import time
import dns.resolver
import requests
from typing import Dict, Any, List, Optional

from sooty.exceptions import APIError, NetworkError
from sooty.logger import get_logger

logger = get_logger(__name__)


class BaseAPIClient:
    """Base class for API clients with common functionality."""

    def __init__(self, timeout: int = 30):
        """
        Initialize base API client.

        Args:
            timeout: Request timeout in seconds
        """
        self.timeout = timeout
        self.session = requests.Session()

    def _make_request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        retry_count: int = 3,
        retry_delay: float = 1.0,
    ) -> requests.Response:
        """
        Make HTTP request with retry logic.

        Args:
            method: HTTP method (GET, POST, etc.)
            url: Request URL
            headers: Optional headers
            params: Optional query parameters
            json_data: Optional JSON body
            retry_count: Number of retries on failure
            retry_delay: Delay between retries in seconds

        Returns:
            Response object

        Raises:
            APIError: If request fails after retries
            NetworkError: If network error occurs
        """
        last_exception = None

        for attempt in range(retry_count):
            try:
                response = self.session.request(
                    method=method,
                    url=url,
                    headers=headers,
                    params=params,
                    json=json_data,
                    timeout=self.timeout,
                )

                # Raise for HTTP errors
                if response.status_code >= 400:
                    if response.status_code == 404:
                        # 404 might be valid (e.g., no breach found)
                        return response
                    elif response.status_code == 429:
                        # Rate limit - wait and retry
                        if attempt < retry_count - 1:
                            wait_time = retry_delay * (2 ** attempt)
                            logger.warning(f"Rate limited, waiting {wait_time}s...")
                            time.sleep(wait_time)
                            continue
                        raise APIError(
                            f"Rate limit exceeded: {url}",
                            status_code=response.status_code,
                            response=response.text,
                        )
                    else:
                        raise APIError(
                            f"HTTP {response.status_code}: {response.text}",
                            status_code=response.status_code,
                            response=response.text,
                        )

                return response

            except requests.exceptions.Timeout as e:
                last_exception = e
                if attempt < retry_count - 1:
                    logger.debug(f"Request timeout, retrying... ({attempt + 1}/{retry_count})")
                    time.sleep(retry_delay)
                    continue
            except requests.exceptions.ConnectionError as e:
                last_exception = e
                if attempt < retry_count - 1:
                    logger.debug(f"Connection error, retrying... ({attempt + 1}/{retry_count})")
                    time.sleep(retry_delay)
                    continue
            except requests.exceptions.RequestException as e:
                raise NetworkError(f"Request failed: {str(e)}")

        # If we get here, all retries failed
        raise NetworkError(f"Request failed after {retry_count} attempts: {str(last_exception)}")


class EmailRepClient(BaseAPIClient):
    """
    Client for EmailRep.io API.

    Provides email reputation checking.
    """

    BASE_URL = "https://emailrep.io"

    def __init__(self, api_key: Optional[str] = None, timeout: int = 30):
        """
        Initialize EmailRep client.

        Args:
            api_key: Optional API key for higher rate limits
            timeout: Request timeout in seconds
        """
        super().__init__(timeout)
        self.api_key = api_key

    def check_email(self, email: str) -> Dict[str, Any]:
        """
        Check email reputation.

        Args:
            email: Email address to check

        Returns:
            Dictionary with reputation data:
                - email: Email address
                - reputation: Reputation score (0-100)
                - suspicious: Boolean flag
                - references: Number of references
                - details: Additional details

        Raises:
            APIError: If API request fails
        """
        url = f"{self.BASE_URL}/{email}"
        headers = {}

        if self.api_key:
            headers["Key"] = self.api_key

        logger.debug(f"Checking email reputation: {email}")

        response = self._make_request("GET", url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            return {
                "email": data.get("email"),
                "reputation": data.get("reputation", {}).get("score", 0) if isinstance(data.get("reputation"), dict) else data.get("reputation", 0),
                "suspicious": data.get("suspicious", False),
                "references": data.get("references", 0),
                "details": data.get("details", {}),
            }
        elif response.status_code == 404:
            # Email not found - return default neutral response
            return {
                "email": email,
                "reputation": 50,
                "suspicious": False,
                "references": 0,
                "details": {},
            }
        else:
            raise APIError(f"EmailRep API error: {response.text}", status_code=response.status_code)


class HaveIBeenPwnedClient(BaseAPIClient):
    """
    Client for HaveIBeenPwned API.

    Provides breach and paste detection.
    """

    BASE_URL = "https://haveibeenpwned.com/api/v3"

    def __init__(self, api_key: str, timeout: int = 30):
        """
        Initialize HIBP client.

        Args:
            api_key: HIBP API key (required)
            timeout: Request timeout in seconds
        """
        super().__init__(timeout)
        self.api_key = api_key

    def _get_headers(self) -> Dict[str, str]:
        """Get headers for HIBP requests."""
        return {
            "hibp-api-key": self.api_key,
            "user-agent": "Sooty-SOC-Analyst-Tool",
        }

    def check_email(self, email: str) -> List[Dict[str, Any]]:
        """
        Check if email appears in known breaches.

        Args:
            email: Email address to check

        Returns:
            List of breach dictionaries, each containing:
                - Name: Breach name
                - Title: Breach title
                - Domain: Affected domain
                - BreachDate: Date of breach
                - PwnCount: Number of accounts affected
                - DataClasses: Types of data compromised

        Raises:
            APIError: If API request fails
        """
        url = f"{self.BASE_URL}/breachedaccount/{email}"
        headers = self._get_headers()

        logger.debug(f"Checking HIBP breaches: {email}")

        response = self._make_request("GET", url, headers=headers)

        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            # No breaches found
            return []
        else:
            raise APIError(f"HIBP API error: {response.text}", status_code=response.status_code)

    def get_pastes(self, email: str) -> List[Dict[str, Any]]:
        """
        Get paste site occurrences for email.

        Args:
            email: Email address to check

        Returns:
            List of paste dictionaries, each containing:
                - Source: Paste source
                - Id: Paste ID
                - Title: Paste title
                - Date: Paste date
                - EmailCount: Number of emails in paste

        Raises:
            APIError: If API request fails
        """
        url = f"{self.BASE_URL}/pasteaccount/{email}"
        headers = self._get_headers()

        logger.debug(f"Checking HIBP pastes: {email}")

        response = self._make_request("GET", url, headers=headers)

        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            # No pastes found
            return []
        else:
            raise APIError(f"HIBP paste API error: {response.text}", status_code=response.status_code)


class DNSClient:
    """
    Client for DNS lookups.

    Provides DNS record queries.
    """

    def __init__(self, timeout: int = 30, nameservers: Optional[List[str]] = None):
        """
        Initialize DNS client.

        Args:
            timeout: Query timeout in seconds
            nameservers: Optional list of nameservers to use
        """
        self.timeout = timeout

        try:
            self.resolver = dns.resolver.Resolver()
        except dns.resolver.NoResolverConfiguration:
            # No resolv.conf available - use default nameservers
            self.resolver = dns.resolver.Resolver(configure=False)
            self.resolver.nameservers = ['8.8.8.8', '8.8.4.4']  # Google DNS
            logger.debug("No system DNS configured, using Google DNS")

        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

        if nameservers:
            self.resolver.nameservers = nameservers

    def get_mx_records(self, domain: str) -> List[str]:
        """
        Get MX records for domain.

        Args:
            domain: Domain name

        Returns:
            List of MX record values

        Raises:
            APIError: If DNS query fails
        """
        try:
            logger.debug(f"Querying MX records: {domain}")
            answers = self.resolver.resolve(domain, "MX")
            return [str(rdata.exchange) for rdata in answers]
        except dns.resolver.NXDOMAIN:
            logger.debug(f"Domain not found: {domain}")
            return []
        except dns.resolver.NoAnswer:
            logger.debug(f"No MX records found: {domain}")
            return []
        except dns.exception.Timeout:
            raise APIError(f"DNS query timeout for {domain}")
        except Exception as e:
            raise APIError(f"DNS query failed for {domain}: {str(e)}")

    def get_txt_records(self, domain: str) -> List[str]:
        """
        Get TXT records for domain.

        Args:
            domain: Domain name

        Returns:
            List of TXT record values

        Raises:
            APIError: If DNS query fails
        """
        try:
            logger.debug(f"Querying TXT records: {domain}")
            answers = self.resolver.resolve(domain, "TXT")
            return [str(rdata).strip('"') for rdata in answers]
        except dns.resolver.NXDOMAIN:
            logger.debug(f"Domain not found: {domain}")
            return []
        except dns.resolver.NoAnswer:
            logger.debug(f"No TXT records found: {domain}")
            return []
        except dns.exception.Timeout:
            raise APIError(f"DNS query timeout for {domain}")
        except Exception as e:
            raise APIError(f"DNS query failed for {domain}: {str(e)}")

    def get_a_records(self, domain: str) -> List[str]:
        """
        Get A records for domain.

        Args:
            domain: Domain name

        Returns:
            List of IP addresses

        Raises:
            APIError: If DNS query fails
        """
        try:
            logger.debug(f"Querying A records: {domain}")
            answers = self.resolver.resolve(domain, "A")
            return [str(rdata) for rdata in answers]
        except dns.resolver.NXDOMAIN:
            logger.debug(f"Domain not found: {domain}")
            return []
        except dns.resolver.NoAnswer:
            logger.debug(f"No A records found: {domain}")
            return []
        except dns.exception.Timeout:
            raise APIError(f"DNS query timeout for {domain}")
        except Exception as e:
            raise APIError(f"DNS query failed for {domain}: {str(e)}")
