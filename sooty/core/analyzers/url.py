"""
URL Analyzer Module

Analyzes URLs for safety, decodes encoded URLs, checks against threat databases.
"""

from typing import Dict, Any, Optional, Tuple
from sooty.api import VirusTotalClient, URLScanClient, PhishTankClient
from sooty.core.decoders import URLDecoder
from sooty.exceptions import ValidationError, APIError
from sooty.logger import get_logger

logger = get_logger(__name__)


class URLAnalyzer:
    """Analyze URLs using multiple threat intelligence sources"""

    def __init__(
        self,
        virustotal_key: str,
        urlscan_key: Optional[str] = None,
        phishtank_key: Optional[str] = None
    ):
        """
        Initialize URL analyzer with API keys.

        Args:
            virustotal_key: VirusTotal API key (required)
            urlscan_key: URLScan.io API key (optional, needed for submissions)
            phishtank_key: PhishTank API key (optional)

        Raises:
            ValidationError: If VirusTotal API key is missing
        """
        if not virustotal_key:
            raise ValidationError("VirusTotal API key is required")

        self.virustotal = VirusTotalClient(api_key=virustotal_key)
        self.urlscan = URLScanClient(api_key=urlscan_key) if urlscan_key else None
        self.phishtank = PhishTankClient(api_key=phishtank_key)

        logger.info("URL Analyzer initialized")

    def decode_url(self, url: str) -> Tuple[str, str]:
        """
        Decode URL if it's encoded.

        Args:
            url: URL to decode (may be encoded)

        Returns:
            Tuple of (decoded_url, decode_type) where decode_type is:
            - "proofpoint_v1", "proofpoint_v2", "proofpoint_v3"
            - "safelinks"
            - "generic"
            - "none" (if no encoding detected)

        Raises:
            ValidationError: If URL is empty
        """
        if not url:
            raise ValidationError("URL cannot be empty")

        logger.debug(f"Decoding URL: {url[:50]}...")

        # Detect encoding type
        decode_type = "none"

        if "proofpoint.com/v1/" in url:
            decode_type = "proofpoint_v1"
        elif "proofpoint.com/v2/" in url or "proofpoint.com/d/" in url:
            decode_type = "proofpoint_v2"
        elif "proofpoint.com/v3/" in url or "urldefense.com/v3/" in url:
            decode_type = "proofpoint_v3"
        elif "safelinks.protection.outlook.com" in url:
            decode_type = "safelinks"
        elif URLDecoder.is_encoded(url):
            decode_type = "generic"

        # Decode URL
        decoded_url = URLDecoder.auto_detect(url)

        if decoded_url != url:
            logger.info(f"Decoded URL using {decode_type}: {decoded_url[:50]}...")
        else:
            logger.debug("No URL encoding detected")

        return decoded_url, decode_type

    def analyze_url(self, url: str, scan: bool = False) -> Dict[str, Any]:
        """
        Perform comprehensive URL analysis.

        Args:
            url: URL to analyze
            scan: Whether to submit to URLScan for full analysis (requires API key)

        Returns:
            Dictionary containing:
            - original_url: The original input URL
            - decoded_url: Decoded URL (same as original if not encoded)
            - decode_type: Type of encoding detected
            - virustotal_detections: Number of vendors flagging as malicious
            - virustotal_total: Total vendors checked
            - virustotal_permalink: Link to VT results
            - is_phishing: Whether flagged as phishing by PhishTank
            - phishtank_details: PhishTank response details
            - urlscan_verdict: URLScan results (if scan=True)
            - is_malicious: Overall verdict
            - errors: List of any errors encountered

        Raises:
            ValidationError: If URL is empty
        """
        if not url:
            raise ValidationError("URL cannot be empty")

        logger.info(f"Analyzing URL: {url[:50]}...")

        # Decode URL if encoded
        decoded_url, decode_type = self.decode_url(url)

        result = {
            "original_url": url,
            "decoded_url": decoded_url,
            "decode_type": decode_type,
            "virustotal_detections": 0,
            "virustotal_total": 0,
            "virustotal_permalink": None,
            "is_phishing": False,
            "phishtank_details": None,
            "urlscan_verdict": None,
            "is_malicious": False,
            "errors": []
        }

        # Check VirusTotal
        try:
            vt_verdict = self.get_virustotal_verdict(decoded_url)
            result["virustotal_detections"] = vt_verdict.get("detections", 0)
            result["virustotal_total"] = vt_verdict.get("total", 0)
            result["virustotal_permalink"] = vt_verdict.get("permalink")

            if result["virustotal_detections"] > 0:
                result["is_malicious"] = True
                logger.warning(
                    f"URL flagged by {result['virustotal_detections']}/"
                    f"{result['virustotal_total']} VirusTotal vendors"
                )
        except APIError as e:
            logger.error(f"VirusTotal check failed: {e}")
            result["errors"].append(f"VirusTotal: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error in VirusTotal check: {e}")
            result["errors"].append(f"VirusTotal: {str(e)}")

        # Check PhishTank
        try:
            is_phishing = self.is_phishing(decoded_url)
            result["is_phishing"] = is_phishing
            if is_phishing:
                result["is_malicious"] = True
                logger.warning(f"URL flagged as phishing by PhishTank")

            # Get full PhishTank details
            phish_data = self.phishtank.check_url(decoded_url)
            result["phishtank_details"] = phish_data.get("results", {})
        except APIError as e:
            logger.error(f"PhishTank check failed: {e}")
            result["errors"].append(f"PhishTank: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error in PhishTank check: {e}")
            result["errors"].append(f"PhishTank: {str(e)}")

        # Optional URLScan submission
        if scan and self.urlscan:
            try:
                logger.info("Submitting URL to URLScan.io...")
                scan_result = self.urlscan.submit_url(decoded_url, public=False)
                result["urlscan_verdict"] = {
                    "uuid": scan_result.get("uuid"),
                    "api": scan_result.get("api"),
                    "visibility": scan_result.get("visibility"),
                }
                logger.info(f"URLScan submitted: UUID {scan_result.get('uuid')}")
            except APIError as e:
                logger.error(f"URLScan submission failed: {e}")
                result["errors"].append(f"URLScan: {str(e)}")
            except Exception as e:
                logger.error(f"Unexpected error in URLScan: {e}")
                result["errors"].append(f"URLScan: {str(e)}")
        elif scan and not self.urlscan:
            logger.warning("URLScan requested but no API key provided")
            result["errors"].append("URLScan: No API key configured")

        logger.info(
            f"URL analysis complete: Malicious={result['is_malicious']}, "
            f"Phishing={result['is_phishing']}"
        )

        return result

    def is_phishing(self, url: str) -> bool:
        """
        Check if URL is flagged as phishing.

        Args:
            url: URL to check

        Returns:
            True if URL is flagged as phishing

        Raises:
            ValidationError: If URL is empty
        """
        if not url:
            raise ValidationError("URL cannot be empty")

        logger.debug(f"Checking phishing status for: {url[:50]}...")

        try:
            return self.phishtank.is_phishing(url)
        except Exception as e:
            logger.error(f"PhishTank phishing check failed: {e}")
            return False

    def get_virustotal_verdict(self, url: str) -> Dict[str, Any]:
        """
        Get VirusTotal detection verdict for URL.

        Args:
            url: URL to check

        Returns:
            Dictionary containing:
            - detections: Number of vendors flagging as malicious
            - total: Total number of vendors
            - permalink: Link to VirusTotal results
            - positives: List of vendors that flagged the URL
            - scan_date: When the URL was last scanned

        Raises:
            ValidationError: If URL is empty
            APIError: If VirusTotal check fails
        """
        if not url:
            raise ValidationError("URL cannot be empty")

        logger.debug(f"Getting VirusTotal verdict for: {url[:50]}...")

        vt_result = self.virustotal.check_url(url)

        verdict = {
            "detections": 0,
            "total": 0,
            "permalink": None,
            "positives": [],
            "scan_date": None,
        }

        if vt_result:
            verdict["detections"] = vt_result.get("positives", 0)
            verdict["total"] = vt_result.get("total", 0)
            verdict["permalink"] = vt_result.get("permalink")
            verdict["scan_date"] = vt_result.get("scan_date")

            # Extract vendor details
            scans = vt_result.get("scans", {})
            verdict["positives"] = [
                vendor for vendor, details in scans.items()
                if details.get("detected")
            ]

        logger.debug(
            f"VirusTotal verdict: {verdict['detections']}/{verdict['total']} detections"
        )

        return verdict

    def submit_for_scanning(self, url: str, wait: bool = False) -> Dict[str, Any]:
        """
        Submit URL to URLScan.io for scanning.

        Args:
            url: URL to scan
            wait: Whether to wait for scan completion

        Returns:
            Scan submission details or full results if wait=True

        Raises:
            ValidationError: If URL is empty or URLScan not configured
        """
        if not url:
            raise ValidationError("URL cannot be empty")

        if not self.urlscan:
            raise ValidationError("URLScan.io API key not configured")

        logger.info(f"Submitting URL for scanning: {url[:50]}...")

        if wait:
            return self.urlscan.submit_and_wait(url, public=False)
        else:
            return self.urlscan.submit_url(url, public=False)

    def sanitize_url(self, url: str) -> str:
        """
        Sanitize URL for safe display in emails and reports.

        Defangs the URL by replacing protocols and dots to prevent
        accidental clicking in emails and reports.

        Args:
            url: URL to sanitize

        Returns:
            Defanged URL (e.g., hxxps://malicious[.]com/path)

        Example:
            >>> analyzer.sanitize_url("https://malicious.com/evil")
            "hxxps://malicious[.]com/evil"
        """
        return URLDecoder.sanitize_url(url)

    def close(self):
        """Close all API client sessions"""
        self.virustotal.close()
        if self.urlscan:
            self.urlscan.close()
        self.phishtank.close()

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()
