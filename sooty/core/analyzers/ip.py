"""
IP Address Analyzer Module

Analyzes IP addresses for reputation, location, and abuse history.
"""

from typing import Dict, Any, Optional
from sooty.api import AbuseIPDBClient, VirusTotalClient, DNSClient
from sooty.exceptions import ValidationError, APIError
from sooty.logger import get_logger

logger = get_logger(__name__)


class IPAnalyzer:
    """Analyze IP addresses using multiple threat intelligence sources"""

    def __init__(self, abuseipdb_key: str, virustotal_key: str):
        """
        Initialize IP analyzer with API keys.

        Args:
            abuseipdb_key: AbuseIPDB API key
            virustotal_key: VirusTotal API key

        Raises:
            ValidationError: If API keys are missing
        """
        if not abuseipdb_key or not virustotal_key:
            raise ValidationError("AbuseIPDB and VirusTotal API keys are required")

        self.abuseipdb = AbuseIPDBClient(api_key=abuseipdb_key)
        self.virustotal = VirusTotalClient(api_key=virustotal_key)
        self.dns = DNSClient()

        logger.info("IP Analyzer initialized")

    def analyze_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Perform comprehensive IP address analysis.

        Args:
            ip_address: IP address to analyze

        Returns:
            Dictionary containing:
            - ip: The IP address
            - is_valid: Whether IP format is valid
            - is_private: Whether IP is private/internal
            - abuse_score: AbuseIPDB confidence score (0-100)
            - total_reports: Number of abuse reports
            - is_malicious: Boolean indicating if IP is malicious
            - hostname: Reverse DNS hostname (if available)
            - virustotal: VirusTotal detection results
            - dns_info: Additional DNS information

        Raises:
            ValidationError: If IP address is invalid
        """
        # Validate IP format
        if not self.dns.validate_ip(ip_address):
            raise ValidationError(f"Invalid IP address format: {ip_address}")

        logger.info(f"Analyzing IP address: {ip_address}")

        result = {
            "ip": ip_address,
            "is_valid": True,
            "is_private": False,
            "abuse_score": 0,
            "total_reports": 0,
            "is_malicious": False,
            "hostname": None,
            "virustotal": None,
            "dns_info": None,
            "errors": []
        }

        # Check if private IP
        try:
            result["is_private"] = self.dns.is_private_ip(ip_address)
            result["dns_info"] = self.dns.get_ip_info(ip_address)
        except Exception as e:
            logger.warning(f"DNS info check failed: {e}")
            result["errors"].append(f"DNS info: {str(e)}")

        # Skip external checks for private IPs
        if result["is_private"]:
            logger.info(f"{ip_address} is a private IP, skipping external checks")
            return result

        # Check AbuseIPDB reputation
        try:
            abuse_data = self.abuseipdb.check_ip(ip_address, max_age_days=90)
            if abuse_data and "data" in abuse_data:
                data = abuse_data["data"]
                result["abuse_score"] = data.get("abuseConfidenceScore", 0)
                result["total_reports"] = data.get("totalReports", 0)
                result["is_malicious"] = result["abuse_score"] > 50

                if result["is_malicious"]:
                    logger.warning(
                        f"IP {ip_address} flagged as malicious! "
                        f"Abuse score: {result['abuse_score']}"
                    )
        except APIError as e:
            logger.error(f"AbuseIPDB check failed: {e}")
            result["errors"].append(f"AbuseIPDB: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error in AbuseIPDB check: {e}")
            result["errors"].append(f"AbuseIPDB: {str(e)}")

        # Check VirusTotal reputation
        try:
            vt_data = self.virustotal.check_ip(ip_address)
            if vt_data:
                result["virustotal"] = {
                    "detected_urls": vt_data.get("detected_urls", []),
                    "detected_downloaded_samples": vt_data.get("detected_downloaded_samples", []),
                    "detected_communicating_samples": vt_data.get("detected_communicating_samples", []),
                }

                # Check if any detections
                if (vt_data.get("detected_urls") or
                        vt_data.get("detected_downloaded_samples") or
                        vt_data.get("detected_communicating_samples")):
                    result["is_malicious"] = True
                    logger.warning(f"IP {ip_address} has VirusTotal detections")
        except APIError as e:
            logger.error(f"VirusTotal check failed: {e}")
            result["errors"].append(f"VirusTotal: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error in VirusTotal check: {e}")
            result["errors"].append(f"VirusTotal: {str(e)}")

        # Perform reverse DNS lookup
        try:
            result["hostname"] = self.dns.reverse_lookup(ip_address)
            logger.debug(f"Reverse DNS for {ip_address}: {result['hostname']}")
        except APIError:
            logger.debug(f"No reverse DNS entry for {ip_address}")
        except Exception as e:
            logger.warning(f"Reverse DNS lookup failed: {e}")

        logger.info(
            f"IP analysis complete for {ip_address}: "
            f"Malicious={result['is_malicious']}, "
            f"Abuse Score={result['abuse_score']}"
        )

        return result

    def get_abuse_score(self, ip_address: str) -> int:
        """
        Get AbuseIPDB confidence score for an IP address.

        Args:
            ip_address: IP address to check

        Returns:
            Abuse confidence score (0-100), or 0 if check fails

        Raises:
            ValidationError: If IP address is invalid
        """
        if not self.dns.validate_ip(ip_address):
            raise ValidationError(f"Invalid IP address format: {ip_address}")

        logger.info(f"Getting abuse score for {ip_address}")

        try:
            result = self.abuseipdb.check_ip(ip_address, max_age_days=90)
            if result and "data" in result:
                score = result["data"].get("abuseConfidenceScore", 0)
                logger.debug(f"Abuse score for {ip_address}: {score}")
                return score
        except Exception as e:
            logger.error(f"Failed to get abuse score for {ip_address}: {e}")

        return 0

    def check_tor_exit_node(self, ip_address: str) -> bool:
        """
        Check if IP is a TOR exit node.

        This is a basic implementation that checks if the IP
        resolves to a known TOR-related hostname pattern.

        Args:
            ip_address: IP address to check

        Returns:
            True if IP appears to be a TOR exit node

        Raises:
            ValidationError: If IP address is invalid
        """
        if not self.dns.validate_ip(ip_address):
            raise ValidationError(f"Invalid IP address format: {ip_address}")

        logger.debug(f"Checking if {ip_address} is a TOR exit node")

        # Check for TOR-related hostname patterns
        try:
            hostname = self.dns.reverse_lookup(ip_address)
            if hostname:
                tor_indicators = [
                    'tor-exit',
                    'tor.exit',
                    'torexit',
                    'exit.tor',
                    'exitnode',
                ]
                hostname_lower = hostname.lower()
                for indicator in tor_indicators:
                    if indicator in hostname_lower:
                        logger.info(f"{ip_address} appears to be a TOR exit node: {hostname}")
                        return True
        except APIError:
            # No reverse DNS entry
            pass
        except Exception as e:
            logger.warning(f"TOR check failed for {ip_address}: {e}")

        # Note: For production use, consider integrating with the official TOR exit node list
        # Available at: https://check.torproject.org/exit-addresses
        logger.debug(f"{ip_address} does not appear to be a TOR exit node")
        return False

    def is_malicious(self, ip_address: str) -> bool:
        """
        Quick check if IP is malicious.

        Args:
            ip_address: IP address to check

        Returns:
            True if IP is flagged as malicious

        Raises:
            ValidationError: If IP address is invalid
        """
        abuse_score = self.get_abuse_score(ip_address)
        return abuse_score > 50

    def close(self):
        """Close all API client sessions"""
        self.abuseipdb.close()
        self.virustotal.close()

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()
