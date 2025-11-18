"""DNS Utilities Module"""

from typing import Optional, Dict, Any, List
import socket
import ipaddress
from sooty.exceptions import ValidationError, APIError
from sooty.logger import get_logger

logger = get_logger(__name__)


class DNSClient:
    """DNS utilities wrapper for domain and IP lookups"""

    def __init__(self, timeout: int = 5):
        """
        Initialize DNS client.

        Args:
            timeout: Socket timeout in seconds
        """
        self.timeout = timeout
        socket.setdefaulttimeout(timeout)

    def resolve_hostname(self, hostname: str) -> List[str]:
        """
        Resolve hostname to IP addresses.

        Args:
            hostname: Domain name to resolve

        Returns:
            List of IP addresses

        Raises:
            ValidationError: If hostname is invalid
            APIError: If resolution fails
        """
        if not hostname:
            raise ValidationError("Hostname cannot be empty")

        logger.info(f"Resolving hostname: {hostname}")

        try:
            # Get all addresses for hostname
            addr_info = socket.getaddrinfo(hostname, None)

            # Extract unique IP addresses
            ips = list(set([info[4][0] for info in addr_info]))

            logger.info(f"Resolved {hostname} to {len(ips)} IP(s): {', '.join(ips)}")
            return ips

        except socket.gaierror as e:
            logger.error(f"Failed to resolve {hostname}: {e}")
            raise APIError(f"DNS resolution failed for {hostname}") from e
        except Exception as e:
            logger.error(f"Unexpected error resolving {hostname}: {e}")
            raise APIError(f"DNS error: {str(e)}") from e

    def reverse_lookup(self, ip_address: str) -> str:
        """
        Reverse DNS lookup for IP address.

        Args:
            ip_address: IP address to lookup

        Returns:
            Hostname associated with IP

        Raises:
            ValidationError: If IP is invalid
            APIError: If lookup fails
        """
        if not ip_address:
            raise ValidationError("IP address cannot be empty")

        # Validate IP address format
        try:
            ipaddress.ip_address(ip_address)
        except ValueError as e:
            raise ValidationError(f"Invalid IP address: {ip_address}") from e

        logger.info(f"Reverse DNS lookup for: {ip_address}")

        try:
            hostname, _, _ = socket.gethostbyaddr(ip_address)
            logger.info(f"Resolved {ip_address} to {hostname}")
            return hostname

        except socket.herror as e:
            logger.warning(f"No reverse DNS entry for {ip_address}")
            raise APIError(f"Reverse DNS lookup failed for {ip_address}") from e
        except Exception as e:
            logger.error(f"Unexpected error during reverse lookup: {e}")
            raise APIError(f"DNS error: {str(e)}") from e

    def get_mx_records(self, domain: str) -> List[Dict[str, Any]]:
        """
        Get MX records for domain.

        Note: This is a basic implementation. For production use,
        consider using the dnspython library for full DNS record support.

        Args:
            domain: Domain to query

        Returns:
            List of MX records (requires dnspython for full support)

        Raises:
            ValidationError: If domain is invalid
        """
        if not domain:
            raise ValidationError("Domain cannot be empty")

        logger.warning("MX record lookup requires dnspython library")
        logger.info(f"Attempting basic MX lookup for: {domain}")

        # Basic implementation - would need dnspython for proper MX lookup
        # For now, return empty list with warning
        return []

    def validate_ip(self, ip_string: str) -> bool:
        """
        Validate IP address format.

        Args:
            ip_string: String to validate as IP

        Returns:
            True if valid IPv4 or IPv6 address
        """
        try:
            ipaddress.ip_address(ip_string)
            return True
        except ValueError:
            return False

    def is_private_ip(self, ip_string: str) -> bool:
        """
        Check if IP address is private/internal.

        Args:
            ip_string: IP address to check

        Returns:
            True if private IP address

        Raises:
            ValidationError: If IP is invalid
        """
        try:
            ip_obj = ipaddress.ip_address(ip_string)
            return ip_obj.is_private
        except ValueError as e:
            raise ValidationError(f"Invalid IP address: {ip_string}") from e

    def get_ip_info(self, ip_string: str) -> Dict[str, Any]:
        """
        Get information about an IP address.

        Args:
            ip_string: IP address to analyze

        Returns:
            Dictionary with IP information

        Raises:
            ValidationError: If IP is invalid
        """
        try:
            ip_obj = ipaddress.ip_address(ip_string)

            info = {
                "ip": str(ip_obj),
                "version": ip_obj.version,
                "is_private": ip_obj.is_private,
                "is_global": ip_obj.is_global,
                "is_loopback": ip_obj.is_loopback,
                "is_multicast": ip_obj.is_multicast,
                "is_reserved": ip_obj.is_reserved,
            }

            # Try reverse lookup
            try:
                info["hostname"] = self.reverse_lookup(ip_string)
            except APIError:
                info["hostname"] = None

            logger.info(f"IP info for {ip_string}: {info}")
            return info

        except ValueError as e:
            raise ValidationError(f"Invalid IP address: {ip_string}") from e

    def bulk_resolve(self, hostnames: List[str]) -> Dict[str, List[str]]:
        """
        Resolve multiple hostnames.

        Args:
            hostnames: List of hostnames to resolve

        Returns:
            Dictionary mapping hostname to list of IPs
        """
        results = {}

        for hostname in hostnames:
            try:
                results[hostname] = self.resolve_hostname(hostname)
            except Exception as e:
                logger.error(f"Failed to resolve {hostname}: {e}")
                results[hostname] = []

        return results
