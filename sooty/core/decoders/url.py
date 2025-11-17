"""
URL Decoder Module

Implements various URL decoding strategies:
- ProofPoint URL decoding (v1, v2, v3)
- Office 365 SafeLinks decoder
- Generic URL decoder
"""

import re
import urllib.parse
import html
from typing import Optional, List
from sooty.exceptions import ValidationError
from sooty.logger import get_logger

logger = get_logger(__name__)


class URLDecoder:
    """URL decoding utilities"""

    @staticmethod
    def proofpoint_v1(url: str) -> Optional[str]:
        """
        Decode ProofPoint v1 encoded URL.

        Args:
            url: ProofPoint v1 encoded URL

        Returns:
            Decoded URL or None if not a valid v1 URL
        """
        match = re.search(r'u=(.+?)&k=', url)
        if not match:
            return None

        urlencodedurl = match.group(1)
        htmlencodedurl = urllib.parse.unquote(urlencodedurl)
        decoded = html.unescape(htmlencodedurl)
        return re.sub(r"^http://", "", decoded)

    @staticmethod
    def proofpoint_v2(url: str) -> Optional[str]:
        """
        Decode ProofPoint v2 encoded URL.

        Args:
            url: ProofPoint v2 encoded URL

        Returns:
            Decoded URL or None if not a valid v2 URL
        """
        match = re.search(r'u=(.+?)&[dc]=', url)
        if not match:
            return None

        specialencodedurl = match.group(1)
        trans = str.maketrans('-_', '%/')
        urlencodedurl = specialencodedurl.translate(trans)
        htmlencodedurl = urllib.parse.unquote(urlencodedurl)
        decoded = html.unescape(htmlencodedurl)
        return re.sub(r"^http://", "", decoded)

    @staticmethod
    def proofpoint_v3(url: str) -> Optional[str]:
        """
        Decode ProofPoint v3 encoded URL.

        Args:
            url: ProofPoint v3 encoded URL

        Returns:
            Decoded URL or None if not a valid v3 URL
        """
        match = re.search(r'v3/__(?P<url>.+?)__;', url)
        if not match:
            return None

        encoded_url = match.group('url')
        if re.search(r'\*(\*.)?', encoded_url):
            decoded = re.sub(r'\*', '+', encoded_url)
            return decoded
        return encoded_url

    @staticmethod
    def proofpoint(url: str) -> Optional[str]:
        """
        Auto-detect and decode any ProofPoint URL.

        Supports v1, v2, and v3 ProofPoint URL formats.

        Args:
            url: ProofPoint encoded URL

        Returns:
            Decoded URL or None if not a ProofPoint URL
        """
        if 'proofpoint.com/v1/' in url:
            logger.debug("Detected ProofPoint v1 URL")
            return URLDecoder.proofpoint_v1(url)
        elif 'proofpoint.com/v2/' in url or 'proofpoint.com/d/' in url:
            logger.debug("Detected ProofPoint v2 URL")
            return URLDecoder.proofpoint_v2(url)
        elif 'proofpoint.com/v3/' in url or 'urldefense.com/v3/' in url:
            logger.debug("Detected ProofPoint v3 URL")
            return URLDecoder.proofpoint_v3(url)
        return None

    @staticmethod
    def safelinks(url: str) -> Optional[str]:
        """
        Decode Office 365 SafeLinks URL.

        Args:
            url: SafeLinks encoded URL

        Returns:
            Decoded URL or None if not a SafeLinks URL
        """
        if 'safelinks.protection.outlook.com' not in url:
            return None

        logger.debug("Detected Office 365 SafeLinks URL")

        decoded = urllib.parse.unquote(url)
        # Remove SafeLinks wrapper
        decoded = re.sub(
            r'https://[a-z]{3}\d{2}\.safelinks\.protection\.outlook\.com/\?url=',
            '',
            decoded
        )
        # Remove additional parameters
        return decoded.split('&')[0] if '&' in decoded else decoded

    @staticmethod
    def uri_decode(url: str) -> str:
        """
        Generic URI decoding.

        Args:
            url: URL-encoded string

        Returns:
            Decoded URL
        """
        return urllib.parse.unquote(url)

    @staticmethod
    def auto_detect(url: str) -> str:
        """
        Attempt to decode URL, auto-detecting type.

        Tries to detect and decode:
        - ProofPoint URLs (v1, v2, v3)
        - Office 365 SafeLinks
        - Generic URL encoding

        Args:
            url: Potentially encoded URL

        Returns:
            Decoded URL (or original if no encoding detected)

        Raises:
            ValidationError: If URL is empty
        """
        if not url:
            raise ValidationError("URL cannot be empty")

        logger.debug(f"Auto-detecting URL type: {url[:50]}...")

        # Try ProofPoint
        result = URLDecoder.proofpoint(url)
        if result:
            logger.info(f"Decoded ProofPoint URL: {result[:50]}...")
            return result

        # Try SafeLinks
        result = URLDecoder.safelinks(url)
        if result:
            logger.info(f"Decoded SafeLinks URL: {result[:50]}...")
            return result

        # Return generic decode
        decoded = URLDecoder.uri_decode(url)
        if decoded != url:
            logger.debug("Applied generic URI decoding")
        else:
            logger.debug("No encoding detected")

        return decoded

    @staticmethod
    def decode_multiple(urls: List[str]) -> List[str]:
        """
        Decode multiple URLs at once.

        Args:
            urls: List of URLs to decode

        Returns:
            List of decoded URLs
        """
        return [URLDecoder.auto_detect(url) for url in urls if url]

    @staticmethod
    def is_encoded(url: str) -> bool:
        """
        Check if URL appears to be encoded.

        Args:
            url: URL to check

        Returns:
            True if URL appears to be encoded
        """
        # Check for ProofPoint indicators
        if any(x in url for x in ['proofpoint.com', 'urldefense.com']):
            return True

        # Check for SafeLinks indicators
        if 'safelinks.protection.outlook.com' in url:
            return True

        # Check for URL encoding
        if '%' in url and re.search(r'%[0-9A-Fa-f]{2}', url):
            return True

        return False

    @staticmethod
    def sanitize_url(url: str) -> str:
        """
        Sanitize URL for safe display in emails and reports.

        Defangs URLs by replacing:
        - http:// with hxxp://
        - https:// with hxxps://
        - . with [.]

        Args:
            url: URL to sanitize

        Returns:
            Defanged URL safe for display

        Example:
            >>> URLDecoder.sanitize_url("https://malicious.com/evil")
            "hxxps://malicious[.]com/evil"
        """
        if not url:
            return url

        sanitized = url

        # Replace protocol
        sanitized = sanitized.replace("https://", "hxxps://")
        sanitized = sanitized.replace("http://", "hxxp://")

        # Replace dots with [.]
        # Split on :// to avoid replacing dots in the protocol
        if "://" in sanitized:
            protocol, rest = sanitized.split("://", 1)
            rest = rest.replace(".", "[.]")
            sanitized = f"{protocol}://{rest}"
        else:
            sanitized = sanitized.replace(".", "[.]")

        logger.debug(f"Sanitized URL: {url} -> {sanitized}")

        return sanitized
