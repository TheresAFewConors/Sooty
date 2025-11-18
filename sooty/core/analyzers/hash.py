"""
Hash Analyzer Module

Analyzes file hashes (MD5, SHA-1, SHA-256) for malware detection.
"""

from typing import Dict, Any, Optional, Tuple
import hashlib
import os
from sooty.api import VirusTotalClient
from sooty.exceptions import ValidationError, APIError
from sooty.logger import get_logger

logger = get_logger(__name__)


class HashAnalyzer:
    """Analyze file hashes using threat intelligence sources"""

    def __init__(self, virustotal_key: str):
        """
        Initialize hash analyzer with API key.

        Args:
            virustotal_key: VirusTotal API key

        Raises:
            ValidationError: If API key is missing
        """
        if not virustotal_key:
            raise ValidationError("VirusTotal API key is required")

        self.virustotal = VirusTotalClient(api_key=virustotal_key)

        logger.info("Hash Analyzer initialized")

    def _determine_hash_type(self, file_hash: str) -> str:
        """
        Determine hash type based on length.

        Args:
            file_hash: Hash string

        Returns:
            Hash type: "md5", "sha1", or "sha256"

        Raises:
            ValidationError: If hash length is invalid
        """
        hash_length = len(file_hash)

        if hash_length == 32:
            return "md5"
        elif hash_length == 40:
            return "sha1"
        elif hash_length == 64:
            return "sha256"
        else:
            raise ValidationError(
                f"Invalid hash length: {hash_length}. "
                "Expected 32 (MD5), 40 (SHA-1), or 64 (SHA-256)"
            )

    def _validate_hash_format(self, file_hash: str) -> bool:
        """
        Validate hash format (hexadecimal).

        Args:
            file_hash: Hash string to validate

        Returns:
            True if valid

        Raises:
            ValidationError: If hash format is invalid
        """
        if not file_hash:
            raise ValidationError("Hash cannot be empty")

        # Check if all characters are hexadecimal
        try:
            int(file_hash, 16)
        except ValueError:
            raise ValidationError(
                f"Invalid hash format: must be hexadecimal. Got: {file_hash}"
            )

        return True

    def analyze_hash(self, file_hash: str) -> Dict[str, Any]:
        """
        Perform comprehensive file hash analysis.

        Args:
            file_hash: File hash (MD5, SHA-1, or SHA-256)

        Returns:
            Dictionary containing:
            - hash: The file hash
            - hash_type: Type of hash (md5, sha1, sha256)
            - is_malicious: Whether hash is flagged as malicious
            - detections: Number of vendors flagging as malicious
            - total_vendors: Total number of vendors checked
            - virustotal_link: Link to VirusTotal report
            - scan_date: When the file was last scanned
            - file_names: Known file names for this hash
            - file_type: Detected file type
            - errors: List of any errors encountered

        Raises:
            ValidationError: If hash format is invalid
        """
        # Validate and determine hash type
        self._validate_hash_format(file_hash)
        hash_type = self._determine_hash_type(file_hash)

        logger.info(f"Analyzing {hash_type.upper()} hash: {file_hash}")

        result = {
            "hash": file_hash,
            "hash_type": hash_type,
            "is_malicious": False,
            "detections": 0,
            "total_vendors": 0,
            "virustotal_link": None,
            "scan_date": None,
            "file_names": [],
            "file_type": None,
            "errors": []
        }

        # Check VirusTotal
        try:
            vt_data = self.virustotal.check_file_hash(file_hash)

            if vt_data:
                # Check response code (1 = found, 0 = not found, -2 = queued)
                response_code = vt_data.get("response_code")

                if response_code == 1:
                    # Hash found in VT database
                    result["detections"] = vt_data.get("positives", 0)
                    result["total_vendors"] = vt_data.get("total", 0)
                    result["is_malicious"] = result["detections"] > 0
                    result["virustotal_link"] = vt_data.get("permalink")
                    result["scan_date"] = vt_data.get("scan_date")

                    # Extract additional information
                    _scans = vt_data.get("scans", {})  # Reserved for future detailed scan analysis
                    result["file_names"] = [vt_data.get("sha256", file_hash)]
                    result["file_type"] = vt_data.get("type")

                    if result["is_malicious"]:
                        logger.warning(
                            f"Hash {file_hash} flagged as malicious! "
                            f"Detections: {result['detections']}/{result['total_vendors']}"
                        )
                    else:
                        logger.info(f"Hash {file_hash} is clean (0 detections)")

                elif response_code == 0:
                    logger.info(f"Hash {file_hash} not found in VirusTotal database")
                    result["errors"].append("Hash not found in VirusTotal")

                elif response_code == -2:
                    logger.info(f"Hash {file_hash} is queued for analysis")
                    result["errors"].append("Hash queued for analysis")

        except APIError as e:
            logger.error(f"VirusTotal check failed: {e}")
            result["errors"].append(f"VirusTotal: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error in VirusTotal check: {e}")
            result["errors"].append(f"VirusTotal: {str(e)}")

        logger.info(
            f"Hash analysis complete: Malicious={result['is_malicious']}, "
            f"Detections={result['detections']}/{result['total_vendors']}"
        )

        return result

    def check_file_hash(self, file_hash: str) -> bool:
        """
        Quick check if hash is malicious.

        Args:
            file_hash: File hash to check

        Returns:
            True if hash is detected as malicious, False otherwise

        Raises:
            ValidationError: If hash format is invalid
        """
        self._validate_hash_format(file_hash)
        _hash_type = self._determine_hash_type(file_hash)  # Validated but not used in quick check

        logger.debug(f"Quick hash check: {file_hash}")

        try:
            vt_data = self.virustotal.check_file_hash(file_hash)

            if vt_data and vt_data.get("response_code") == 1:
                detections = vt_data.get("positives", 0)
                return detections > 0

        except Exception as e:
            logger.error(f"Hash check failed: {e}")

        return False

    def hash_file(self, file_path: str, hash_type: str = "md5") -> str:
        """
        Compute hash of a file.

        Args:
            file_path: Path to file to hash
            hash_type: Type of hash to compute (md5, sha1, sha256)

        Returns:
            Hexadecimal hash string

        Raises:
            ValidationError: If file doesn't exist or hash type is invalid
        """
        if not os.path.exists(file_path):
            raise ValidationError(f"File not found: {file_path}")

        if not os.path.isfile(file_path):
            raise ValidationError(f"Not a file: {file_path}")

        hash_type = hash_type.lower()
        if hash_type not in ["md5", "sha1", "sha256"]:
            raise ValidationError(
                f"Invalid hash type: {hash_type}. "
                "Must be md5, sha1, or sha256"
            )

        logger.info(f"Computing {hash_type.upper()} hash of {file_path}")

        # Select hash algorithm
        if hash_type == "md5":
            hash_obj = hashlib.md5()
        elif hash_type == "sha1":
            hash_obj = hashlib.sha1()
        else:  # sha256
            hash_obj = hashlib.sha256()

        # Read file in chunks for memory efficiency
        try:
            with open(file_path, "rb") as f:
                while chunk := f.read(8192):
                    hash_obj.update(chunk)

            file_hash = hash_obj.hexdigest()
            logger.info(f"{hash_type.upper()} hash: {file_hash}")
            return file_hash

        except IOError as e:
            raise ValidationError(f"Error reading file {file_path}: {e}")

    def get_detection_ratio(self, file_hash: str) -> Tuple[int, int]:
        """
        Get detection ratio for a hash.

        Args:
            file_hash: File hash to check

        Returns:
            Tuple of (detections, total_vendors)

        Raises:
            ValidationError: If hash format is invalid
        """
        self._validate_hash_format(file_hash)

        logger.debug(f"Getting detection ratio for: {file_hash}")

        try:
            vt_data = self.virustotal.check_file_hash(file_hash)

            if vt_data and vt_data.get("response_code") == 1:
                detections = vt_data.get("positives", 0)
                total = vt_data.get("total", 0)
                logger.debug(f"Detection ratio: {detections}/{total}")
                return (detections, total)

        except Exception as e:
            logger.error(f"Failed to get detection ratio: {e}")

        return (0, 0)

    def hash_string(self, text: str, hash_type: str = "md5") -> str:
        """
        Compute hash of a string.

        Args:
            text: Text to hash
            hash_type: Type of hash to compute (md5, sha1, sha256)

        Returns:
            Hexadecimal hash string

        Raises:
            ValidationError: If hash type is invalid
        """
        hash_type = hash_type.lower()
        if hash_type not in ["md5", "sha1", "sha256"]:
            raise ValidationError(
                f"Invalid hash type: {hash_type}. "
                "Must be md5, sha1, or sha256"
            )

        logger.debug(f"Computing {hash_type.upper()} hash of string")

        # Select hash algorithm
        if hash_type == "md5":
            hash_obj = hashlib.md5()
        elif hash_type == "sha1":
            hash_obj = hashlib.sha1()
        else:  # sha256
            hash_obj = hashlib.sha256()

        hash_obj.update(text.encode('utf-8'))
        return hash_obj.hexdigest()

    def close(self):
        """Close API client sessions"""
        self.virustotal.close()

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()
