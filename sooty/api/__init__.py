"""Sooty API clients module"""

from sooty.api.base import BaseAPIClient
from sooty.api.virustotal import VirusTotalClient
from sooty.api.abuseipdb import AbuseIPDBClient
from sooty.api.urlscan import URLScanClient
from sooty.api.emailrep import EmailRepClient
from sooty.api.haveibeenpwned import HaveIBeenPwnedClient
from sooty.api.phishtank import PhishTankClient
from sooty.api.dns import DNSClient

__all__ = [
    "BaseAPIClient",
    "VirusTotalClient",
    "AbuseIPDBClient",
    "URLScanClient",
    "EmailRepClient",
    "HaveIBeenPwnedClient",
    "PhishTankClient",
    "DNSClient",
]
