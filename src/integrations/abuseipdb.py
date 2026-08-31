"""AbuseIPDB Threat Intelligence Provider and Deterministic Mock."""
import httpx
from typing import Optional
from src.core.config import settings
from src.core.logging import logger
from src.integrations.base import ThreatIntelProvider, ThreatIntelReport


class AbuseIPDBProvider(ThreatIntelProvider):
    """AbuseIPDB IP Reputation Adapter."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or settings.ABUSEIPDB_API_KEY
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.headers = {"Key": self.api_key or "", "Accept": "application/json"}

    async def lookup_ip(self, ip: str) -> ThreatIntelReport:
        if not self.api_key:
            return MockAbuseIPDBProvider().lookup_ip_sync(ip)
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(
                    f"{self.base_url}/check",
                    headers=self.headers,
                    params={"ipAddress": ip, "maxAgeInDays": "90"},
                )
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    score = data.get("abuseConfidenceScore", 0) / 100.0
                    return ThreatIntelReport(
                        observable=ip,
                        observable_type="ip",
                        reputation_score=score,
                        is_malicious=score >= 0.50,
                        verdict="MALICIOUS" if score >= 0.50 else "BENIGN",
                        detections=data.get("totalReports", 0),
                        total_engines=100,
                        tags=["abuseipdb-reported"] if score >= 0.50 else ["clean"],
                    )
        except Exception as e:
            logger.warning(f"AbuseIPDB lookup failed: {e}")
        return MockAbuseIPDBProvider().lookup_ip_sync(ip)

    async def lookup_hash(self, file_hash: str) -> ThreatIntelReport:
        return ThreatIntelReport(observable=file_hash, observable_type="hash", verdict="BENIGN")

    async def lookup_domain(self, domain: str) -> ThreatIntelReport:
        return ThreatIntelReport(observable=domain, observable_type="domain", verdict="BENIGN")


class MockAbuseIPDBProvider(ThreatIntelProvider):
    """Deterministic Mock AbuseIPDB Provider."""

    KNOWN_BAD_IPS = {"185.220.101.5", "194.26.29.112", "45.154.255.80", "198.51.100.23"}

    def lookup_ip_sync(self, ip: str) -> ThreatIntelReport:
        is_bad = ip in self.KNOWN_BAD_IPS or ip.startswith("185.220.")
        return ThreatIntelReport(
            observable=ip,
            observable_type="ip",
            reputation_score=0.95 if is_bad else 0.0,
            is_malicious=is_bad,
            verdict="MALICIOUS" if is_bad else "BENIGN",
            detections=142 if is_bad else 0,
            total_engines=100,
            tags=["brute-force", "ssh-scanner"] if is_bad else [],
        )

    async def lookup_ip(self, ip: str) -> ThreatIntelReport:
        return self.lookup_ip_sync(ip)

    async def lookup_hash(self, file_hash: str) -> ThreatIntelReport:
        return ThreatIntelReport(observable=file_hash, observable_type="hash", verdict="BENIGN")

    async def lookup_domain(self, domain: str) -> ThreatIntelReport:
        return ThreatIntelReport(observable=domain, observable_type="domain", verdict="BENIGN")
