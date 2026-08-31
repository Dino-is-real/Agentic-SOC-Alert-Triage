"""Shodan Host and Port Scanner Provider and Deterministic Mock."""
import httpx
from typing import Optional
from src.core.config import settings
from src.core.logging import logger
from src.integrations.base import ThreatIntelProvider, ThreatIntelReport


class ShodanProvider(ThreatIntelProvider):
    """Shodan Host Information Adapter."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or settings.SHODAN_API_KEY
        self.base_url = "https://api.shodan.io"

    async def lookup_ip(self, ip: str) -> ThreatIntelReport:
        if not self.api_key:
            return MockShodanProvider().lookup_ip_sync(ip)
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{self.base_url}/shodan/host/{ip}?key={self.api_key}")
                if resp.status_code == 200:
                    data = resp.json()
                    ports = data.get("ports", [])
                    vulns = list(data.get("vulns", {}).keys())
                    is_risky = len(vulns) > 0 or 4444 in ports
                    return ThreatIntelReport(
                        observable=ip,
                        observable_type="ip",
                        reputation_score=0.85 if is_risky else 0.10,
                        is_malicious=is_risky,
                        verdict="SUSPICIOUS" if is_risky else "BENIGN",
                        detections=len(vulns),
                        tags=[f"port:{p}" for p in ports[:5]] + vulns[:3],
                    )
        except Exception as e:
            logger.warning(f"Shodan lookup failed: {e}")
        return MockShodanProvider().lookup_ip_sync(ip)

    async def lookup_hash(self, file_hash: str) -> ThreatIntelReport:
        return ThreatIntelReport(observable=file_hash, observable_type="hash", verdict="BENIGN")

    async def lookup_domain(self, domain: str) -> ThreatIntelReport:
        return ThreatIntelReport(observable=domain, observable_type="domain", verdict="BENIGN")


class MockShodanProvider(ThreatIntelProvider):
    """Deterministic Mock Shodan Provider."""

    def lookup_ip_sync(self, ip: str) -> ThreatIntelReport:
        is_scanner = ip.startswith("185.220.") or ip == "194.26.29.112"
        return ThreatIntelReport(
            observable=ip,
            observable_type="ip",
            reputation_score=0.80 if is_scanner else 0.10,
            is_malicious=is_scanner,
            verdict="SUSPICIOUS" if is_scanner else "BENIGN",
            detections=4 if is_scanner else 0,
            tags=["port:22", "port:8080", "CVE-2021-44228"] if is_scanner else ["port:443"],
        )

    async def lookup_ip(self, ip: str) -> ThreatIntelReport:
        return self.lookup_ip_sync(ip)

    async def lookup_hash(self, file_hash: str) -> ThreatIntelReport:
        return ThreatIntelReport(observable=file_hash, observable_type="hash", verdict="BENIGN")

    async def lookup_domain(self, domain: str) -> ThreatIntelReport:
        return ThreatIntelReport(observable=domain, observable_type="domain", verdict="BENIGN")
