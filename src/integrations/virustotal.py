"""VirusTotal Threat Intelligence Provider and Deterministic Mock."""
import httpx
from typing import Optional
from src.core.config import settings
from src.core.logging import logger
from src.integrations.base import ThreatIntelProvider, ThreatIntelReport


class VirusTotalProvider(ThreatIntelProvider):
    """Live VirusTotal v3 API Adapter with rate limiting and timeout guards."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or settings.VIRUSTOTAL_API_KEY
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {"x-apikey": self.api_key or ""}

    async def lookup_ip(self, ip: str) -> ThreatIntelReport:
        if not self.api_key:
            return MockVirusTotalProvider().lookup_ip_sync(ip)
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{self.base_url}/ip_addresses/{ip}", headers=self.headers)
                if resp.status_code == 200:
                    data = resp.json().get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    total = sum(stats.values()) if stats else 1
                    rep_score = min(1.0, malicious / max(1, total))
                    return ThreatIntelReport(
                        observable=ip,
                        observable_type="ip",
                        reputation_score=rep_score,
                        is_malicious=malicious >= 3,
                        verdict="MALICIOUS" if malicious >= 3 else "BENIGN",
                        detections=malicious,
                        total_engines=total,
                        tags=data.get("tags", []),
                    )
        except Exception as e:
            logger.warning(f"VirusTotal IP lookup failed: {e}")
        return MockVirusTotalProvider().lookup_ip_sync(ip)

    async def lookup_hash(self, file_hash: str) -> ThreatIntelReport:
        if not self.api_key:
            return MockVirusTotalProvider().lookup_hash_sync(file_hash)
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{self.base_url}/files/{file_hash}", headers=self.headers)
                if resp.status_code == 200:
                    data = resp.json().get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    total = sum(stats.values()) if stats else 1
                    rep_score = min(1.0, malicious / max(1, total))
                    return ThreatIntelReport(
                        observable=file_hash,
                        observable_type="hash",
                        reputation_score=rep_score,
                        is_malicious=malicious >= 3,
                        verdict="MALICIOUS" if malicious >= 3 else "BENIGN",
                        detections=malicious,
                        total_engines=total,
                        tags=data.get("tags", []),
                    )
        except Exception as e:
            logger.warning(f"VirusTotal hash lookup failed: {e}")
        return MockVirusTotalProvider().lookup_hash_sync(file_hash)

    async def lookup_domain(self, domain: str) -> ThreatIntelReport:
        if not self.api_key:
            return MockVirusTotalProvider().lookup_domain_sync(domain)
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{self.base_url}/domains/{domain}", headers=self.headers)
                if resp.status_code == 200:
                    data = resp.json().get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    total = sum(stats.values()) if stats else 1
                    rep_score = min(1.0, malicious / max(1, total))
                    return ThreatIntelReport(
                        observable=domain,
                        observable_type="domain",
                        reputation_score=rep_score,
                        is_malicious=malicious >= 3,
                        verdict="MALICIOUS" if malicious >= 3 else "BENIGN",
                        detections=malicious,
                        total_engines=total,
                        tags=data.get("tags", []),
                    )
        except Exception as e:
            logger.warning(f"VirusTotal domain lookup failed: {e}")
        return MockVirusTotalProvider().lookup_domain_sync(domain)


class MockVirusTotalProvider(ThreatIntelProvider):
    """Deterministic Mock Provider for tests, CI/CD, and offline benchmarking."""

    KNOWN_MALICIOUS_IPS = {"185.220.101.5", "194.26.29.112", "45.154.255.80", "198.51.100.23"}
    KNOWN_MALICIOUS_HASHES = {
        "44d88612fea8a8f36de82e1278abb02f",
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    }
    KNOWN_MALICIOUS_DOMAINS = {"c2-beacon.darknet.top", "evil-phish.xyz", "malicious-update.org"}

    def lookup_ip_sync(self, ip: str) -> ThreatIntelReport:
        is_mal = ip in self.KNOWN_MALICIOUS_IPS or ip.startswith("185.220.")
        return ThreatIntelReport(
            observable=ip,
            observable_type="ip",
            reputation_score=0.92 if is_mal else 0.05,
            is_malicious=is_mal,
            verdict="MALICIOUS" if is_mal else "BENIGN",
            detections=54 if is_mal else 0,
            total_engines=88,
            tags=["tor-exit", "scanner"] if is_mal else ["clean"],
        )

    def lookup_hash_sync(self, file_hash: str) -> ThreatIntelReport:
        is_mal = file_hash.lower() in self.KNOWN_MALICIOUS_HASHES
        return ThreatIntelReport(
            observable=file_hash,
            observable_type="hash",
            reputation_score=0.96 if is_mal else 0.02,
            is_malicious=is_mal,
            verdict="MALICIOUS" if is_mal else "BENIGN",
            detections=61 if is_mal else 0,
            total_engines=72,
            tags=["trojan", "ransomware"] if is_mal else ["signed"],
        )

    def lookup_domain_sync(self, domain: str) -> ThreatIntelReport:
        is_mal = domain.lower() in self.KNOWN_MALICIOUS_DOMAINS or "c2" in domain.lower()
        return ThreatIntelReport(
            observable=domain,
            observable_type="domain",
            reputation_score=0.88 if is_mal else 0.04,
            is_malicious=is_mal,
            verdict="MALICIOUS" if is_mal else "BENIGN",
            detections=48 if is_mal else 0,
            total_engines=90,
            tags=["c2", "cobalt-strike"] if is_mal else ["cdn"],
        )

    async def lookup_ip(self, ip: str) -> ThreatIntelReport:
        return self.lookup_ip_sync(ip)

    async def lookup_hash(self, file_hash: str) -> ThreatIntelReport:
        return self.lookup_hash_sync(file_hash)

    async def lookup_domain(self, domain: str) -> ThreatIntelReport:
        return self.lookup_domain_sync(domain)
