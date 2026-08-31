"""Threat Intelligence Domain Specialist Agent."""
from typing import Any, Optional
from uuid import uuid4
from src.domain.enums import AgentDomain, AgentVerdict, EvidenceType
from src.domain.models import NormalizedAlert, AgentFinding, Evidence
from src.agents.base import SpecialistAgent
from src.integrations.base import ThreatIntelProvider
from src.integrations.virustotal import MockVirusTotalProvider
from src.integrations.shodan import MockShodanProvider
from src.integrations.llm import BaseLLMProvider, get_llm_provider


class ThreatIntelSpecialistAgent(SpecialistAgent):
    """Correlates observables with multi-source threat intelligence feeds and known threat actors."""

    def __init__(
        self,
        vt_provider: Optional[ThreatIntelProvider] = None,
        shodan_provider: Optional[ThreatIntelProvider] = None,
        llm: Optional[BaseLLMProvider] = None,
    ):
        super().__init__(domain=AgentDomain.THREAT_INTEL)
        self.vt = vt_provider or MockVirusTotalProvider()
        self.shodan = shodan_provider or MockShodanProvider()
        self.llm = llm or get_llm_provider()

    async def analyze(
        self,
        alert: NormalizedAlert,
        context: Optional[dict[str, Any]] = None,
    ) -> AgentFinding:
        evidence_items: list[Evidence] = []

        if alert.network.src_ip:
            shodan_rep = await self.shodan.lookup_ip(alert.network.src_ip)
            evidence_items.append(
                Evidence(
                    evidence_type=EvidenceType.IP_ADDRESS,
                    key="shodan_ip_intel",
                    value=f"{alert.network.src_ip} (Tags: {shodan_rep.tags})",
                    source="ThreatIntelAgent:Shodan",
                    confidence_weight=0.90,
                )
            )

        if alert.network.dns_query:
            domain_rep = await self.vt.lookup_domain(alert.network.dns_query)
            evidence_items.append(
                Evidence(
                    evidence_type=EvidenceType.DOMAIN,
                    key="domain_reputation",
                    value=f"{alert.network.dns_query} (Verdict: {domain_rep.verdict}, Detections: {domain_rep.detections})",
                    source="ThreatIntelAgent:VirusTotal",
                    confidence_weight=0.92,
                )
            )

        sys_prompt = "You are an expert SOC Threat Intelligence Specialist. Correlate IOCs, threat actor TTPs, and C2 infrastructure."
        user_prompt = f"""
        Alert Signature: {alert.signature}
        Source IP: {alert.network.src_ip}
        DNS Query: {alert.network.dns_query}
        File Hash: {alert.endpoint.sha256}
        Category: {alert.category}
        """

        raw_finding = await self.llm.generate_structured(sys_prompt, user_prompt)

        verdict_str = str(raw_finding.get("verdict", "suspicious")).lower()
        verdict_map = {
            "benign": AgentVerdict.BENIGN,
            "suspicious": AgentVerdict.SUSPICIOUS,
            "malicious": AgentVerdict.MALICIOUS,
            "insufficient_data": AgentVerdict.INSUFFICIENT_DATA,
        }
        verdict = verdict_map.get(verdict_str, AgentVerdict.SUSPICIOUS)

        return AgentFinding(
            finding_id=uuid4(),
            domain=self.domain,
            verdict=verdict,
            confidence=float(raw_finding.get("confidence", 0.92)),
            evidence_items=evidence_items,
            mitre_techniques=raw_finding.get("mitre_techniques", ["T1071.001"]),
            reasoning_summary=raw_finding.get("reasoning_summary", "Threat intelligence correlation completed."),
            uncertainty_factors=raw_finding.get("uncertainty_factors", []),
            recommended_queries=raw_finding.get("recommended_queries", []),
        )
