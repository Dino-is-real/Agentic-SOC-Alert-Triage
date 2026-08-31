"""Network Domain Specialist Agent."""
from typing import Any, Optional
from uuid import uuid4
from src.domain.enums import AgentDomain, AgentVerdict, EvidenceType
from src.domain.models import NormalizedAlert, AgentFinding, Evidence
from src.agents.base import SpecialistAgent
from src.integrations.base import ThreatIntelProvider
from src.integrations.abuseipdb import MockAbuseIPDBProvider
from src.integrations.llm import BaseLLMProvider, get_llm_provider


class NetworkSpecialistAgent(SpecialistAgent):
    """Investigates IP addresses, ports, protocols, DNS queries, and network flows."""

    def __init__(
        self,
        threat_intel: Optional[ThreatIntelProvider] = None,
        llm: Optional[BaseLLMProvider] = None,
    ):
        super().__init__(domain=AgentDomain.NETWORK)
        self.threat_intel = threat_intel or MockAbuseIPDBProvider()
        self.llm = llm or get_llm_provider()

    async def analyze(
        self,
        alert: NormalizedAlert,
        context: Optional[dict[str, Any]] = None,
    ) -> AgentFinding:
        evidence_items: list[Evidence] = []

        # 1. Inspect Network Flow & IP Evidence
        if alert.network.src_ip:
            ip_report = await self.threat_intel.lookup_ip(alert.network.src_ip)
            evidence_items.append(
                Evidence(
                    evidence_type=EvidenceType.IP_ADDRESS,
                    key="src_ip_reputation",
                    value=f"{alert.network.src_ip} (Rep: {ip_report.reputation_score}, Detections: {ip_report.detections})",
                    source="NetworkAgent:AbuseIPDB",
                    confidence_weight=0.90 if ip_report.is_malicious else 0.70,
                    context_data={"tags": ip_report.tags, "is_malicious": ip_report.is_malicious},
                )
            )

        if alert.network.dns_query:
            evidence_items.append(
                Evidence(
                    evidence_type=EvidenceType.DOMAIN,
                    key="dns_query",
                    value=alert.network.dns_query,
                    source="NetworkAgent:DNS",
                    confidence_weight=0.85,
                )
            )

        if alert.network.dst_port:
            evidence_items.append(
                Evidence(
                    evidence_type=EvidenceType.NETWORK_FLOW,
                    key="dst_port",
                    value=str(alert.network.dst_port),
                    source="NetworkAgent:Flow",
                    confidence_weight=0.80,
                )
            )

        # 2. LLM Reasoning Prompt
        sys_prompt = "You are an expert SOC Network Security Specialist. Analyze network flow telemetry, IPs, ports, and protocols."
        user_prompt = f"""
        Alert Signature: {alert.signature}
        Category: {alert.category}
        Source IP: {alert.network.src_ip}
        Destination IP: {alert.network.dst_ip}
        Destination Port: {alert.network.dst_port}
        Protocol: {alert.network.protocol}
        DNS Query: {alert.network.dns_query}
        HTTP URI: {alert.network.http_uri}
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
            confidence=float(raw_finding.get("confidence", 0.85)),
            evidence_items=evidence_items,
            mitre_techniques=raw_finding.get("mitre_techniques", ["T1046"]),
            reasoning_summary=raw_finding.get("reasoning_summary", "Network activity analyzed."),
            uncertainty_factors=raw_finding.get("uncertainty_factors", []),
            recommended_queries=raw_finding.get("recommended_queries", []),
        )
