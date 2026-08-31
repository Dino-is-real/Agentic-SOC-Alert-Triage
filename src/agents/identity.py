"""Identity Domain Specialist Agent."""
from typing import Any, Optional
from uuid import uuid4
from src.domain.enums import AgentDomain, AgentVerdict, EvidenceType
from src.domain.models import NormalizedAlert, AgentFinding, Evidence
from src.agents.base import SpecialistAgent
from src.integrations.llm import BaseLLMProvider, get_llm_provider


class IdentitySpecialistAgent(SpecialistAgent):
    """Investigates authentication failures, MFA bypass, impossible travel, and IAM anomalies."""

    def __init__(self, llm: Optional[BaseLLMProvider] = None):
        super().__init__(domain=AgentDomain.IDENTITY)
        self.llm = llm or get_llm_provider()

    async def analyze(
        self,
        alert: NormalizedAlert,
        context: Optional[dict[str, Any]] = None,
    ) -> AgentFinding:
        evidence_items: list[Evidence] = []

        if alert.identity.username:
            evidence_items.append(
                Evidence(
                    evidence_type=EvidenceType.AUTH_EVENT,
                    key="username",
                    value=alert.identity.username,
                    source="IdentityAgent:ActiveDirectory",
                    confidence_weight=0.90,
                    context_data={"is_privileged": alert.identity.is_privileged},
                )
            )

        if alert.identity.auth_status:
            evidence_items.append(
                Evidence(
                    evidence_type=EvidenceType.AUTH_EVENT,
                    key="auth_status",
                    value=alert.identity.auth_status,
                    source="IdentityAgent:AuthLog",
                    confidence_weight=0.95,
                    context_data={"mfa_used": alert.identity.mfa_used},
                )
            )

        if alert.identity.src_geo_country:
            evidence_items.append(
                Evidence(
                    evidence_type=EvidenceType.AUTH_EVENT,
                    key="geo_location",
                    value=f"{alert.identity.src_geo_city}, {alert.identity.src_geo_country}",
                    source="IdentityAgent:GeoIP",
                    confidence_weight=0.80,
                )
            )

        sys_prompt = "You are an expert SOC Identity Security Specialist. Analyze authentication patterns, brute force, and privilege anomalies."
        user_prompt = f"""
        Alert Signature: {alert.signature}
        Username: {alert.identity.username}
        Domain: {alert.identity.user_domain}
        Auth Status: {alert.identity.auth_status}
        MFA Used: {alert.identity.mfa_used}
        Geo Country: {alert.identity.src_geo_country}
        Is Privileged: {alert.identity.is_privileged}
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
            confidence=float(raw_finding.get("confidence", 0.84)),
            evidence_items=evidence_items,
            mitre_techniques=raw_finding.get("mitre_techniques", ["T1110.001"]),
            reasoning_summary=raw_finding.get("reasoning_summary", "Identity telemetry evaluated."),
            uncertainty_factors=raw_finding.get("uncertainty_factors", []),
            recommended_queries=raw_finding.get("recommended_queries", []),
        )
