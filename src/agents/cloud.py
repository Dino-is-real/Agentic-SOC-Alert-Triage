"""Cloud Domain Specialist Agent."""
from typing import Any, Optional
from uuid import uuid4
from src.domain.enums import AgentDomain, AgentVerdict, EvidenceType
from src.domain.models import NormalizedAlert, AgentFinding, Evidence
from src.agents.base import SpecialistAgent
from src.integrations.llm import BaseLLMProvider, get_llm_provider


class CloudSpecialistAgent(SpecialistAgent):
    """Investigates AWS/Azure/GCP IAM role assumptions, S3 policy mutations, and CloudTrail events."""

    def __init__(self, llm: Optional[BaseLLMProvider] = None):
        super().__init__(domain=AgentDomain.CLOUD)
        self.llm = llm or get_llm_provider()

    async def analyze(
        self,
        alert: NormalizedAlert,
        context: Optional[dict[str, Any]] = None,
    ) -> AgentFinding:
        evidence_items: list[Evidence] = []

        if alert.cloud.resource_arn:
            evidence_items.append(
                Evidence(
                    evidence_type=EvidenceType.CLOUD_API,
                    key="resource_arn",
                    value=alert.cloud.resource_arn,
                    source="CloudAgent:CloudTrail",
                    confidence_weight=0.90,
                )
            )

        if alert.cloud.event_name:
            evidence_items.append(
                Evidence(
                    evidence_type=EvidenceType.CLOUD_API,
                    key="event_name",
                    value=alert.cloud.event_name,
                    source="CloudAgent:AuditLog",
                    confidence_weight=0.95,
                    context_data={"region": alert.cloud.region, "account_id": alert.cloud.account_id},
                )
            )

        sys_prompt = "You are an expert SOC Cloud Security Specialist. Analyze CloudTrail events, IAM role mutations, and resource exposures."
        user_prompt = f"""
        Alert Signature: {alert.signature}
        Cloud Provider: {alert.cloud.cloud_provider}
        Account ID: {alert.cloud.account_id}
        Region: {alert.cloud.region}
        Resource ARN: {alert.cloud.resource_arn}
        Event Source: {alert.cloud.event_source}
        Event Name: {alert.cloud.event_name}
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
            confidence=float(raw_finding.get("confidence", 0.89)),
            evidence_items=evidence_items,
            mitre_techniques=raw_finding.get("mitre_techniques", ["T1078.004"]),
            reasoning_summary=raw_finding.get("reasoning_summary", "Cloud API event evaluated."),
            uncertainty_factors=raw_finding.get("uncertainty_factors", []),
            recommended_queries=raw_finding.get("recommended_queries", []),
        )
