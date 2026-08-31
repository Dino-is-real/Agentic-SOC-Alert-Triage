"""Endpoint Domain Specialist Agent."""
from typing import Any, Optional
from uuid import uuid4
from src.domain.enums import AgentDomain, AgentVerdict, EvidenceType
from src.domain.models import NormalizedAlert, AgentFinding, Evidence
from src.agents.base import SpecialistAgent
from src.integrations.llm import BaseLLMProvider, get_llm_provider


class EndpointSpecialistAgent(SpecialistAgent):
    """Investigates host processes, command lines, parent-child trees, hashes, and registry keys."""

    def __init__(self, llm: Optional[BaseLLMProvider] = None):
        super().__init__(domain=AgentDomain.ENDPOINT)
        self.llm = llm or get_llm_provider()

    async def analyze(
        self,
        alert: NormalizedAlert,
        context: Optional[dict[str, Any]] = None,
    ) -> AgentFinding:
        evidence_items: list[Evidence] = []

        if alert.endpoint.command_line:
            evidence_items.append(
                Evidence(
                    evidence_type=EvidenceType.PROCESS_LINE,
                    key="command_line",
                    value=alert.endpoint.command_line,
                    source="EndpointAgent:Sysmon/Auditd",
                    confidence_weight=0.95,
                )
            )

        if alert.endpoint.process_name:
            evidence_items.append(
                Evidence(
                    evidence_type=EvidenceType.PROCESS_LINE,
                    key="process_name",
                    value=alert.endpoint.process_name,
                    source="EndpointAgent:ProcessTree",
                    confidence_weight=0.90,
                    context_data={"parent": alert.endpoint.parent_process_name},
                )
            )

        if alert.endpoint.sha256:
            evidence_items.append(
                Evidence(
                    evidence_type=EvidenceType.FILE_HASH,
                    key="sha256",
                    value=alert.endpoint.sha256,
                    source="EndpointAgent:HashLookup",
                    confidence_weight=0.95,
                )
            )

        if alert.endpoint.registry_key:
            evidence_items.append(
                Evidence(
                    evidence_type=EvidenceType.REGISTRY_KEY,
                    key="registry_key",
                    value=alert.endpoint.registry_key,
                    source="EndpointAgent:Registry",
                    confidence_weight=0.85,
                )
            )

        sys_prompt = "You are an expert SOC Endpoint Security Specialist. Analyze host processes, LOLBAS, and execution command lines."
        user_prompt = f"""
        Alert Signature: {alert.signature}
        Hostname: {alert.endpoint.hostname}
        Process Name: {alert.endpoint.process_name}
        Parent Process: {alert.endpoint.parent_process_name}
        Command Line: {alert.endpoint.command_line}
        File Path: {alert.endpoint.file_path}
        SHA256: {alert.endpoint.sha256}
        Registry Key: {alert.endpoint.registry_key}
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
            confidence=float(raw_finding.get("confidence", 0.88)),
            evidence_items=evidence_items,
            mitre_techniques=raw_finding.get("mitre_techniques", ["T1059.001"]),
            reasoning_summary=raw_finding.get("reasoning_summary", "Endpoint telemetry evaluated."),
            uncertainty_factors=raw_finding.get("uncertainty_factors", []),
            recommended_queries=raw_finding.get("recommended_queries", []),
        )