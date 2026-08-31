"""LangGraph Multi-Agent Investigation State Graph."""
import asyncio
from typing import Any
from langgraph.graph import StateGraph, END
from src.domain.enums import AgentDomain
from src.domain.models import AgentFinding
from src.orchestration.state import SOCGraphState
from src.ingestion.normalizer import AlertNormalizer
from src.routing.router import AdaptiveRouter
from src.agents import (
    NetworkSpecialistAgent,
    EndpointSpecialistAgent,
    IdentitySpecialistAgent,
    CloudSpecialistAgent,
    MalwareSpecialistAgent,
    ThreatIntelSpecialistAgent,
)
from src.synthesis.investigator import SynthesisInvestigator
from src.memory.repository import HistoricalIncidentMemory
from src.trust.score import TrustScoreEngine
from src.response.playbooks import PlaybookGenerator
from src.response.approval import ApprovalService


class SOCGraphOrchestrator:
    """Constructs and executes the LangGraph DAG for autonomous SOC triage."""

    def __init__(
        self,
        normalizer: AlertNormalizer | None = None,
        router: AdaptiveRouter | None = None,
        synthesis_investigator: SynthesisInvestigator | None = None,
        memory: HistoricalIncidentMemory | None = None,
        trust_engine: TrustScoreEngine | None = None,
        playbook_generator: PlaybookGenerator | None = None,
        approval_service: ApprovalService | None = None,
    ):
        self.normalizer = normalizer or AlertNormalizer()
        self.router = router or AdaptiveRouter()
        self.synthesis = synthesis_investigator or SynthesisInvestigator()
        self.memory = memory or HistoricalIncidentMemory()
        self.trust_engine = trust_engine or TrustScoreEngine()
        self.playbook_gen = playbook_generator or PlaybookGenerator()
        self.approval_svc = approval_service or ApprovalService()

        # Instantiate specialist agents
        self.specialist_agents = {
            AgentDomain.NETWORK: NetworkSpecialistAgent(),
            AgentDomain.ENDPOINT: EndpointSpecialistAgent(),
            AgentDomain.IDENTITY: IdentitySpecialistAgent(),
            AgentDomain.CLOUD: CloudSpecialistAgent(),
            AgentDomain.MALWARE: MalwareSpecialistAgent(),
            AgentDomain.THREAT_INTEL: ThreatIntelSpecialistAgent(),
        }

        self.graph = self._build_graph()

    def _build_graph(self):
        builder = StateGraph(SOCGraphState)

        # Register DAG Nodes
        builder.add_node("normalize", self._node_normalize)
        builder.add_node("route", self._node_route)
        builder.add_node("dispatch_specialists", self._node_dispatch_specialists)
        builder.add_node("synthesize", self._node_synthesize)
        builder.add_node("retrieve_memory", self._node_retrieve_memory)
        builder.add_node("evaluate_trust", self._node_evaluate_trust)
        builder.add_node("generate_playbook", self._node_generate_playbook)
        builder.add_node("stage_approval", self._node_stage_approval)

        # Set Entry Point and Sequential Flow
        builder.set_entry_point("normalize")
        builder.add_edge("normalize", "route")
        builder.add_edge("route", "dispatch_specialists")
        builder.add_edge("dispatch_specialists", "synthesize")
        builder.add_edge("synthesize", "retrieve_memory")
        builder.add_edge("retrieve_memory", "evaluate_trust")
        builder.add_edge("evaluate_trust", "generate_playbook")
        builder.add_edge("generate_playbook", "stage_approval")
        builder.add_edge("stage_approval", END)

        return builder.compile()

    async def _node_normalize(self, state: SOCGraphState) -> dict[str, Any]:
        alert = self.normalizer.normalize(state["raw_payload"])
        timeline = state.get("audit_timeline", [])
        timeline.append({"stage": "NORMALIZATION", "signature": alert.signature, "severity": alert.raw_severity.value})
        return {"normalized_alert": alert, "audit_timeline": timeline}

    async def _node_route(self, state: SOCGraphState) -> dict[str, Any]:
        alert = state["normalized_alert"]
        decision = self.router.route(alert)
        timeline = state.get("audit_timeline", [])
        timeline.append({
            "stage": "ROUTING",
            "selected_domains": [d.value for d in decision.selected_domains],
            "latency_ms": decision.routing_latency_ms,
        })
        return {
            "routing_decision": decision,
            "active_domains": decision.selected_domains,
            "audit_timeline": timeline,
        }

    async def _node_dispatch_specialists(self, state: SOCGraphState) -> dict[str, Any]:
        alert = state["normalized_alert"]
        active_domains = state["active_domains"]

        # Run only the selected specialist agents in parallel
        tasks = []
        domain_keys = []
        for domain in active_domains:
            agent = self.specialist_agents.get(domain)
            if agent:
                tasks.append(agent.analyze(alert))
                domain_keys.append(domain.value)

        results: list[AgentFinding] = await asyncio.gather(*tasks)

        findings_dict: dict[str, AgentFinding] = {k: v for k, v in zip(domain_keys, results)}
        timeline = state.get("audit_timeline", [])
        timeline.append({
            "stage": "SPECIALIST_INVESTIGATION",
            "active_count": len(results),
            "verdicts": {k: f.verdict.value for k, f in findings_dict.items()},
        })
        return {"agent_findings": findings_dict, "audit_timeline": timeline}

    async def _node_synthesize(self, state: SOCGraphState) -> dict[str, Any]:
        findings = list(state["agent_findings"].values())
        consensus = self.synthesis.synthesize(findings)
        timeline = state.get("audit_timeline", [])
        timeline.append({
            "stage": "SYNTHESIS",
            "overall_verdict": consensus.overall_verdict.value,
            "consensus_score": consensus.consensus_score,
            "has_conflict": consensus.has_conflict,
        })
        return {"consensus_assessment": consensus, "audit_timeline": timeline}

    async def _node_retrieve_memory(self, state: SOCGraphState) -> dict[str, Any]:
        alert = state["normalized_alert"]
        consensus = state.get("consensus_assessment")
        cases, h_score = self.memory.retrieve_similar_cases(alert, consensus)
        timeline = state.get("audit_timeline", [])
        timeline.append({"stage": "HISTORICAL_MEMORY", "matched_cases": len(cases), "H_score": h_score})
        return {"historical_cases": cases, "historical_score": h_score, "audit_timeline": timeline}

    async def _node_evaluate_trust(self, state: SOCGraphState) -> dict[str, Any]:
        alert = state["normalized_alert"]
        consensus = state["consensus_assessment"]
        h_score = state.get("historical_score", 0.0)
        single_agent = len(state.get("active_domains", [])) == 1

        assessment = self.trust_engine.evaluate_trust(
            incident_id=alert.alert_id,
            consensus=consensus,
            historical_score=h_score,
            raw_severity=alert.raw_severity,
            single_agent_invoked=single_agent,
        )
        timeline = state.get("audit_timeline", [])
        timeline.append({
            "stage": "TRUST_EVALUATION_GATE_03",
            "trust_score": assessment.trust_score,
            "decision": assessment.decision.value,
            "reason_codes": assessment.reason_codes,
        })
        return {"trust_assessment": assessment, "audit_timeline": timeline}

    async def _node_generate_playbook(self, state: SOCGraphState) -> dict[str, Any]:
        alert = state["normalized_alert"]
        consensus = state["consensus_assessment"]
        playbook = self.playbook_gen.generate_playbook(alert.alert_id, alert, consensus)
        timeline = state.get("audit_timeline", [])
        timeline.append({"stage": "PLAYBOOK_GENERATION", "actions_count": len(playbook.actions)})
        return {"playbook": playbook, "audit_timeline": timeline}

    async def _node_stage_approval(self, state: SOCGraphState) -> dict[str, Any]:
        alert = state["normalized_alert"]
        playbook = state["playbook"]
        trust = state["trust_assessment"]

        req = self.approval_svc.create_approval_request(
            incident_id=alert.alert_id,
            playbook=playbook,
            trust_score=trust.trust_score,
        )
        timeline = state.get("audit_timeline", [])
        timeline.append({"stage": "MANDATORY_APPROVAL_GATE", "request_id": str(req.request_id), "status": req.status.value})
        return {"approval_request": req, "audit_timeline": timeline}

    async def run(self, raw_payload: dict[str, Any]) -> SOCGraphState:
        """Executes full investigation pipeline end-to-end."""
        initial_state: SOCGraphState = {
            "raw_payload": raw_payload,
            "audit_timeline": [],
            "errors": [],
        }
        final_state = await self.graph.ainvoke(initial_state)
        return final_state
