"""LangGraph State Definitions for Multi-Agent SOC Investigation."""
from typing import Any, Optional
from typing_extensions import TypedDict
from src.domain.enums import AgentDomain
from src.domain.models import (
    NormalizedAlert,
    RoutingDecision,
    AgentFinding,
    ConsensusAssessment,
    HistoricalCase,
    TrustAssessment,
    Playbook,
    ApprovalRequest,
    ApprovalDecision,
    ExecutionResult,
)


class SOCGraphState(TypedDict, total=False):
    """Unified state schema passed through LangGraph nodes."""
    raw_payload: dict[str, Any]
    normalized_alert: Optional[NormalizedAlert]
    routing_decision: Optional[RoutingDecision]
    active_domains: list[AgentDomain]
    agent_findings: dict[str, AgentFinding]
    consensus_assessment: Optional[ConsensusAssessment]
    historical_cases: list[HistoricalCase]
    historical_score: float
    trust_assessment: Optional[TrustAssessment]
    playbook: Optional[Playbook]
    approval_request: Optional[ApprovalRequest]
    approval_decision: Optional[ApprovalDecision]
    execution_result: Optional[ExecutionResult]
    audit_timeline: list[dict[str, Any]]
    errors: list[str]
