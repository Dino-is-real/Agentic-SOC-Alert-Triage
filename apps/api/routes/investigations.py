"""Investigation Orchestration API Endpoints."""
from typing import Any
from uuid import UUID
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from src.orchestration.graph import SOCGraphOrchestrator
from src.orchestration.state import SOCGraphState
from src.domain.models import (
    NormalizedAlert,
    RoutingDecision,
    AgentFinding,
    ConsensusAssessment,
    HistoricalCase,
    TrustAssessment,
    Playbook,
    ApprovalRequest,
)

router = APIRouter(prefix="/investigations", tags=["Investigations"])
orchestrator = SOCGraphOrchestrator()

# Global in-memory incident cache for demo and API retrieval
INCIDENTS_STORE: dict[UUID, dict[str, Any]] = {}


class InvestigationResponse(BaseModel):
    incident_id: UUID
    normalized_alert: NormalizedAlert
    routing_decision: RoutingDecision
    agent_findings: dict[str, AgentFinding]
    consensus_assessment: ConsensusAssessment
    historical_cases: list[HistoricalCase]
    trust_assessment: TrustAssessment
    playbook: Playbook
    approval_request: ApprovalRequest
    audit_timeline: list[dict[str, Any]]


@router.post("/run", response_model=InvestigationResponse, status_code=status.HTTP_200_OK)
async def run_investigation(payload: dict[str, Any]):
    """Executes the full LangGraph adaptive multi-agent investigation workflow."""
    try:
        final_state: SOCGraphState = await orchestrator.run(payload)

        alert = final_state["normalized_alert"]
        if not alert:
            raise ValueError("Pipeline failed to produce NormalizedAlert.")

        response_data = {
            "incident_id": alert.alert_id,
            "normalized_alert": alert,
            "routing_decision": final_state["routing_decision"],
            "agent_findings": final_state["agent_findings"],
            "consensus_assessment": final_state["consensus_assessment"],
            "historical_cases": final_state["historical_cases"],
            "trust_assessment": final_state["trust_assessment"],
            "playbook": final_state["playbook"],
            "approval_request": final_state["approval_request"],
            "audit_timeline": final_state["audit_timeline"],
        }

        # Store for dashboard retrieval
        INCIDENTS_STORE[alert.alert_id] = response_data
        return response_data
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Investigation workflow failed: {str(e)}",
        )
