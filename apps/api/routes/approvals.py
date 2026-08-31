"""Human Approval and Simulation Execution API Endpoints."""
from typing import Optional
from uuid import UUID
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from src.domain.enums import ApprovalStatus
from src.domain.models import ApprovalRequest, ApprovalDecision, ExecutionResult, RecommendedAction
from src.response.approval import ApprovalService
from src.response.simulator import SimulationExecutor
from apps.api.routes.investigations import INCIDENTS_STORE, orchestrator

router = APIRouter(prefix="/approvals", tags=["Approvals"])

# Share the exact approval_service instance used by the orchestrator
approval_service: ApprovalService = orchestrator.approval_svc
simulation_executor = SimulationExecutor(approval_service=approval_service)


class DecisionSubmission(BaseModel):
    analyst_id: str
    decision: ApprovalStatus
    analyst_notes: str = ""
    modified_actions: Optional[list[RecommendedAction]] = None


@router.get("/pending", response_model=list[ApprovalRequest])
async def list_pending_approvals():
    """Returns all approval requests currently awaiting human analyst sign-off."""
    return [
        req for req in approval_service._requests.values() if req.status == ApprovalStatus.PENDING
    ]


@router.post("/{request_id}/decide", response_model=ApprovalDecision)
async def submit_approval_decision(request_id: UUID, body: DecisionSubmission):
    """Submits human analyst approval/rejection decision and creates cryptographic authorization token."""
    try:
        decision = approval_service.submit_decision(
            request_id=request_id,
            analyst_id=body.analyst_id,
            decision=body.decision,
            analyst_notes=body.analyst_notes,
            modified_actions=body.modified_actions,
        )
        return decision
    except KeyError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Approval request not found.")
    except TimeoutError as e:
        raise HTTPException(status_code=status.HTTP_410_GONE, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/{decision_id}/execute", response_model=ExecutionResult)
async def execute_approved_remediation(decision_id: UUID):
    """Executes approved remediation actions in non-destructive simulation mode."""
    try:
        decision = approval_service.verify_authorization_for_execution(decision_id)
        req = approval_service._requests.get(decision.request_id)
        if not req:
            raise KeyError("Associated approval request not found.")

        incident = INCIDENTS_STORE.get(req.incident_id)
        if not incident:
            raise KeyError("Associated incident data not found.")

        playbook = incident["playbook"]
        result = simulation_executor.execute_playbook(decision.decision_id, playbook)
        return result
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except KeyError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
