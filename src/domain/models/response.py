"""Response Playbooks, Approval Requests, and Execution Models."""
from datetime import datetime, timezone
from typing import Optional, Any
from uuid import UUID, uuid4
from pydantic import BaseModel, Field
from src.domain.enums import ActionType, AlertSeverity, ApprovalStatus, ExecutionStatus, ExecutorType


class RecommendedAction(BaseModel):
    action_id: UUID = Field(default_factory=uuid4)
    action_type: ActionType
    target_entity: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    rationale: str
    risk_level: AlertSeverity = AlertSeverity.MEDIUM
    is_reversible: bool = True


class Playbook(BaseModel):
    playbook_id: UUID = Field(default_factory=uuid4)
    incident_id: UUID
    title: str
    actions: list[RecommendedAction] = Field(..., min_length=1)
    suggested_by: str = "AdaptiveTrustEngine"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ApprovalRequest(BaseModel):
    request_id: UUID = Field(default_factory=uuid4)
    incident_id: UUID
    playbook_id: UUID
    trust_score: float
    status: ApprovalStatus = ApprovalStatus.PENDING
    requested_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime


class ApprovalDecision(BaseModel):
    decision_id: UUID = Field(default_factory=uuid4)
    request_id: UUID
    analyst_id: str
    decision: ApprovalStatus
    analyst_notes: str = ""
    modified_actions: Optional[list[RecommendedAction]] = None
    signature_token: str
    decided_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ExecutionResult(BaseModel):
    execution_id: UUID = Field(default_factory=uuid4)
    decision_id: UUID
    executor_type: ExecutorType = ExecutorType.SIMULATION
    status: ExecutionStatus
    action_logs: list[dict[str, Any]] = Field(default_factory=list)
    executed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
