"""Agent Finding, Evidence, and State Models."""
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4
from pydantic import BaseModel, Field
from src.domain.enums import AgentDomain, AgentVerdict, EvidenceType


class Evidence(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    evidence_type: EvidenceType
    key: str
    value: str
    source: str
    confidence_weight: float = Field(1.0, ge=0.0, le=1.0)
    context_data: dict[str, Any] = Field(default_factory=dict)


class AgentFinding(BaseModel):
    finding_id: UUID = Field(default_factory=uuid4)
    domain: AgentDomain
    verdict: AgentVerdict
    confidence: float = Field(..., ge=0.0, le=1.0, description="Calibrated agent confidence")
    evidence_items: list[Evidence] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(
        default_factory=list, description="Technique IDs, e.g. T1059.001"
    )
    reasoning_summary: str = Field(..., min_length=10)
    uncertainty_factors: list[str] = Field(default_factory=list)
    recommended_queries: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AgentRunRecord(BaseModel):
    run_id: UUID = Field(default_factory=uuid4)
    incident_id: UUID
    domain: AgentDomain
    status: str = "COMPLETED"
    execution_latency_ms: float = Field(..., ge=0.0)
    prompt_tokens: int = Field(0, ge=0)
    completion_tokens: int = Field(0, ge=0)
    finding: AgentFinding
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
