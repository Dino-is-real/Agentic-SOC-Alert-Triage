"""Synthesis, Consensus Assessment, and MITRE Domain Models."""
from typing import Optional
from uuid import UUID, uuid4
from pydantic import BaseModel, Field
from src.domain.enums import AgentDomain, AgentVerdict, ApprovalStatus


class MITRETechnique(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    mapped_by_agents: list[AgentDomain] = Field(default_factory=list)


class HistoricalCase(BaseModel):
    case_id: UUID = Field(default_factory=uuid4)
    incident_title: str
    similarity_score: float = Field(..., ge=0.0, le=1.0)
    historical_verdict: AgentVerdict
    historical_trust_score: float
    analyst_decision: ApprovalStatus
    executed_playbook: str
    outcome_summary: str


class ConflictDetail(BaseModel):
    conflicting_domains: list[AgentDomain]
    verdicts: dict[AgentDomain, AgentVerdict]
    confidences: dict[AgentDomain, float]
    disagreement_severity: float = Field(..., ge=0.0, le=1.0)


class ConsensusAssessment(BaseModel):
    overall_verdict: AgentVerdict
    consensus_score: float = Field(..., ge=0.0, le=1.0, description="C_consensus in Trust Formula")
    has_conflict: bool = False
    conflict_details: Optional[ConflictDetail] = None
    aggregated_mitre: list[MITRETechnique] = Field(default_factory=list)
