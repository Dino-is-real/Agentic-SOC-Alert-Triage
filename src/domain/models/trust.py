"""Trust Score Assessment Domain Models."""
from datetime import datetime, timezone
from uuid import UUID, uuid4
from pydantic import BaseModel, Field
from src.domain.enums import TrustDecision


class TrustWeights(BaseModel):
    w_C: float = Field(0.50, ge=0.0, le=1.0, description="Weight for agent consensus")
    w_H: float = Field(0.30, ge=0.0, le=1.0, description="Weight for historical similarity")
    w_S: float = Field(0.20, ge=0.0, le=1.0, description="Weight for severity penalty")


class TrustComponentBreakdown(BaseModel):
    consensus_score: float = Field(..., ge=0.0, le=1.0, description="C_consensus")
    historical_similarity: float = Field(..., ge=0.0, le=1.0, description="H")
    severity_penalty: float = Field(..., ge=0.0, le=1.0, description="S_penalty")
    weighted_consensus: float
    weighted_historical: float
    weighted_penalty: float


class TrustAssessment(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    incident_id: UUID
    trust_score: float = Field(..., ge=0.0, le=1.0, description="Final clamped T in [0, 1]")
    threshold: float = Field(0.65, ge=0.0, le=1.0)
    decision: TrustDecision
    components: TrustComponentBreakdown
    weights: TrustWeights = Field(default_factory=TrustWeights)
    reason_codes: list[str] = Field(default_factory=list)
    calculation_version: str = Field(default="v1.0.0")
    calculated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
