"""Routing Domain Models and Probability Records."""
from datetime import datetime, timezone
from uuid import UUID, uuid4
from pydantic import BaseModel, Field
from src.domain.enums import AgentDomain


class RoutingDecision(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    alert_id: UUID
    model_version: str = "v1.0.0"
    probabilities: dict[AgentDomain, float] = Field(
        ..., description="Calibrated posterior probabilities per domain"
    )
    selected_domains: list[AgentDomain] = Field(
        ..., min_length=1, description="Domains exceeding routing threshold"
    )
    threshold_applied: float = Field(0.50, ge=0.0, le=1.0)
    routing_latency_ms: float = Field(..., ge=0.0)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
