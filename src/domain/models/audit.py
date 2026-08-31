"""Audit Event Models with Cryptographic Integrity Chaining."""
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4
from pydantic import BaseModel, Field


class AuditEvent(BaseModel):
    event_id: UUID = Field(default_factory=uuid4)
    incident_id: UUID
    event_type: str
    actor: str
    action: str
    state_before: dict[str, Any] = Field(default_factory=dict)
    state_after: dict[str, Any] = Field(default_factory=dict)
    previous_integrity_hash: str = "GENESIS"
    integrity_hash: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
