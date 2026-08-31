"""Incident Management and Retrieval API Endpoints."""
from typing import Any
from uuid import UUID
from fastapi import APIRouter, HTTPException, status
from apps.api.routes.investigations import INCIDENTS_STORE

router = APIRouter(prefix="/incidents", tags=["Incidents"])


@router.get("/", response_model=list[dict[str, Any]])
async def list_incidents():
    """Lists all active and resolved incidents."""
    summaries = []
    for inc_id, inc in INCIDENTS_STORE.items():
        alert = inc["normalized_alert"]
        trust = inc["trust_assessment"]
        consensus = inc["consensus_assessment"]
        summaries.append({
            "incident_id": str(inc_id),
            "signature": alert.signature,
            "severity": alert.raw_severity.value,
            "source_format": alert.source_format.value,
            "overall_verdict": consensus.overall_verdict.value,
            "trust_score": trust.trust_score,
            "decision": trust.decision.value,
            "created_at": alert.timestamp.isoformat(),
        })
    return summaries


@router.get("/{incident_id}", response_model=dict[str, Any])
async def get_incident(incident_id: UUID):
    """Fetches full dossier for a specific incident."""
    if incident_id not in INCIDENTS_STORE:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident {incident_id} not found.",
        )
    return INCIDENTS_STORE[incident_id]
