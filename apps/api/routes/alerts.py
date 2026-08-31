"""Alert Ingestion and Normalization API Endpoints."""
from typing import Any
from fastapi import APIRouter, HTTPException, status
from src.domain.models import NormalizedAlert
from src.ingestion.normalizer import AlertNormalizer

router = APIRouter(prefix="/alerts", tags=["Alerts"])
normalizer = AlertNormalizer()


@router.post("/ingest", response_model=NormalizedAlert, status_code=status.HTTP_201_CREATED)
async def ingest_raw_alert(payload: dict[str, Any]):
    """Ingests and normalizes a raw vendor SIEM/sensor alert."""
    try:
        normalized = normalizer.normalize(payload)
        return normalized
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Failed to normalize alert payload: {str(e)}",
        )
