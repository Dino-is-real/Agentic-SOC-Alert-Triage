"""Alert Ingestion Pipeline."""
from typing import Any
from src.domain.models import NormalizedAlert
from src.ingestion.normalizer import AlertNormalizer
from src.core.logging import logger


class IngestionPipeline:
    """Orchestrates incoming alert normalization and audit tracking."""

    def __init__(self, normalizer: AlertNormalizer | None = None):
        self.normalizer = normalizer or AlertNormalizer()

    def process_raw_alert(self, raw_payload: dict[str, Any]) -> NormalizedAlert:
        """Normalizes raw input and logs ingestion audit event."""
        logger.info("Ingesting raw alert payload", extra={"payload_keys": list(raw_payload.keys())})
        normalized = self.normalizer.normalize(raw_payload)
        logger.info(
            "Alert normalized successfully",
            extra={
                "alert_id": str(normalized.alert_id),
                "source_format": normalized.source_format.value,
                "signature": normalized.signature,
                "severity": normalized.raw_severity.value,
            },
        )
        return normalized
