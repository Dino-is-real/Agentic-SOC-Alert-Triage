"""Synthetic Test and Benchmark Alert Parser."""
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4
from src.domain.enums import AlertSourceFormat, AlertSeverity
from src.domain.models import (
    NormalizedAlert,
    NormalizedNetworkContext,
    NormalizedEndpointContext,
    NormalizedIdentityContext,
    NormalizedCloudContext,
)
from src.ingestion.parsers.base import AlertParser


class SyntheticParser(AlertParser):
    """Parses native synthetic benchmark JSON alerts into NormalizedAlert format."""

    def can_parse(self, raw_payload: dict[str, Any]) -> bool:
        return raw_payload.get("source_format") == "synthetic" or "signature" in raw_payload

    def parse(self, raw_payload: dict[str, Any]) -> NormalizedAlert:
        net_raw = raw_payload.get("network", {})
        end_raw = raw_payload.get("endpoint", {})
        id_raw = raw_payload.get("identity", {})
        cld_raw = raw_payload.get("cloud", {})

        alert_id_raw = raw_payload.get("alert_id")
        alert_id = UUID(alert_id_raw) if alert_id_raw else uuid4()

        severity_raw = str(raw_payload.get("raw_severity", "medium")).lower()
        severity_map = {
            "low": AlertSeverity.LOW,
            "medium": AlertSeverity.MEDIUM,
            "high": AlertSeverity.HIGH,
            "critical": AlertSeverity.CRITICAL,
        }
        severity = severity_map.get(severity_raw, AlertSeverity.MEDIUM)

        return NormalizedAlert(
            alert_id=alert_id,
            source_format=AlertSourceFormat.SYNTHETIC,
            timestamp=datetime.now(timezone.utc),
            signature=raw_payload.get("signature", "Synthetic Benchmark Alert"),
            raw_severity=severity,
            category=raw_payload.get("category", "benchmark"),
            description=raw_payload.get("description", ""),
            network=NormalizedNetworkContext(**net_raw),
            endpoint=NormalizedEndpointContext(**end_raw),
            identity=NormalizedIdentityContext(**id_raw),
            cloud=NormalizedCloudContext(**cld_raw),
            raw_payload=raw_payload,
        )
