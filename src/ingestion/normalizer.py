"""Alert Normalizer Engine."""
import re
from typing import Any, Optional
from src.domain.models import NormalizedAlert
from src.ingestion.parsers import (
    AlertParser,
    WazuhParser,
    SplunkParser,
    CICIDSParser,
    SyntheticParser,
)


class AlertNormalizer:
    """Dispatches raw SIEM and sensor alert payloads to registered parsers and sanitizes normalized output."""

    def __init__(self, custom_parsers: Optional[list[AlertParser]] = None):
        self.parsers: list[AlertParser] = custom_parsers or [
            WazuhParser(),
            SplunkParser(),
            CICIDSParser(),
            SyntheticParser(),
        ]

    def _sanitize_string(self, val: Optional[str]) -> Optional[str]:
        if val is None:
            return None
        # Strip null bytes and control characters while preserving valid unicode
        cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", str(val))
        return cleaned.strip()

    def normalize(self, raw_payload: dict[str, Any]) -> NormalizedAlert:
        """Finds matching parser and produces a validated NormalizedAlert."""
        if not isinstance(raw_payload, dict):
            raise ValueError(f"Expected dict raw_payload, got {type(raw_payload).__name__}")

        matched_parser: Optional[AlertParser] = None
        for parser in self.parsers:
            if parser.can_parse(raw_payload):
                matched_parser = parser
                break

        if matched_parser is None:
            # Fallback to synthetic parser
            matched_parser = SyntheticParser()

        alert = matched_parser.parse(raw_payload)

        # Sanitize critical fields against malicious log injection
        alert.signature = self._sanitize_string(alert.signature) or "Unknown Alert"
        if alert.endpoint.command_line:
            alert.endpoint.command_line = self._sanitize_string(alert.endpoint.command_line)
        if alert.endpoint.process_name:
            alert.endpoint.process_name = self._sanitize_string(alert.endpoint.process_name)
        if alert.identity.username:
            alert.identity.username = self._sanitize_string(alert.identity.username)

        return alert
