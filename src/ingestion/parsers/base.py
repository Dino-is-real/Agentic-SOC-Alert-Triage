"""Base Alert Parser Interface."""
from abc import ABC, abstractmethod
from typing import Any
from src.domain.models import NormalizedAlert


class AlertParser(ABC):
    """Abstract Base Class for format-specific SIEM/Sensor alert parsers."""

    @abstractmethod
    def can_parse(self, raw_payload: dict[str, Any]) -> bool:
        """Determines if the given raw payload matches this parser's schema."""
        pass

    @abstractmethod
    def parse(self, raw_payload: dict[str, Any]) -> NormalizedAlert:
        """Transforms a raw vendor/dataset payload into a canonical NormalizedAlert."""
        pass
