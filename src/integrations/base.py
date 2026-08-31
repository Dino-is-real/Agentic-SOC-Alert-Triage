"""Base Interfaces and Data Structures for Tool Integrations."""
from abc import ABC, abstractmethod
from typing import Any, Optional
from pydantic import BaseModel, Field


class ThreatIntelReport(BaseModel):
    observable: str
    observable_type: str  # "ip", "domain", "hash"
    reputation_score: float = Field(0.0, ge=0.0, le=1.0, description="Normalized risk: 0=benign, 1=malicious")
    is_malicious: bool = False
    verdict: str = "BENIGN"
    detections: int = 0
    total_engines: int = 0
    threat_actor: Optional[str] = None
    tags: list[str] = Field(default_factory=list)
    raw_details: dict[str, Any] = Field(default_factory=dict)


class ThreatIntelProvider(ABC):
    """Abstract Base Class for External Threat Intelligence Providers."""

    @abstractmethod
    async def lookup_ip(self, ip: str) -> ThreatIntelReport:
        pass

    @abstractmethod
    async def lookup_hash(self, file_hash: str) -> ThreatIntelReport:
        pass

    @abstractmethod
    async def lookup_domain(self, domain: str) -> ThreatIntelReport:
        pass
