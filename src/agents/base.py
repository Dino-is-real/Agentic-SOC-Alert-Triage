"""Abstract Base Classes for Specialist Domain Agents."""
from abc import ABC, abstractmethod
from typing import Any, Optional
from src.domain.enums import AgentDomain
from src.domain.models import NormalizedAlert, AgentFinding, AgentRunRecord


class SpecialistAgent(ABC):
    """Abstract Base Class for all domain-specific security investigation agents."""

    def __init__(self, domain: AgentDomain):
        self.domain = domain

    @abstractmethod
    async def analyze(
        self,
        alert: NormalizedAlert,
        context: Optional[dict[str, Any]] = None,
    ) -> AgentFinding:
        """Executes deep domain analysis on the alert and returns structured AgentFinding."""
        pass
