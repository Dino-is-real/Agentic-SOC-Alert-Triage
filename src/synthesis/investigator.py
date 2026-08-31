"""Synthesis and Cross-Domain Investigation Coordinator."""
from typing import Optional
from src.domain.models import AgentFinding, ConsensusAssessment
from src.synthesis.consensus import ConsensusEngine
from src.synthesis.mitre import MitreSynthesisEngine
from src.core.logging import logger


class SynthesisInvestigator:
    """Orchestrates consensus computation, conflict resolution, and MITRE mapping."""

    def __init__(
        self,
        consensus_engine: Optional[ConsensusEngine] = None,
        mitre_engine: Optional[MitreSynthesisEngine] = None,
    ):
        self.consensus_engine = consensus_engine or ConsensusEngine()
        self.mitre_engine = mitre_engine or MitreSynthesisEngine()

    def synthesize(self, findings: list[AgentFinding]) -> ConsensusAssessment:
        logger.info("Synthesizing multi-agent findings", extra={"agent_count": len(findings)})

        assessment = self.consensus_engine.compute_consensus(findings)
        assessment.aggregated_mitre = self.mitre_engine.aggregate_techniques(findings)

        logger.info(
            "Synthesis complete",
            extra={
                "overall_verdict": assessment.overall_verdict.value,
                "consensus_score": assessment.consensus_score,
                "has_conflict": assessment.has_conflict,
                "mitre_count": len(assessment.aggregated_mitre),
            },
        )

        return assessment
