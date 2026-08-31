"""Unit Tests for Synthesis and Consensus Subsystem."""
import pytest
from uuid import uuid4
from src.domain.enums import AgentDomain, AgentVerdict
from src.domain.models import AgentFinding
from src.synthesis.consensus import ConsensusEngine
from src.synthesis.investigator import SynthesisInvestigator


def test_unanimous_consensus():
    engine = ConsensusEngine()
    findings = [
        AgentFinding(
            finding_id=uuid4(),
            domain=AgentDomain.NETWORK,
            verdict=AgentVerdict.MALICIOUS,
            confidence=0.90,
            reasoning_summary="Observed port scan",
            mitre_techniques=["T1046"],
        ),
        AgentFinding(
            finding_id=uuid4(),
            domain=AgentDomain.ENDPOINT,
            verdict=AgentVerdict.MALICIOUS,
            confidence=0.92,
            reasoning_summary="Observed powershell LOLBAS",
            mitre_techniques=["T1059.001"],
        ),
    ]

    assessment = engine.compute_consensus(findings)
    assert assessment.overall_verdict == AgentVerdict.MALICIOUS
    assert assessment.consensus_score >= 0.85
    assert assessment.has_conflict is False


def test_explicit_agent_contradiction():
    engine = ConsensusEngine()
    findings = [
        AgentFinding(
            finding_id=uuid4(),
            domain=AgentDomain.NETWORK,
            verdict=AgentVerdict.MALICIOUS,
            confidence=0.91,
            reasoning_summary="Malicious C2 connection",
        ),
        AgentFinding(
            finding_id=uuid4(),
            domain=AgentDomain.IDENTITY,
            verdict=AgentVerdict.BENIGN,
            confidence=0.88,
            reasoning_summary="Legitimate employee login",
        ),
    ]

    assessment = engine.compute_consensus(findings)
    # Contradiction must trigger conflict flag and drastically reduce consensus score
    assert assessment.has_conflict is True
    assert assessment.conflict_details is not None
    assert assessment.consensus_score < 0.60
    assert assessment.conflict_details.disagreement_severity >= 0.40


def test_mitre_aggregation_and_corroboration():
    investigator = SynthesisInvestigator()
    findings = [
        AgentFinding(
            finding_id=uuid4(),
            domain=AgentDomain.NETWORK,
            verdict=AgentVerdict.MALICIOUS,
            confidence=0.85,
            reasoning_summary="Network beaconing",
            mitre_techniques=["T1071.001"],
        ),
        AgentFinding(
            finding_id=uuid4(),
            domain=AgentDomain.THREAT_INTEL,
            verdict=AgentVerdict.MALICIOUS,
            confidence=0.90,
            reasoning_summary="C2 domain match",
            mitre_techniques=["T1071.001"],
        ),
    ]

    assessment = investigator.synthesize(findings)
    assert len(assessment.aggregated_mitre) == 1
    tech = assessment.aggregated_mitre[0]
    assert tech.technique_id == "T1071.001"
    assert len(tech.mapped_by_agents) == 2
    # Confidence should be boosted from 0.85 to 0.90
    assert tech.confidence > 0.85
