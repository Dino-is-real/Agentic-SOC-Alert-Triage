"""Unit Tests for Trust Score Engine (Gate 03) and Calibration."""
import pytest
from uuid import uuid4
from src.domain.enums import AlertSeverity, AgentVerdict, TrustDecision
from src.domain.models import ConsensusAssessment, ConflictDetail
from src.trust import TrustScoreEngine, TrustCalibrator


def test_standard_high_trust_auto_suggest():
    engine = TrustScoreEngine(threshold=0.65)
    incident_id = uuid4()
    consensus = ConsensusAssessment(
        overall_verdict=AgentVerdict.MALICIOUS,
        consensus_score=0.92,
        has_conflict=False,
    )
    assessment = engine.evaluate_trust(
        incident_id=incident_id,
        consensus=consensus,
        historical_score=0.80,
        raw_severity=AlertSeverity.LOW,
        asset_criticality=AlertSeverity.LOW,
    )
    # T = 0.50(0.92) + 0.30(0.80) - 0.20(0.14) = 0.46 + 0.24 - 0.028 = 0.672
    assert assessment.trust_score >= 0.65
    assert assessment.decision == TrustDecision.AUTO_SUGGEST
    assert "RC_HIGH_CONSENSUS" in assessment.reason_codes
    assert "RC_HIGH_HISTORICAL_MATCH" in assessment.reason_codes


def test_critical_asset_escalation():
    engine = TrustScoreEngine(threshold=0.65)
    incident_id = uuid4()
    consensus = ConsensusAssessment(
        overall_verdict=AgentVerdict.MALICIOUS,
        consensus_score=0.95,
        has_conflict=False,
    )
    # Critical Domain Controller / Payment Gateway
    assessment = engine.evaluate_trust(
        incident_id=incident_id,
        consensus=consensus,
        historical_score=0.85,
        raw_severity=AlertSeverity.CRITICAL,
        asset_criticality=AlertSeverity.CRITICAL,
    )
    # Penalty is 1.0 -> T = 0.50(0.95) + 0.30(0.85) - 0.20(1.0) = 0.475 + 0.255 - 0.20 = 0.53
    assert assessment.trust_score < 0.65
    assert assessment.decision == TrustDecision.ESCALATE_TO_HUMAN
    assert "RC_CRITICAL_ASSET_PENALTY" in assessment.reason_codes


def test_contradiction_escalation():
    engine = TrustScoreEngine(threshold=0.65)
    incident_id = uuid4()
    consensus = ConsensusAssessment(
        overall_verdict=AgentVerdict.SUSPICIOUS,
        consensus_score=0.35,
        has_conflict=True,
    )
    assessment = engine.evaluate_trust(
        incident_id=incident_id,
        consensus=consensus,
        historical_score=0.70,
        raw_severity=AlertSeverity.MEDIUM,
    )
    assert assessment.trust_score < 0.65
    assert assessment.decision == TrustDecision.ESCALATE_TO_HUMAN
    assert "RC_AGENT_CONFLICT" in assessment.reason_codes


def test_cold_start_reason_code():
    engine = TrustScoreEngine(threshold=0.65)
    incident_id = uuid4()
    consensus = ConsensusAssessment(
        overall_verdict=AgentVerdict.MALICIOUS,
        consensus_score=0.90,
        has_conflict=False,
    )
    assessment = engine.evaluate_trust(
        incident_id=incident_id,
        consensus=consensus,
        historical_score=0.0,
        raw_severity=AlertSeverity.MEDIUM,
    )
    assert "RC_COLD_START_NO_HISTORY" in assessment.reason_codes


def test_clamping_bounds():
    engine = TrustScoreEngine()
    incident_id = uuid4()
    # Case with extreme high penalty
    consensus_zero = ConsensusAssessment(
        overall_verdict=AgentVerdict.BENIGN,
        consensus_score=0.0,
        has_conflict=False,
    )
    assessment = engine.evaluate_trust(
        incident_id=incident_id,
        consensus=consensus_zero,
        historical_score=0.0,
        raw_severity=AlertSeverity.CRITICAL,
        asset_criticality=AlertSeverity.CRITICAL,
    )
    assert assessment.trust_score == 0.0


def test_calibration_ece_and_brier():
    calibrator = TrustCalibrator()
    preds = [0.9, 0.8, 0.7, 0.6, 0.2, 0.1]
    labels = [1, 1, 1, 0, 0, 0]

    ece = calibrator.calculate_ece(preds, labels, num_bins=5)
    brier = calibrator.calculate_brier_score(preds, labels)

    assert 0.0 <= ece <= 1.0
    assert 0.0 <= brier <= 1.0

    sweep = calibrator.threshold_sensitivity_sweep(preds, labels, thresholds=[0.50, 0.65, 0.80])
    assert len(sweep) == 3
    assert sweep[0]["threshold"] == 0.50
