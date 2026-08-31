"""Unit and Safety Tests for Response Playbooks and Human Approval Boundary."""
import pytest
from uuid import uuid4
from datetime import datetime, timezone, timedelta
from src.domain.enums import AlertSourceFormat, AlertSeverity, AgentVerdict, ApprovalStatus, ExecutionStatus
from src.domain.models import (
    NormalizedAlert,
    NormalizedNetworkContext,
    NormalizedEndpointContext,
    ConsensusAssessment,
)
from src.response import PlaybookGenerator, ApprovalService, SimulationExecutor


@pytest.fixture
def sample_malicious_alert():
    return NormalizedAlert(
        alert_id=uuid4(),
        source_format=AlertSourceFormat.SPLUNK,
        signature="Cobalt Strike Lateral Movement",
        raw_severity=AlertSeverity.HIGH,
        network=NormalizedNetworkContext(src_ip="194.26.29.112", dst_port=445),
        endpoint=NormalizedEndpointContext(hostname="FINANCE-WORKSTATION-01"),
    )


@pytest.fixture
def sample_consensus():
    return ConsensusAssessment(
        overall_verdict=AgentVerdict.MALICIOUS,
        consensus_score=0.92,
        has_conflict=False,
    )


def test_playbook_generation(sample_malicious_alert, sample_consensus):
    generator = PlaybookGenerator()
    incident_id = uuid4()
    playbook = generator.generate_playbook(incident_id, sample_malicious_alert, sample_consensus)

    assert playbook.incident_id == incident_id
    assert len(playbook.actions) >= 3
    action_types = [a.action_type.value for a in playbook.actions]
    assert "simulate_host_isolation" in action_types
    assert "simulate_ip_block" in action_types
    assert "collect_forensic_triage" in action_types


def test_approval_workflow_and_execution_success(sample_malicious_alert, sample_consensus):
    generator = PlaybookGenerator()
    approval_svc = ApprovalService()
    executor = SimulationExecutor(approval_service=approval_svc)

    incident_id = uuid4()
    playbook = generator.generate_playbook(incident_id, sample_malicious_alert, sample_consensus)

    # 1. Create pending approval request
    req = approval_svc.create_approval_request(incident_id, playbook, trust_score=0.78)
    assert req.status == ApprovalStatus.PENDING

    # 2. Analyst submits APPROVED decision
    decision = approval_svc.submit_decision(
        request_id=req.request_id,
        analyst_id="analyst_alice_tier2",
        decision=ApprovalStatus.APPROVED,
        analyst_notes="Host confirmed compromised via threat telemetry.",
    )
    assert decision.decision == ApprovalStatus.APPROVED
    assert len(decision.signature_token) > 0

    # 3. Execution succeeds in simulation mode
    result = executor.execute_playbook(decision.decision_id, playbook)
    assert result.status == ExecutionStatus.SIMULATED_SUCCESS
    assert len(result.action_logs) == len(playbook.actions)


def test_safety_invariant_rejected_execution_blocked(sample_malicious_alert, sample_consensus):
    generator = PlaybookGenerator()
    approval_svc = ApprovalService()
    executor = SimulationExecutor(approval_service=approval_svc)

    incident_id = uuid4()
    playbook = generator.generate_playbook(incident_id, sample_malicious_alert, sample_consensus)
    req = approval_svc.create_approval_request(incident_id, playbook, trust_score=0.55)

    # Analyst rejects playbook (false alarm)
    decision = approval_svc.submit_decision(
        request_id=req.request_id,
        analyst_id="analyst_bob_tier2",
        decision=ApprovalStatus.REJECTED,
        analyst_notes="Confirmed authorized penetration test activity.",
    )

    # Attempting to execute MUST raise PermissionError
    with pytest.raises(PermissionError, match="must be APPROVED"):
        executor.execute_playbook(decision.decision_id, playbook)


def test_safety_invariant_tampered_token_blocked(sample_malicious_alert, sample_consensus):
    generator = PlaybookGenerator()
    approval_svc = ApprovalService()
    executor = SimulationExecutor(approval_service=approval_svc)

    incident_id = uuid4()
    playbook = generator.generate_playbook(incident_id, sample_malicious_alert, sample_consensus)
    req = approval_svc.create_approval_request(incident_id, playbook, trust_score=0.85)

    decision = approval_svc.submit_decision(
        request_id=req.request_id,
        analyst_id="analyst_carol",
        decision=ApprovalStatus.APPROVED,
    )

    # Malicious actor tampers with signature token
    decision.signature_token = "forged_invalid_signature_hash_12345"

    with pytest.raises(PermissionError, match="signature mismatch"):
        executor.execute_playbook(decision.decision_id, playbook)


def test_safety_invariant_expired_approval_blocked(sample_malicious_alert, sample_consensus):
    generator = PlaybookGenerator()
    approval_svc = ApprovalService()

    incident_id = uuid4()
    playbook = generator.generate_playbook(incident_id, sample_malicious_alert, sample_consensus)
    req = approval_svc.create_approval_request(incident_id, playbook, trust_score=0.85, ttl_minutes=1)

    # Simulate expiration by moving expires_at into the past
    req.expires_at = datetime.now(timezone.utc) - timedelta(minutes=5)

    with pytest.raises(TimeoutError, match="expired"):
        approval_svc.submit_decision(
            request_id=req.request_id,
            analyst_id="analyst_david",
            decision=ApprovalStatus.APPROVED,
        )
