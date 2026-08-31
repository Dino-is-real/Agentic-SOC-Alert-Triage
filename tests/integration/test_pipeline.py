"""Integration Tests for End-to-End Multi-Agent LangGraph Pipeline."""
import pytest
from src.orchestration.graph import SOCGraphOrchestrator
from src.domain.enums import AgentDomain, TrustDecision, ApprovalStatus


@pytest.mark.asyncio
async def test_end_to_end_pipeline_splunk_powershell():
    orchestrator = SOCGraphOrchestrator()
    raw_payload = {
        "sourcetype": "WinEventLog:Security",
        "host": "FINANCE-PC-02",
        "CommandLine": "powershell.exe -enc JABhID0A... -WindowStyle Hidden",
        "process_name": "powershell.exe",
        "user": "victim_user",
        "severity": "high",
        "src_ip": "185.220.101.5",
        "dest_port": "443",
    }

    final_state = await orchestrator.run(raw_payload)

    # 1. Verification of Normalization
    assert final_state["normalized_alert"] is not None
    assert final_state["normalized_alert"].endpoint.hostname == "FINANCE-PC-02"

    # 2. Verification of Selective ML Routing
    assert final_state["routing_decision"] is not None
    active = final_state["active_domains"]
    assert AgentDomain.ENDPOINT in active or AgentDomain.MALWARE in active
    # Ensure not all 6 agents were blindly invoked (research contribution)
    assert len(active) <= 4

    # 3. Verification of Findings & Synthesis
    findings = final_state["agent_findings"]
    assert len(findings) == len(active)
    assert final_state["consensus_assessment"] is not None
    assert len(final_state["consensus_assessment"].aggregated_mitre) >= 1

    # 4. Verification of Memory & Trust Gate 03
    assert final_state["trust_assessment"] is not None
    assert 0.0 <= final_state["trust_assessment"].trust_score <= 1.0
    assert final_state["trust_assessment"].decision in [TrustDecision.AUTO_SUGGEST, TrustDecision.ESCALATE_TO_HUMAN]

    # 5. Verification of Playbook & Approval Gate
    assert final_state["playbook"] is not None
    assert len(final_state["playbook"].actions) >= 2
    assert final_state["approval_request"] is not None
    assert final_state["approval_request"].status == ApprovalStatus.PENDING

    # 6. Verification of Audit Timeline
    timeline = final_state["audit_timeline"]
    stages = [event["stage"] for event in timeline]
    assert "NORMALIZATION" in stages
    assert "ROUTING" in stages
    assert "SPECIALIST_INVESTIGATION" in stages
    assert "SYNTHESIS" in stages
    assert "TRUST_EVALUATION_GATE_03" in stages
    assert "MANDATORY_APPROVAL_GATE" in stages
