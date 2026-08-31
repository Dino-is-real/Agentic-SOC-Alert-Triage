"""Integration Tests for FastAPI Endpoints."""
import pytest
from httpx import AsyncClient, ASGITransport
from apps.api.main import app
from src.domain.enums import ApprovalStatus


@pytest.mark.asyncio
async def test_api_healthcheck():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert data["trust_gate_threshold"] == 0.65


@pytest.mark.asyncio
async def test_api_investigation_and_approval_flow():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 1. Run investigation on raw alert
        alert_payload = {
            "sourcetype": "WinEventLog:Security",
            "host": "DC-PRIMARY-01",
            "CommandLine": "powershell.exe -enc JABhID0A...",
            "user": "administrator",
            "severity": "critical",
            "src_ip": "185.220.101.5",
        }
        inv_resp = await client.post("/api/v1/investigations/run", json=alert_payload)
        assert inv_resp.status_code == 200
        inv_data = inv_resp.json()

        incident_id = inv_data["incident_id"]
        trust_score = inv_data["trust_assessment"]["trust_score"]
        req_id = inv_data["approval_request"]["request_id"]
        assert 0.0 <= trust_score <= 1.0

        # 2. List incidents
        inc_resp = await client.get("/api/v1/incidents/")
        assert inc_resp.status_code == 200
        inc_list = inc_resp.json()
        assert any(inc["incident_id"] == incident_id for inc in inc_list)

        # 3. Submit analyst approval
        dec_resp = await client.post(
            f"/api/v1/approvals/{req_id}/decide",
            json={
                "analyst_id": "soc_senior_analyst_1",
                "decision": "APPROVED",
                "analyst_notes": "Verified malicious activity. Approved for simulation.",
            },
        )
        assert dec_resp.status_code == 200
        dec_data = dec_resp.json()
        decision_id = dec_data["decision_id"]
        assert dec_data["decision"] == "APPROVED"
        assert len(dec_data["signature_token"]) > 0

        # 4. Execute approved simulation
        exec_resp = await client.post(f"/api/v1/approvals/{decision_id}/execute")
        assert exec_resp.status_code == 200
        exec_data = exec_resp.json()
        assert exec_data["status"] == "SIMULATED_SUCCESS"
        assert len(exec_data["action_logs"]) >= 1

        # 5. Check metrics summary
        metrics_resp = await client.get("/api/v1/metrics/summary")
        assert metrics_resp.status_code == 200
        metrics = metrics_resp.json()
        assert metrics["total_incidents_triaged"] >= 1
        assert len(metrics["baseline_comparison"]) == 4
