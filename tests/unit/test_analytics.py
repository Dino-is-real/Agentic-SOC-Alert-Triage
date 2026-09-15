"""Unit and Integration Tests for Real-Time Analytics Endpoints."""
import pytest
from httpx import AsyncClient, ASGITransport
from apps.api.main import app
from apps.api.routes.investigations import INCIDENTS_STORE


@pytest.mark.asyncio
async def test_analytics_empty_and_populated_telemetry():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 1. Test analytics when empty or initial
        resp = await client.get("/api/v1/metrics/analytics")
        assert resp.status_code == 200
        data = resp.json()
        assert "executive_kpis" in data
        assert "trust_distribution" in data
        assert "domain_routing_analytics" in data
        assert "mitre_attack_analytics" in data
        assert "latency_telemetry" in data
        assert "incident_runs" in data

        # 2. Test batch-seed endpoint
        seed_resp = await client.post("/api/v1/metrics/batch-seed")
        assert seed_resp.status_code == 200
        seed_data = seed_resp.json()
        assert seed_data["status"] == "success"
        assert seed_data["seeded_count"] >= 1

        # 3. Test analytics after seeding
        analytics_resp = await client.get("/api/v1/metrics/analytics")
        assert analytics_resp.status_code == 200
        analytics = analytics_resp.json()
        assert analytics["total_runs"] >= 1
        assert analytics["executive_kpis"]["total_runs"] >= 1
        assert len(analytics["domain_routing_analytics"]["domain_names"]) == 6
        assert len(analytics["domain_routing_analytics"]["co_activation_matrix"]) == 6
        assert len(analytics["trust_distribution"]["bins"]) == 5
        assert len(analytics["incident_runs"]) >= 1
