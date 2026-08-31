"""Unit Tests for Specialist Domain Agents."""
import pytest
from uuid import uuid4
from src.domain.enums import AlertSourceFormat, AlertSeverity, AgentDomain, AgentVerdict
from src.domain.models import (
    NormalizedAlert,
    NormalizedNetworkContext,
    NormalizedEndpointContext,
    NormalizedIdentityContext,
    NormalizedCloudContext,
)
from src.agents import (
    NetworkSpecialistAgent,
    EndpointSpecialistAgent,
    IdentitySpecialistAgent,
    CloudSpecialistAgent,
    MalwareSpecialistAgent,
    ThreatIntelSpecialistAgent,
)


@pytest.mark.asyncio
async def test_network_specialist_agent():
    agent = NetworkSpecialistAgent()
    alert = NormalizedAlert(
        alert_id=uuid4(),
        source_format=AlertSourceFormat.CIC_IDS,
        signature="SYN Flood Port Scan",
        raw_severity=AlertSeverity.HIGH,
        network=NormalizedNetworkContext(src_ip="185.220.101.5", dst_ip="10.0.0.1", dst_port=80),
    )
    finding = await agent.analyze(alert)
    assert finding.domain == AgentDomain.NETWORK
    assert finding.verdict in [AgentVerdict.MALICIOUS, AgentVerdict.SUSPICIOUS]
    assert finding.confidence >= 0.80
    assert len(finding.evidence_items) >= 1
    assert "T1046" in finding.mitre_techniques or len(finding.mitre_techniques) > 0


@pytest.mark.asyncio
async def test_endpoint_specialist_agent():
    agent = EndpointSpecialistAgent()
    alert = NormalizedAlert(
        alert_id=uuid4(),
        source_format=AlertSourceFormat.SPLUNK,
        signature="Suspicious PowerShell Command",
        raw_severity=AlertSeverity.CRITICAL,
        endpoint=NormalizedEndpointContext(
            process_name="powershell.exe",
            command_line="powershell.exe -enc JABhID0A...",
        ),
    )
    finding = await agent.analyze(alert)
    assert finding.domain == AgentDomain.ENDPOINT
    assert finding.verdict == AgentVerdict.MALICIOUS
    assert finding.confidence >= 0.80
    assert len(finding.evidence_items) >= 1


@pytest.mark.asyncio
async def test_identity_specialist_agent():
    agent = IdentitySpecialistAgent()
    alert = NormalizedAlert(
        alert_id=uuid4(),
        source_format=AlertSourceFormat.WAZUH,
        signature="Brute Force SSH Login Failures",
        raw_severity=AlertSeverity.HIGH,
        identity=NormalizedIdentityContext(username="root", auth_status="FAILED", is_privileged=True),
    )
    finding = await agent.analyze(alert)
    assert finding.domain == AgentDomain.IDENTITY
    assert finding.verdict in [AgentVerdict.MALICIOUS, AgentVerdict.SUSPICIOUS]
    assert len(finding.evidence_items) >= 2


@pytest.mark.asyncio
async def test_cloud_specialist_agent():
    agent = CloudSpecialistAgent()
    alert = NormalizedAlert(
        alert_id=uuid4(),
        source_format=AlertSourceFormat.SYNTHETIC,
        signature="Unauthorized S3 Bucket Public Access Grant",
        raw_severity=AlertSeverity.CRITICAL,
        cloud=NormalizedCloudContext(
            cloud_provider="AWS",
            resource_arn="arn:aws:s3:::prod-customer-pii-data",
            event_name="PutBucketPolicy",
        ),
    )
    finding = await agent.analyze(alert)
    assert finding.domain == AgentDomain.CLOUD
    assert finding.verdict in [AgentVerdict.MALICIOUS, AgentVerdict.SUSPICIOUS]
    assert len(finding.evidence_items) >= 1


@pytest.mark.asyncio
async def test_malware_specialist_agent():
    agent = MalwareSpecialistAgent()
    alert = NormalizedAlert(
        alert_id=uuid4(),
        source_format=AlertSourceFormat.SYNTHETIC,
        signature="Trojan Execution Detected",
        raw_severity=AlertSeverity.CRITICAL,
        endpoint=NormalizedEndpointContext(
            sha256="44d88612fea8a8f36de82e1278abb02f",
            file_path="C:\\Users\\victim\\AppData\\Local\\Temp\\update.exe",
        ),
    )
    finding = await agent.analyze(alert)
    assert finding.domain == AgentDomain.MALWARE
    assert finding.verdict == AgentVerdict.MALICIOUS
    assert finding.confidence >= 0.90


@pytest.mark.asyncio
async def test_threat_intel_specialist_agent():
    agent = ThreatIntelSpecialistAgent()
    alert = NormalizedAlert(
        alert_id=uuid4(),
        source_format=AlertSourceFormat.SYNTHETIC,
        signature="Known C2 Beacon Connection",
        raw_severity=AlertSeverity.CRITICAL,
        network=NormalizedNetworkContext(
            src_ip="185.220.101.5",
            dns_query="c2-beacon.darknet.top",
        ),
    )
    finding = await agent.analyze(alert)
    assert finding.domain == AgentDomain.THREAT_INTEL
    assert finding.verdict == AgentVerdict.MALICIOUS
    assert len(finding.evidence_items) >= 1
