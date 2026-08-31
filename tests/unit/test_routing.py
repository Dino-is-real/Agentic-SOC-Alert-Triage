"""Unit Tests for Multi-Label Routing Subsystem."""
import pytest
from uuid import uuid4
from src.domain.enums import AlertSourceFormat, AlertSeverity, AgentDomain
from src.domain.models import (
    NormalizedAlert,
    NormalizedNetworkContext,
    NormalizedEndpointContext,
    NormalizedIdentityContext,
    NormalizedCloudContext,
)
from src.routing.feature_engineering import AlertFeatureExtractor
from src.routing.classifier import MultiLabelClassifier
from src.routing.router import AdaptiveRouter


@pytest.fixture
def sample_network_alert():
    return NormalizedAlert(
        alert_id=uuid4(),
        source_format=AlertSourceFormat.CIC_IDS,
        signature="SYN Flood Port Scan",
        raw_severity=AlertSeverity.HIGH,
        network=NormalizedNetworkContext(src_ip="192.168.1.10", dst_ip="10.0.0.1", dst_port=80, protocol="TCP"),
    )


@pytest.fixture
def sample_endpoint_alert():
    return NormalizedAlert(
        alert_id=uuid4(),
        source_format=AlertSourceFormat.SPLUNK,
        signature="Suspicious PowerShell Encoded Command",
        raw_severity=AlertSeverity.CRITICAL,
        endpoint=NormalizedEndpointContext(
            hostname="WIN-SRV-01",
            process_name="powershell.exe",
            command_line="powershell -enc W2V4ZWN1dGlvbl0...",
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
    )


def test_feature_extractor(sample_network_alert, sample_endpoint_alert):
    extractor = AlertFeatureExtractor(max_tfidf_features=64)
    vec1 = extractor.transform_single(sample_network_alert)
    vec2 = extractor.transform_single(sample_endpoint_alert)

    assert len(vec1) == 64 + 16
    assert len(vec2) == 64 + 16
    assert vec1.shape == (80,)


def test_classifier_probabilities(sample_endpoint_alert):
    classifier = MultiLabelClassifier()
    probs = classifier.predict_proba(sample_endpoint_alert)

    for domain in AgentDomain:
        assert domain in probs
        assert 0.0 <= probs[domain] <= 1.0

    # Endpoint, Malware, and Threat Intel should be high for this alert
    assert probs[AgentDomain.ENDPOINT] >= 0.70
    assert probs[AgentDomain.MALWARE] >= 0.70


def test_adaptive_router_dispatch(sample_network_alert):
    router = AdaptiveRouter(threshold=0.50)
    decision = router.route(sample_network_alert)

    assert decision.alert_id == sample_network_alert.alert_id
    assert AgentDomain.NETWORK in decision.selected_domains
    assert decision.routing_latency_ms >= 0.0
    assert len(decision.selected_domains) >= 1


def test_router_safety_fallback_empty():
    router = AdaptiveRouter(threshold=0.99)  # Ultra-high threshold
    minimal_alert = NormalizedAlert(
        alert_id=uuid4(),
        source_format=AlertSourceFormat.SYNTHETIC,
        signature="Generic Ambient Traffic",
        raw_severity=AlertSeverity.LOW,
    )
    decision = router.route(minimal_alert)

    # Even with threshold=0.99, safety fallback must guarantee at least 2 specialists
    assert len(decision.selected_domains) >= 2
