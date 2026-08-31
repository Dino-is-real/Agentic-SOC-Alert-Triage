"""Unit Tests for Memory Subsystem."""
import pytest
import numpy as np
from uuid import uuid4
from src.domain.enums import AlertSourceFormat, AlertSeverity
from src.domain.models import NormalizedAlert, NormalizedEndpointContext
from src.memory import IncidentEmbedder, HistoricalIncidentMemory


def test_incident_embedder():
    embedder = IncidentEmbedder(embedding_dim=64)
    alert = NormalizedAlert(
        alert_id=uuid4(),
        source_format=AlertSourceFormat.SPLUNK,
        signature="PowerShell C2 Beaconing",
        raw_severity=AlertSeverity.HIGH,
        endpoint=NormalizedEndpointContext(process_name="powershell.exe", command_line="powershell -enc ..."),
    )
    vec = embedder.generate_embedding(alert)
    assert len(vec) == 64
    norm = np.linalg.norm(vec)
    assert np.isclose(norm, 1.0, atol=1e-3)


def test_historical_memory_retrieval():
    memory = HistoricalIncidentMemory()
    alert = NormalizedAlert(
        alert_id=uuid4(),
        source_format=AlertSourceFormat.SPLUNK,
        signature="Cobalt Strike PowerShell Beaconing",
        raw_severity=AlertSeverity.HIGH,
        description="powershell c2 beacon high 185.220.101.5",
    )
    cases, H_score = memory.retrieve_similar_cases(alert, top_k=2)
    assert len(cases) >= 1
    assert H_score >= 0.50
    assert "PowerShell" in cases[0].incident_title or "Beaconing" in cases[0].incident_title


def test_historical_memory_cold_start():
    memory = HistoricalIncidentMemory()
    novel_alert = NormalizedAlert(
        alert_id=uuid4(),
        source_format=AlertSourceFormat.SYNTHETIC,
        signature="Completely Novel Quantum Teleportation Attack Vector",
        raw_severity=AlertSeverity.LOW,
        description="xyz123 unique unseen payload",
    )
    cases, H_score = memory.retrieve_similar_cases(novel_alert, similarity_threshold=0.98)
    # High threshold on novel event should return cold start
    assert len(cases) == 0
    assert H_score == 0.0
