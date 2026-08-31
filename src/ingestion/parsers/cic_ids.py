"""CSE-CIC-IDS2018 / CIC-IDS Dataset Flow Parser."""
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4
from src.domain.enums import AlertSourceFormat, AlertSeverity
from src.domain.models import (
    NormalizedAlert,
    NormalizedNetworkContext,
    NormalizedEndpointContext,
    NormalizedIdentityContext,
    NormalizedCloudContext,
)
from src.ingestion.parsers.base import AlertParser


class CICIDSParser(AlertParser):
    """Parses CSE-CIC-IDS2018 Network Flow CSV/JSON records into NormalizedAlert."""

    def can_parse(self, raw_payload: dict[str, Any]) -> bool:
        return (
            ("Dst Port" in raw_payload or "dst_port" in raw_payload)
            and ("Flow Duration" in raw_payload or "flow_duration" in raw_payload or "Label" in raw_payload)
        )

    def parse(self, raw_payload: dict[str, Any]) -> NormalizedAlert:
        label = raw_payload.get("Label") or raw_payload.get("label", "Benign")
        is_attack = str(label).strip().lower() != "benign"

        # Severity mapping from attack label
        if not is_attack:
            severity = AlertSeverity.LOW
        elif any(k in label.lower() for k in ["ddos", "bot", "infiltration", "heartbleed"]):
            severity = AlertSeverity.CRITICAL
        elif any(k in label.lower() for k in ["brute", "sql", "xss", "portscan"]):
            severity = AlertSeverity.HIGH
        else:
            severity = AlertSeverity.MEDIUM

        dst_port = raw_payload.get("Dst Port") or raw_payload.get("dst_port")
        protocol_num = raw_payload.get("Protocol") or raw_payload.get("protocol", "6")
        protocol = "TCP" if str(protocol_num) == "6" else ("UDP" if str(protocol_num) == "17" else "OTHER")

        tot_fwd_pkts = raw_payload.get("Tot Fwd Pkts") or raw_payload.get("tot_fwd_pkts", 0)
        tot_bwd_pkts = raw_payload.get("Tot Bwd Pkts") or raw_payload.get("tot_bwd_pkts", 0)

        network = NormalizedNetworkContext(
            src_ip=raw_payload.get("Src IP") or raw_payload.get("src_ip", "192.168.10.50"),
            dst_ip=raw_payload.get("Dst IP") or raw_payload.get("dst_ip", "172.16.0.1"),
            src_port=int(raw_payload.get("Src Port", 49152)) if str(raw_payload.get("Src Port", "")).isdigit() else 49152,
            dst_port=int(dst_port) if str(dst_port).isdigit() else 80,
            protocol=protocol,
            bytes_in=int(float(raw_payload.get("TotLen Fwd Pkts", 0))),
            bytes_out=int(float(raw_payload.get("TotLen Bwd Pkts", 0))),
            flags=[f"FwdPkts:{tot_fwd_pkts}", f"BwdPkts:{tot_bwd_pkts}"],
        )

        return NormalizedAlert(
            alert_id=uuid4(),
            source_format=AlertSourceFormat.CIC_IDS,
            timestamp=datetime.now(timezone.utc),
            signature=f"CIC-IDS Flow: {label}",
            raw_severity=severity,
            category="network_ids_flow",
            description=f"Flow duration: {raw_payload.get('Flow Duration', 0)} us, Label: {label}",
            network=network,
            endpoint=NormalizedEndpointContext(),
            identity=NormalizedIdentityContext(),
            cloud=NormalizedCloudContext(),
            raw_payload=raw_payload,
        )
