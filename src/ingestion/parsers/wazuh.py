"""Wazuh / OSSEC SIEM Alert Parser."""
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


class WazuhParser(AlertParser):
    """Parses Wazuh JSON log events and rule alerts into NormalizedAlert format."""

    def can_parse(self, raw_payload: dict[str, Any]) -> bool:
        return "rule" in raw_payload and ("agent" in raw_payload or "decoder" in raw_payload)

    def parse(self, raw_payload: dict[str, Any]) -> NormalizedAlert:
        rule = raw_payload.get("rule", {})
        agent = raw_payload.get("agent", {})
        data = raw_payload.get("data", {})
        decoder = raw_payload.get("decoder", {})

        # Map Wazuh rule level (0-16) to AlertSeverity
        level = rule.get("level", 5)
        if level >= 12:
            severity = AlertSeverity.CRITICAL
        elif level >= 8:
            severity = AlertSeverity.HIGH
        elif level >= 4:
            severity = AlertSeverity.MEDIUM
        else:
            severity = AlertSeverity.LOW

        # Extract Network Context
        network = NormalizedNetworkContext(
            src_ip=data.get("srcip") or data.get("src_ip"),
            dst_ip=data.get("dstip") or data.get("dst_ip"),
            src_port=int(data["srcport"]) if "srcport" in data and str(data["srcport"]).isdigit() else None,
            dst_port=int(data["dstport"]) if "dstport" in data and str(data["dstport"]).isdigit() else None,
            protocol=data.get("protocol") or data.get("proto"),
            dns_query=data.get("query") or data.get("dns_query"),
            http_uri=data.get("url") or data.get("http_uri"),
        )

        # Extract Endpoint Context
        endpoint = NormalizedEndpointContext(
            hostname=agent.get("name"),
            agent_id=str(agent.get("id")) if agent.get("id") is not None else None,
            os_type=agent.get("os", {}).get("name") if isinstance(agent.get("os"), dict) else None,
            process_name=data.get("process_name") or data.get("process"),
            process_id=int(data["process_id"]) if "process_id" in data and str(data["process_id"]).isdigit() else None,
            parent_process_name=data.get("parent_process"),
            command_line=data.get("command_line") or data.get("cmdline"),
            sha256=data.get("sha256") or data.get("hash"),
            md5=data.get("md5"),
            file_path=data.get("file_path") or data.get("file"),
            registry_key=data.get("registry_key"),
        )

        # Extract Identity Context
        identity = NormalizedIdentityContext(
            username=data.get("srcuser") or data.get("dstuser") or data.get("user"),
            user_id=data.get("uid"),
            user_domain=data.get("domain"),
            auth_status=data.get("auth_status"),
        )

        # Extract Cloud Context
        cloud = NormalizedCloudContext(
            cloud_provider=data.get("cloud_provider"),
            account_id=data.get("aws_account_id"),
            region=data.get("aws_region"),
            resource_arn=data.get("resource_arn"),
            event_name=data.get("event_name"),
        )

        # Parse Timestamp
        ts_raw = raw_payload.get("timestamp")
        timestamp = datetime.now(timezone.utc)
        if ts_raw:
            try:
                timestamp = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
            except Exception:
                pass

        groups = rule.get("groups", [])
        category = groups[0] if groups else decoder.get("name", "wazuh_alert")

        return NormalizedAlert(
            alert_id=uuid4(),
            source_format=AlertSourceFormat.WAZUH,
            timestamp=timestamp,
            signature=rule.get("description", "Wazuh Security Alert"),
            raw_severity=severity,
            category=category,
            description=rule.get("description", ""),
            network=network,
            endpoint=endpoint,
            identity=identity,
            cloud=cloud,
            raw_payload=raw_payload,
        )
