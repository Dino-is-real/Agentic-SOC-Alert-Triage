"""Splunk CIM Event and BOTS v2 Parser."""
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


class SplunkParser(AlertParser):
    """Parses Splunk CIM (Common Information Model) JSON events into NormalizedAlert."""

    def can_parse(self, raw_payload: dict[str, Any]) -> bool:
        return (
            "sourcetype" in raw_payload
            or "eventtype" in raw_payload
            or ("_raw" in raw_payload and "host" in raw_payload)
            or ("src" in raw_payload and "dest" in raw_payload and "tag" in raw_payload)
        )

    def parse(self, raw_payload: dict[str, Any]) -> NormalizedAlert:
        # Determine severity
        sev_raw = str(raw_payload.get("severity", raw_payload.get("urgency", "medium"))).lower()
        if sev_raw in ["critical", "crit", "5"]:
            severity = AlertSeverity.CRITICAL
        elif sev_raw in ["high", "4"]:
            severity = AlertSeverity.HIGH
        elif sev_raw in ["low", "informational", "info", "1", "2"]:
            severity = AlertSeverity.LOW
        else:
            severity = AlertSeverity.MEDIUM

        # Network Context
        network = NormalizedNetworkContext(
            src_ip=raw_payload.get("src") or raw_payload.get("src_ip"),
            dst_ip=raw_payload.get("dest") or raw_payload.get("dest_ip"),
            src_port=int(raw_payload["src_port"]) if "src_port" in raw_payload and str(raw_payload["src_port"]).isdigit() else None,
            dst_port=int(raw_payload["dest_port"]) if "dest_port" in raw_payload and str(raw_payload["dest_port"]).isdigit() else None,
            protocol=raw_payload.get("transport") or raw_payload.get("protocol"),
            bytes_in=int(raw_payload["bytes_in"]) if "bytes_in" in raw_payload and str(raw_payload["bytes_in"]).isdigit() else None,
            bytes_out=int(raw_payload["bytes_out"]) if "bytes_out" in raw_payload and str(raw_payload["bytes_out"]).isdigit() else None,
            dns_query=raw_payload.get("query") or raw_payload.get("dns"),
            http_uri=raw_payload.get("uri") or raw_payload.get("url"),
        )

        # Endpoint Context
        endpoint = NormalizedEndpointContext(
            hostname=raw_payload.get("host") or raw_payload.get("dest_nt_host"),
            process_name=raw_payload.get("process") or raw_payload.get("process_name"),
            process_id=int(raw_payload["process_id"]) if "process_id" in raw_payload and str(raw_payload["process_id"]).isdigit() else None,
            parent_process_name=raw_payload.get("parent_process"),
            command_line=raw_payload.get("CommandLine") or raw_payload.get("process_exec") or raw_payload.get("cmdline"),
            sha256=raw_payload.get("file_hash") or raw_payload.get("sha256"),
            md5=raw_payload.get("md5"),
            file_path=raw_payload.get("file_path") or raw_payload.get("file_name"),
            registry_key=raw_payload.get("registry_key_name"),
        )

        # Identity Context
        identity = NormalizedIdentityContext(
            username=raw_payload.get("user") or raw_payload.get("src_user"),
            user_domain=raw_payload.get("user_domain") or raw_payload.get("domain"),
            auth_status=raw_payload.get("action"),
            src_geo_country=raw_payload.get("src_country"),
        )

        # Cloud Context
        cloud = NormalizedCloudContext(
            cloud_provider=raw_payload.get("vendor_account"),
            account_id=raw_payload.get("account_id"),
            region=raw_payload.get("region"),
            resource_arn=raw_payload.get("arn"),
            event_name=raw_payload.get("eventName"),
        )

        signature = (
            raw_payload.get("rule_name")
            or raw_payload.get("signature")
            or raw_payload.get("sourcetype")
            or "Splunk Security Event"
        )
        category = str(raw_payload.get("sourcetype") or raw_payload.get("category", "splunk_event"))

        return NormalizedAlert(
            alert_id=uuid4(),
            source_format=AlertSourceFormat.SPLUNK,
            timestamp=datetime.now(timezone.utc),
            signature=signature,
            raw_severity=severity,
            category=category,
            description=raw_payload.get("description") or raw_payload.get("_raw", "")[:200],
            network=network,
            endpoint=endpoint,
            identity=identity,
            cloud=cloud,
            raw_payload=raw_payload,
        )
