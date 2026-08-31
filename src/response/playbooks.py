"""Response Playbook Generation Engine."""
from uuid import UUID, uuid4
from src.domain.enums import ActionType, AlertSeverity, AgentVerdict
from src.domain.models import (
    NormalizedAlert,
    ConsensusAssessment,
    Playbook,
    RecommendedAction,
)


class PlaybookGenerator:
    """Generates structured, safe declarative response playbooks tailored to incident findings."""

    def generate_playbook(
        self,
        incident_id: UUID,
        alert: NormalizedAlert,
        consensus: ConsensusAssessment,
    ) -> Playbook:
        actions: list[RecommendedAction] = []

        # 1. Host Isolation if Endpoint/Malware is Malicious
        if alert.endpoint.hostname and consensus.overall_verdict == AgentVerdict.MALICIOUS:
            actions.append(
                RecommendedAction(
                    action_id=uuid4(),
                    action_type=ActionType.SIMULATE_HOST_ISOLATION,
                    target_entity=alert.endpoint.hostname,
                    parameters={"hostname": alert.endpoint.hostname, "network_quarantine_mode": "strict"},
                    rationale=f"Isolate host {alert.endpoint.hostname} to prevent lateral movement and C2 communications.",
                    risk_level=AlertSeverity.HIGH,
                    is_reversible=True,
                )
            )

        # 2. Block Source IP at Perimeter Firewall
        if alert.network.src_ip and consensus.overall_verdict in [AgentVerdict.MALICIOUS, AgentVerdict.SUSPICIOUS]:
            # Don't block private RFC1918 IPs at perimeter
            is_private = any(
                alert.network.src_ip.startswith(prefix) for prefix in ["10.", "192.168.", "172.16.", "127."]
            )
            if not is_private:
                actions.append(
                    RecommendedAction(
                        action_id=uuid4(),
                        action_type=ActionType.SIMULATE_IP_BLOCK,
                        target_entity=alert.network.src_ip,
                        parameters={"ip_address": alert.network.src_ip, "direction": "ingress/egress", "duration_hours": 24},
                        rationale=f"Block malicious external source IP {alert.network.src_ip} at edge firewalls.",
                        risk_level=AlertSeverity.MEDIUM,
                        is_reversible=True,
                    )
                )

        # 3. Revoke Active User Sessions
        if alert.identity.username and consensus.overall_verdict == AgentVerdict.MALICIOUS:
            actions.append(
                RecommendedAction(
                    action_id=uuid4(),
                    action_type=ActionType.SIMULATE_SESSION_REVOCATION,
                    target_entity=alert.identity.username,
                    parameters={"username": alert.identity.username, "revoke_refresh_tokens": True},
                    rationale=f"Revoke all active SSO/OAuth sessions for user {alert.identity.username}.",
                    risk_level=AlertSeverity.LOW,
                    is_reversible=True,
                )
            )

        # 4. Forensic Triage Collection
        actions.append(
            RecommendedAction(
                action_id=uuid4(),
                action_type=ActionType.COLLECT_FORENSIC_TRIAGE,
                target_entity=alert.endpoint.hostname or alert.network.src_ip or "Target-Asset",
                parameters={"artifacts": ["memory_dump_meta", "mft_records", "netstat", "syslog"]},
                rationale="Collect non-destructive volatile memory artifacts and system event logs.",
                risk_level=AlertSeverity.LOW,
                is_reversible=True,
            )
        )

        # 5. Notify Tier-2 SOC
        actions.append(
            RecommendedAction(
                action_id=uuid4(),
                action_type=ActionType.NOTIFY_SOC_TIER2,
                target_entity="SOC-Tier2-OnCall",
                parameters={"channel": "pagerduty/slack", "priority": alert.raw_severity.value},
                rationale="Dispatch alert notification and incident dossier to on-call security engineering team.",
                risk_level=AlertSeverity.LOW,
                is_reversible=True,
            )
        )

        title = f"Remediation Playbook: {alert.signature} ({consensus.overall_verdict.value.upper()})"
        return Playbook(
            playbook_id=uuid4(),
            incident_id=incident_id,
            title=title,
            actions=actions,
            suggested_by="AdaptiveTrustEngine",
        )
