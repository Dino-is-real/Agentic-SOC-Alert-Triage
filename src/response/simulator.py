"""Safe Simulation Response Execution Engine."""
from typing import Any
from uuid import uuid4
from src.core.logging import logger
from src.domain.enums import ActionType, ExecutionStatus, ExecutorType
from src.domain.models import ApprovalDecision, ExecutionResult, Playbook, RecommendedAction
from src.response.approval import ApprovalService


class SimulationExecutor:
    """Executes approved remediation actions in an isolated, non-destructive simulation sandbox."""

    def __init__(self, approval_service: ApprovalService):
        self.approval_service = approval_service

    def execute_playbook(
        self,
        decision_id: Any,
        playbook: Playbook,
    ) -> ExecutionResult:
        """Executes playbook actions iff cryptographically approved."""
        # 1. Enforce hard safety boundary
        decision = self.approval_service.verify_authorization_for_execution(decision_id)

        actions_to_run = decision.modified_actions if decision.modified_actions else playbook.actions
        action_logs: list[dict[str, Any]] = []

        for action in actions_to_run:
            log_entry = self._simulate_action(action)
            action_logs.append(log_entry)

        res = ExecutionResult(
            execution_id=uuid4(),
            decision_id=decision.decision_id,
            executor_type=ExecutorType.SIMULATION,
            status=ExecutionStatus.SIMULATED_SUCCESS,
            action_logs=action_logs,
        )

        logger.info(
            "Playbook simulated execution completed successfully",
            extra={
                "execution_id": str(res.execution_id),
                "decision_id": str(decision_id),
                "actions_executed": len(action_logs),
                "status": res.status.value,
            },
        )
        return res

    def _simulate_action(self, action: RecommendedAction) -> dict[str, Any]:
        """Simulates individual action and computes diff impact."""
        if action.action_type == ActionType.SIMULATE_HOST_ISOLATION:
            return {
                "action_type": action.action_type.value,
                "target": action.target_entity,
                "status": "SIMULATED_SUCCESS",
                "simulated_effect": f"Host '{action.target_entity}' network interfaces switched to quarantine VLAN.",
                "reversion_step": f"Reconnect host '{action.target_entity}' to standard production VLAN.",
                "blast_radius": "Single endpoint isolated; production services unaffected.",
            }

        elif action.action_type == ActionType.SIMULATE_IP_BLOCK:
            return {
                "action_type": action.action_type.value,
                "target": action.target_entity,
                "status": "SIMULATED_SUCCESS",
                "simulated_effect": f"Firewall rule added: DROP INGRESS/EGRESS from {action.target_entity}.",
                "reversion_step": f"Remove iptables/PaloAlto drop rule for {action.target_entity}.",
                "blast_radius": f"External IP {action.target_entity} blocked at boundary.",
            }

        elif action.action_type == ActionType.SIMULATE_SESSION_REVOCATION:
            return {
                "action_type": action.action_type.value,
                "target": action.target_entity,
                "status": "SIMULATED_SUCCESS",
                "simulated_effect": f"Active Okta/AzureAD refresh tokens revoked for user '{action.target_entity}'.",
                "reversion_step": "User must re-authenticate via MFA.",
                "blast_radius": f"User {action.target_entity} forced to re-authenticate.",
            }

        elif action.action_type == ActionType.COLLECT_FORENSIC_TRIAGE:
            return {
                "action_type": action.action_type.value,
                "target": action.target_entity,
                "status": "SIMULATED_SUCCESS",
                "simulated_effect": "Captured forensic snapshot (memory dump metadata + process tree).",
                "reversion_step": "None (non-destructive read-only operation).",
                "blast_radius": "Zero impact (read-only telemetry pull).",
            }

        else:
            return {
                "action_type": action.action_type.value,
                "target": action.target_entity,
                "status": "SIMULATED_SUCCESS",
                "simulated_effect": f"Notification dispatched for {action.target_entity}.",
                "reversion_step": "None.",
                "blast_radius": "Zero impact.",
            }
