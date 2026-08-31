"""Mandatory Human Approval Gate and Cryptographic Token Verification."""
import hmac
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Optional
from uuid import UUID, uuid4
from src.core.config import settings
from src.core.logging import logger
from src.domain.enums import ApprovalStatus
from src.domain.models import (
    ApprovalRequest,
    ApprovalDecision,
    Playbook,
    RecommendedAction,
)


class ApprovalService:
    """Enforces non-bypassable human approval safety boundaries and HMAC token verification."""

    def __init__(self, secret_key: Optional[str] = None):
        self.secret_key = (secret_key or settings.SECRET_KEY).encode("utf-8")
        self._requests: dict[UUID, ApprovalRequest] = {}
        self._decisions: dict[UUID, ApprovalDecision] = {}

    def _generate_signature_token(
        self,
        request_id: UUID,
        analyst_id: str,
        decision: ApprovalStatus,
    ) -> str:
        """Generates HMAC-SHA256 cryptographic authorization token."""
        msg = f"{request_id}:{analyst_id}:{decision.value}".encode("utf-8")
        return hmac.new(self.secret_key, msg, hashlib.sha256).hexdigest()

    def create_approval_request(
        self,
        incident_id: UUID,
        playbook: Playbook,
        trust_score: float,
        ttl_minutes: int = 60,
    ) -> ApprovalRequest:
        """Creates and stages a new pending approval request."""
        now = datetime.now(timezone.utc)
        req = ApprovalRequest(
            request_id=uuid4(),
            incident_id=incident_id,
            playbook_id=playbook.playbook_id,
            trust_score=trust_score,
            status=ApprovalStatus.PENDING,
            requested_at=now,
            expires_at=now + timedelta(minutes=ttl_minutes),
        )
        self._requests[req.request_id] = req
        logger.info(
            "Approval request created (Gate 03 Stage)",
            extra={
                "request_id": str(req.request_id),
                "incident_id": str(incident_id),
                "trust_score": trust_score,
                "status": req.status.value,
            },
        )
        return req

    def submit_decision(
        self,
        request_id: UUID,
        analyst_id: str,
        decision: ApprovalStatus,
        analyst_notes: str = "",
        modified_actions: Optional[list[RecommendedAction]] = None,
    ) -> ApprovalDecision:
        """Records human analyst decision with cryptographic signature."""
        if request_id not in self._requests:
            raise KeyError(f"Approval request {request_id} not found.")

        req = self._requests[request_id]
        now = datetime.now(timezone.utc)

        if now > req.expires_at:
            req.status = ApprovalStatus.EXPIRED
            raise TimeoutError(f"Approval request {request_id} has expired.")

        if req.status != ApprovalStatus.PENDING:
            raise ValueError(f"Approval request {request_id} is already in state {req.status.value}.")

        # Verify analyst_id is not empty
        if not analyst_id or not analyst_id.strip():
            raise ValueError("analyst_id is required for approval verification.")

        # Update request state
        req.status = decision

        # Generate cryptographic token
        sig = self._generate_signature_token(request_id, analyst_id, decision)

        app_decision = ApprovalDecision(
            decision_id=uuid4(),
            request_id=request_id,
            analyst_id=analyst_id,
            decision=decision,
            analyst_notes=analyst_notes,
            modified_actions=modified_actions,
            signature_token=sig,
            decided_at=now,
        )
        self._decisions[app_decision.decision_id] = app_decision

        logger.info(
            "Human approval decision recorded",
            extra={
                "decision_id": str(app_decision.decision_id),
                "request_id": str(request_id),
                "analyst_id": analyst_id,
                "decision": decision.value,
            },
        )
        return app_decision

    def verify_authorization_for_execution(self, decision_id: UUID) -> ApprovalDecision:
        """Verifies that the decision is valid, signed, and authorized for execution."""
        if decision_id not in self._decisions:
            raise PermissionError(f"Decision ID {decision_id} not found. Execution blocked.")

        dec = self._decisions[decision_id]
        if dec.decision != ApprovalStatus.APPROVED:
            raise PermissionError(
                f"Execution blocked: Decision status is {dec.decision.value}, must be APPROVED."
            )

        # Verify HMAC signature integrity
        expected_sig = self._generate_signature_token(dec.request_id, dec.analyst_id, dec.decision)
        if not hmac.compare_digest(dec.signature_token, expected_sig):
            raise PermissionError("Cryptographic signature mismatch. Possible tampering detected.")

        return dec
