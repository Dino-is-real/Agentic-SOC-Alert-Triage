"""Deterministic Trust Score Engine (Gate 03)."""
from typing import Optional
from uuid import UUID, uuid4
from src.core.config import settings
from src.core.logging import logger
from src.domain.enums import AlertSeverity, TrustDecision, AgentVerdict
from src.domain.models import (
    ConsensusAssessment,
    TrustAssessment,
    TrustComponentBreakdown,
    TrustWeights,
)


class TrustScoreEngine:
    """Computes closed-form, deterministic Trust Scores for SOC triage gating."""

    def __init__(
        self,
        weights: Optional[TrustWeights] = None,
        threshold: Optional[float] = None,
        version: str = "v1.0.0",
    ):
        self.weights = weights or TrustWeights(
            w_C=settings.TRUST_WEIGHT_CONSENSUS,
            w_H=settings.TRUST_WEIGHT_HISTORICAL,
            w_S=settings.TRUST_WEIGHT_PENALTY,
        )
        self.threshold = threshold if threshold is not None else settings.TRUST_DEFAULT_THRESHOLD
        self.version = version

    def compute_asset_severity_penalty(
        self,
        raw_severity: AlertSeverity,
        asset_criticality: AlertSeverity = AlertSeverity.MEDIUM,
        is_privileged_user: bool = False,
    ) -> float:
        """Calculates normalized severity impact penalty S_penalty in [0, 1]."""
        sev_map = {
            AlertSeverity.LOW: 0.20,
            AlertSeverity.MEDIUM: 0.50,
            AlertSeverity.HIGH: 0.75,
            AlertSeverity.CRITICAL: 1.0,
        }
        crit_map = {
            AlertSeverity.LOW: 0.10,
            AlertSeverity.MEDIUM: 0.40,
            AlertSeverity.HIGH: 0.75,
            AlertSeverity.CRITICAL: 1.0,
        }

        s_alert = sev_map.get(raw_severity, 0.50)
        s_crit = crit_map.get(asset_criticality, 0.40)
        if is_privileged_user:
            s_crit = min(1.0, s_crit + 0.20)

        # Formula: S_penalty = 0.60 * Criticality + 0.40 * Severity
        penalty = 0.60 * s_crit + 0.40 * s_alert
        return round(max(0.0, min(1.0, penalty)), 4)

    def evaluate_trust(
        self,
        incident_id: UUID,
        consensus: ConsensusAssessment,
        historical_score: float,
        raw_severity: AlertSeverity = AlertSeverity.MEDIUM,
        asset_criticality: AlertSeverity = AlertSeverity.MEDIUM,
        is_privileged_user: bool = False,
        single_agent_invoked: bool = False,
    ) -> TrustAssessment:
        """Evaluates closed-form Trust Score T and determines Gate 03 triage action."""
        C = max(0.0, min(1.0, consensus.consensus_score))
        H = max(0.0, min(1.0, historical_score))
        w_C = self.weights.w_C
        w_H = self.weights.w_H
        w_S = self.weights.w_S
        S = self.compute_asset_severity_penalty(raw_severity, asset_criticality, is_privileged_user)
        reason_codes: list[str] = []

        # Cold-Start Dynamic Normalization: If no historical cases exist, reallocate historical budget to consensus
        if H == 0.0:
            eff_w_C = round(w_C + w_H, 4)
            eff_w_H = 0.0
            reason_codes.append("RC_COLD_START_NO_HISTORY")
        else:
            eff_w_C = w_C
            eff_w_H = w_H
            if H >= 0.80:
                reason_codes.append("RC_HIGH_HISTORICAL_MATCH")

        # For verified benign activities, scale down asset penalty since no malicious attack is occurring
        if consensus.overall_verdict == AgentVerdict.BENIGN:
            S_eff = round(S * 0.5, 4)
        else:
            S_eff = S

        weighted_C = round(eff_w_C * C, 4)
        weighted_H = round(eff_w_H * H, 4)
        weighted_S = round(w_S * S_eff, 4)

        raw_trust = weighted_C + weighted_H - weighted_S
        clamped_trust = round(max(0.0, min(1.0, raw_trust)), 4)

        # Generate Reason Codes
        if C >= 0.85:
            reason_codes.append("RC_HIGH_CONSENSUS")
        if consensus.has_conflict:
            reason_codes.append("RC_AGENT_CONFLICT")
        if S >= 0.70:
            reason_codes.append("RC_CRITICAL_ASSET_PENALTY")
        if single_agent_invoked:
            reason_codes.append("RC_SINGLE_AGENT_DISPATCH")

        # Determine Decision Gate 03
        if clamped_trust >= self.threshold:
            decision = TrustDecision.AUTO_SUGGEST
        else:
            decision = TrustDecision.ESCALATE_TO_HUMAN

        breakdown = TrustComponentBreakdown(
            consensus_score=C,
            historical_similarity=H,
            severity_penalty=S,
            weighted_consensus=weighted_C,
            weighted_historical=weighted_H,
            weighted_penalty=weighted_S,
        )

        assessment = TrustAssessment(
            id=uuid4(),
            incident_id=incident_id,
            trust_score=clamped_trust,
            threshold=self.threshold,
            decision=decision,
            components=breakdown,
            weights=self.weights,
            reason_codes=reason_codes,
            calculation_version=self.version,
        )

        logger.info(
            "Trust assessment evaluated (Gate 03)",
            extra={
                "incident_id": str(incident_id),
                "trust_score": clamped_trust,
                "threshold": self.threshold,
                "decision": decision.value,
                "reason_codes": reason_codes,
            },
        )

        return assessment
