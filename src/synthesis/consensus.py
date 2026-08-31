"""Consensus Calculation and Inter-Agent Contradiction Detection Engine."""
import math
from typing import Optional
from src.domain.enums import AgentDomain, AgentVerdict
from src.domain.models import AgentFinding, ConflictDetail, ConsensusAssessment, MITRETechnique


class ConsensusEngine:
    """Computes mathematical inter-agent agreement, variance, and contradiction penalties."""

    VERDICT_SCORES = {
        AgentVerdict.MALICIOUS: 1.0,
        AgentVerdict.SUSPICIOUS: 0.5,
        AgentVerdict.BENIGN: 0.0,
        AgentVerdict.INSUFFICIENT_DATA: 0.25,
    }

    def compute_consensus(self, findings: list[AgentFinding]) -> ConsensusAssessment:
        if not findings:
            return ConsensusAssessment(
                overall_verdict=AgentVerdict.INSUFFICIENT_DATA,
                consensus_score=0.0,
                has_conflict=False,
            )

        M = len(findings)
        weights = [f.confidence for f in findings]
        scores = [self.VERDICT_SCORES[f.verdict] for f in findings]
        sum_weights = sum(weights) + 1e-6

        # 1. Weighted Average Score
        weighted_mean = sum(w * s for w, s in zip(weights, scores)) / sum_weights

        # 2. Inter-Agent Variance & Contradiction Penalty
        variance = sum(w * ((s - weighted_mean) ** 2) for w, s in zip(weights, scores)) / sum_weights
        std_dev = math.sqrt(variance)
        contradiction_penalty = min(1.0, 2.0 * std_dev)

        # 3. Detect Explicit High-Confidence Conflict
        has_malicious = any(f.verdict == AgentVerdict.MALICIOUS and f.confidence >= 0.70 for f in findings)
        has_benign = any(f.verdict == AgentVerdict.BENIGN and f.confidence >= 0.70 for f in findings)
        has_conflict = has_malicious and has_benign or contradiction_penalty >= 0.40

        conflict_detail: Optional[ConflictDetail] = None
        if has_conflict:
            conflict_detail = ConflictDetail(
                conflicting_domains=[f.domain for f in findings],
                verdicts={f.domain: f.verdict for f in findings},
                confidences={f.domain: f.confidence for f in findings},
                disagreement_severity=round(contradiction_penalty, 4),
            )

        # 4. Uncertainty Factor Deduction
        total_uncertainties = sum(len(f.uncertainty_factors) for f in findings)
        mean_uncertainty_ratio = min(1.0, total_uncertainties / (M * 2.0))

        # 5. Base Consensus Computation
        mean_confidence = sum(weights) / M
        if M == 1:
            # Single specialist: 10% penalty for lack of multi-agent corroboration
            consensus_score = mean_confidence * (1.0 - 0.5 * mean_uncertainty_ratio) * 0.90
        else:
            consensus_score = mean_confidence * (1.0 - contradiction_penalty) * (1.0 - 0.5 * mean_uncertainty_ratio)

        consensus_score = max(0.0, min(1.0, consensus_score))

        # Determine Overall Verdict
        if weighted_mean >= 0.65:
            overall_verdict = AgentVerdict.MALICIOUS
        elif weighted_mean >= 0.35:
            overall_verdict = AgentVerdict.SUSPICIOUS
        elif weighted_mean < 0.20 and not has_malicious:
            overall_verdict = AgentVerdict.BENIGN
        else:
            overall_verdict = AgentVerdict.SUSPICIOUS

        return ConsensusAssessment(
            overall_verdict=overall_verdict,
            consensus_score=round(consensus_score, 4),
            has_conflict=has_conflict,
            conflict_details=conflict_detail,
        )
