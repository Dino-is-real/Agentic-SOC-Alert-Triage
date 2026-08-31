"""Trust Score Calibration Metrics and Reliability Diagrams."""
from typing import Any
import numpy as np


class TrustCalibrator:
    """Calculates statistical calibration error, Brier score, and threshold sweeps."""

    @staticmethod
    def calculate_ece(
        predicted_scores: list[float],
        true_labels: list[int],
        num_bins: int = 10,
    ) -> float:
        """Calculates Expected Calibration Error (ECE)."""
        if not predicted_scores or len(predicted_scores) != len(true_labels):
            return 0.0

        preds = np.array(predicted_scores, dtype=np.float64)
        labels = np.array(true_labels, dtype=np.int32)
        N = len(preds)

        bin_boundaries = np.linspace(0.0, 1.0, num_bins + 1)
        ece = 0.0

        for i in range(num_bins):
            bin_lower = bin_boundaries[i]
            bin_upper = bin_boundaries[i + 1]

            in_bin = (preds >= bin_lower) & (preds < bin_upper if i < num_bins - 1 else preds <= bin_upper)
            bin_size = np.sum(in_bin)

            if bin_size > 0:
                bin_acc = np.mean(labels[in_bin])
                bin_conf = np.mean(preds[in_bin])
                ece += (bin_size / N) * abs(bin_acc - bin_conf)

        return round(float(ece), 4)

    @staticmethod
    def calculate_brier_score(
        predicted_scores: list[float],
        true_labels: list[int],
    ) -> float:
        """Calculates Brier Score (Mean Squared Calibration Error)."""
        if not predicted_scores or len(predicted_scores) != len(true_labels):
            return 0.0
        preds = np.array(predicted_scores, dtype=np.float64)
        labels = np.array(true_labels, dtype=np.int32)
        return round(float(np.mean((preds - labels) ** 2)), 4)

    @staticmethod
    def threshold_sensitivity_sweep(
        predicted_scores: list[float],
        true_labels: list[int],
        thresholds: list[float] | None = None,
    ) -> list[dict[str, Any]]:
        """Sweeps thresholds to analyze False Auto-Suggestion Rate vs Escalation Rate."""
        if thresholds is None:
            thresholds = [round(t, 2) for t in np.linspace(0.40, 0.90, 11)]

        preds = np.array(predicted_scores, dtype=np.float64)
        labels = np.array(true_labels, dtype=np.int32)
        N = len(preds)

        results: list[dict[str, Any]] = []
        for tau in thresholds:
            auto_suggest_mask = preds >= tau
            escalated_mask = preds < tau

            auto_suggest_count = int(np.sum(auto_suggest_mask))
            escalated_count = int(np.sum(escalated_mask))

            # False Auto Suggestion = Auto suggested, but true label was 0 (benign/false alarm)
            false_auto_suggest = int(np.sum(auto_suggest_mask & (labels == 0)))
            fasr = round((false_auto_suggest / max(1, auto_suggest_count)) * 100.0, 2)
            escalation_rate = round((escalated_count / max(1, N)) * 100.0, 2)

            results.append({
                "threshold": tau,
                "auto_suggest_count": auto_suggest_count,
                "escalated_count": escalated_count,
                "false_auto_suggest_count": false_auto_suggest,
                "false_auto_suggest_rate_pct": fasr,
                "escalation_rate_pct": escalation_rate,
            })

        return results
