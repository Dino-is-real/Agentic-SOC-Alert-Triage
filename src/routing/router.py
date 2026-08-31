"""Adaptive Multi-Label Expert Router Engine."""
import time
from uuid import uuid4
from src.core.config import settings
from src.core.logging import logger
from src.domain.enums import AgentDomain
from src.domain.models import NormalizedAlert, RoutingDecision
from src.routing.classifier import MultiLabelClassifier


class AdaptiveRouter:
    """Evaluates normalized alerts and deterministically routes them to relevant domain specialists."""

    def __init__(
        self,
        classifier: MultiLabelClassifier | None = None,
        threshold: float | None = None,
        fallback_threshold: float = 0.35,
    ):
        self.classifier = classifier or MultiLabelClassifier()
        self.threshold = threshold if threshold is not None else settings.ROUTER_CONFIDENCE_THRESHOLD
        self.fallback_threshold = fallback_threshold

    def route(self, alert: NormalizedAlert) -> RoutingDecision:
        """Computes domain probabilities and returns the routing decision."""
        start_time = time.perf_counter()

        probs = self.classifier.predict_proba(alert)

        # Select domains exceeding threshold
        selected_domains = [domain for domain, prob in probs.items() if prob >= self.threshold]

        # Safety Fallback: If no domains exceed threshold or all below fallback, select top-2
        if not selected_domains:
            sorted_by_prob = sorted(probs.items(), key=lambda item: item[1], reverse=True)
            selected_domains = [sorted_by_prob[0][0], sorted_by_prob[1][0]]
            logger.warning(
                "No domain exceeded routing threshold; activated safety fallback top-2 specialists",
                extra={
                    "alert_id": str(alert.alert_id),
                    "fallback_domains": [d.value for d in selected_domains],
                },
            )

        latency_ms = round((time.perf_counter() - start_time) * 1000.0, 3)

        decision = RoutingDecision(
            id=uuid4(),
            alert_id=alert.alert_id,
            model_version="v1.0.0-gbc",
            probabilities=probs,
            selected_domains=selected_domains,
            threshold_applied=self.threshold,
            routing_latency_ms=latency_ms,
        )

        logger.info(
            "Adaptive routing complete",
            extra={
                "alert_id": str(alert.alert_id),
                "selected_domains": [d.value for d in selected_domains],
                "latency_ms": latency_ms,
            },
        )

        return decision
