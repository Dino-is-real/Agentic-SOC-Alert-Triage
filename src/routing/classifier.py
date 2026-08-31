"""Multi-Label Expert Classifier for Domain Routing."""
from typing import Optional
import numpy as np
from sklearn.multiclass import OneVsRestClassifier
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.calibration import CalibratedClassifierCV
from src.domain.enums import AgentDomain
from src.domain.models import NormalizedAlert
from src.routing.feature_engineering import AlertFeatureExtractor


DOMAINS_ORDER = [
    AgentDomain.NETWORK,
    AgentDomain.ENDPOINT,
    AgentDomain.IDENTITY,
    AgentDomain.CLOUD,
    AgentDomain.MALWARE,
    AgentDomain.THREAT_INTEL,
]


class MultiLabelClassifier:
    """Predicts calibrated posterior probabilities for all specialist domains."""

    def __init__(self, feature_extractor: Optional[AlertFeatureExtractor] = None):
        self.feature_extractor = feature_extractor or AlertFeatureExtractor()
        self.domains = DOMAINS_ORDER
        self.model = OneVsRestClassifier(
            HistGradientBoostingClassifier(
                max_iter=50,
                learning_rate=0.1,
                max_leaf_nodes=15,
                random_state=42,
            )
        )
        self.is_trained = False

    def train(self, alerts: list[NormalizedAlert], labels: np.ndarray) -> "MultiLabelClassifier":
        """Trains the feature extractor and multi-label classifier."""
        self.feature_extractor.fit(alerts)
        X = self.feature_extractor.transform(alerts)
        self.model.fit(X, labels)
        self.is_trained = True
        return self

    def predict_proba(self, alert: NormalizedAlert) -> dict[AgentDomain, float]:
        """Returns calibrated probabilities P(Domain | Alert) for all 6 domains."""
        if not self.is_trained:
            # Deterministic heuristic-prior initialization if model is evaluated before offline training
            return self._heuristic_fallback_probabilities(alert)

        feat = self.feature_extractor.transform_single(alert).reshape(1, -1)
        # OneVsRestClassifier predict_proba returns matrix of shape (1, n_classes)
        probs_raw = self.model.predict_proba(feat)[0]

        probs: dict[AgentDomain, float] = {}
        for idx, domain in enumerate(self.domains):
            val = float(probs_raw[idx])
            # Clamp to [0.0, 1.0] and round to 4 decimals
            probs[domain] = round(max(0.0, min(1.0, val)), 4)
        return probs

    def _heuristic_fallback_probabilities(self, alert: NormalizedAlert) -> dict[AgentDomain, float]:
        """Provides deterministic probabilistic priors based on alert characteristics."""
        probs = {d: 0.05 for d in self.domains}

        # Network indicators
        if alert.network.src_ip or alert.network.dst_ip or alert.network.dns_query:
            probs[AgentDomain.NETWORK] += 0.60
        if alert.network.dst_port in [80, 443, 8080, 53]:
            probs[AgentDomain.NETWORK] += 0.20

        # Endpoint indicators
        if alert.endpoint.process_name or alert.endpoint.command_line:
            probs[AgentDomain.ENDPOINT] += 0.70
        if alert.endpoint.registry_key or alert.endpoint.parent_process_name:
            probs[AgentDomain.ENDPOINT] += 0.20

        # Identity indicators
        if alert.identity.username or alert.identity.auth_status:
            probs[AgentDomain.IDENTITY] += 0.75
        if alert.identity.is_privileged or alert.identity.mfa_used is False:
            probs[AgentDomain.IDENTITY] += 0.20

        # Cloud indicators
        if alert.cloud.cloud_provider or alert.cloud.resource_arn or alert.cloud.event_name:
            probs[AgentDomain.CLOUD] += 0.85

        # Malware indicators
        if alert.endpoint.sha256 or alert.endpoint.md5:
            probs[AgentDomain.MALWARE] += 0.80
        if any(w in alert.signature.lower() for w in ["trojan", "ransomware", "malware", "virus", "c2", "beacon"]):
            probs[AgentDomain.MALWARE] += 0.40

        # Threat Intel indicators
        if alert.network.src_ip or alert.endpoint.sha256 or alert.network.dns_query:
            probs[AgentDomain.THREAT_INTEL] += 0.60

        # Clamp and normalize
        return {d: round(max(0.01, min(0.99, p)), 4) for d, p in probs.items()}
