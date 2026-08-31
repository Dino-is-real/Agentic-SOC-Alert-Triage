"""Feature Engineering Pipeline for Alert Multi-Label Classification."""
from typing import Any
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from src.domain.models import NormalizedAlert


class AlertFeatureExtractor:
    """Transforms NormalizedAlert instances into numerical feature vectors."""

    def __init__(self, max_tfidf_features: int = 128):
        self.max_tfidf_features = max_tfidf_features
        self.vectorizer = TfidfVectorizer(
            max_features=max_tfidf_features,
            token_pattern=r"(?u)\b\w+\b",
            ngram_range=(1, 2),
            lowercase=True,
        )
        self._is_fitted = False

    def _extract_text_corpus(self, alert: NormalizedAlert) -> str:
        """Combines textual fields into a single token string."""
        tokens = [
            alert.signature or "",
            alert.category or "",
            alert.description or "",
            alert.endpoint.process_name or "",
            alert.endpoint.parent_process_name or "",
            alert.endpoint.command_line or "",
            alert.endpoint.file_path or "",
            alert.endpoint.registry_key or "",
            alert.network.dns_query or "",
            alert.network.http_uri or "",
            alert.network.protocol or "",
            alert.identity.username or "",
            alert.identity.auth_status or "",
            alert.cloud.cloud_provider or "",
            alert.cloud.event_name or "",
        ]
        return " ".join(t for t in tokens if t)

    def _extract_dense_features(self, alert: NormalizedAlert) -> np.ndarray:
        """Extracts structured indicator features."""
        # Indicator flags
        has_src_ip = 1.0 if alert.network.src_ip else 0.0
        has_dst_ip = 1.0 if alert.network.dst_ip else 0.0
        has_dst_port = 1.0 if alert.network.dst_port is not None else 0.0
        is_priv_port = 1.0 if (alert.network.dst_port or 65535) < 1024 else 0.0
        has_dns = 1.0 if alert.network.dns_query else 0.0
        has_http = 1.0 if alert.network.http_uri else 0.0

        has_process = 1.0 if alert.endpoint.process_name else 0.0
        has_cmdline = 1.0 if alert.endpoint.command_line else 0.0
        has_sha256 = 1.0 if alert.endpoint.sha256 else 0.0
        has_regkey = 1.0 if alert.endpoint.registry_key else 0.0

        has_user = 1.0 if alert.identity.username else 0.0
        has_auth_fail = 1.0 if str(alert.identity.auth_status).lower() in ["failed", "failure", "denied"] else 0.0
        is_privileged = 1.0 if alert.identity.is_privileged else 0.0

        has_cloud_arn = 1.0 if alert.cloud.resource_arn else 0.0
        has_cloud_event = 1.0 if alert.cloud.event_name else 0.0

        # Severity numerical mapping
        sev_map = {"low": 0.25, "medium": 0.50, "high": 0.75, "critical": 1.0}
        sev_val = sev_map.get(alert.raw_severity.value, 0.5)

        return np.array([
            has_src_ip, has_dst_ip, has_dst_port, is_priv_port, has_dns, has_http,
            has_process, has_cmdline, has_sha256, has_regkey,
            has_user, has_auth_fail, is_privileged,
            has_cloud_arn, has_cloud_event, sev_val
        ], dtype=np.float32)

    def fit(self, alerts: list[NormalizedAlert]) -> "AlertFeatureExtractor":
        """Fits the TF-IDF vocabulary on a collection of alerts."""
        texts = [self._extract_text_corpus(a) for a in alerts]
        self.vectorizer.fit(texts)
        self._is_fitted = True
        return self

    def transform_single(self, alert: NormalizedAlert) -> np.ndarray:
        """Transforms a single NormalizedAlert into a 1D feature vector."""
        if not self._is_fitted:
            # Fallback fit with default domain corpus if not explicitly fitted
            default_corpus = [
                "network packet flow ip port dns http ddos beacon scan",
                "endpoint process powershell cmd bash parent child dll registry",
                "identity auth login mfa user password brute force kerberos",
                "cloud aws iam assume role s3 bucket azure cloudtrail",
                "malware hash sha256 ransomware trojan payload evasion c2",
                "threat intel virustotal abuseipdb shodan apt indicator cve",
            ]
            self.vectorizer.fit(default_corpus)
            self._is_fitted = True

        text = self._extract_text_corpus(alert)
        text_vec = self.vectorizer.transform([text]).toarray()[0]
        dense_vec = self._extract_dense_features(alert)
        return np.concatenate([text_vec, dense_vec])

    def transform(self, alerts: list[NormalizedAlert]) -> np.ndarray:
        """Transforms a list of alerts into a 2D matrix."""
        return np.array([self.transform_single(a) for a in alerts])
