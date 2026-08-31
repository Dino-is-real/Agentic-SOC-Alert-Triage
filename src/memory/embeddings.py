"""Incident Dense Vector Embedding Generator."""
import hashlib
import numpy as np
from src.domain.models import NormalizedAlert, ConsensusAssessment


class IncidentEmbedder:
    """Generates normalized 64-dimensional dense semantic vectors representing incidents."""

    def __init__(self, embedding_dim: int = 64):
        self.embedding_dim = embedding_dim

    def generate_embedding(
        self,
        alert: NormalizedAlert,
        consensus: ConsensusAssessment | None = None,
    ) -> list[float]:
        """Generates a reproducible dense unit vector for an incident."""
        # Construct composite text signature
        components = [
            alert.signature,
            alert.category,
            alert.raw_severity.value,
            alert.endpoint.process_name or "",
            alert.endpoint.command_line or "",
            alert.network.protocol or "",
            str(alert.network.dst_port or ""),
            alert.identity.username or "",
            alert.cloud.event_name or "",
        ]
        if consensus:
            components.append(consensus.overall_verdict.value)
            components.extend(t.technique_id for t in consensus.aggregated_mitre)

        composite_text = " ".join(c for c in components if c)

        # Compute deterministic pseudo-random projection vector seeded by SHA-256 tokens
        vec = np.zeros(self.embedding_dim, dtype=np.float32)
        words = composite_text.lower().split()

        for word in words:
            h = hashlib.sha256(word.encode("utf-8")).digest()
            # Map hash chunks into float values
            for i in range(min(self.embedding_dim, len(h) // 2)):
                val = int.from_bytes(h[i * 2 : (i + 1) * 2], byteorder="little", signed=True) / 32768.0
                vec[i] = (vec[i] + val) * 0.5

        # L2-normalize to unit length
        norm = np.linalg.norm(vec)
        if norm > 0:
            vec = vec / norm
        else:
            vec[0] = 1.0

        return [round(float(x), 6) for x in vec]
