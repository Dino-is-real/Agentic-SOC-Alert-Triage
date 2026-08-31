"""Historical Incident Memory Repository with pgvector and In-Memory Vector Search."""
from typing import Optional
from uuid import UUID, uuid4
import numpy as np
from src.domain.enums import AgentVerdict, ApprovalStatus
from src.domain.models import HistoricalCase, NormalizedAlert, ConsensusAssessment
from src.memory.embeddings import IncidentEmbedder
from src.core.logging import logger


class HistoricalIncidentRecord:
    def __init__(
        self,
        case_id: UUID,
        title: str,
        embedding: list[float],
        verdict: AgentVerdict,
        trust_score: float,
        decision: ApprovalStatus,
        playbook: str,
        outcome: str,
        quality_score: float = 1.0,
    ):
        self.case_id = case_id
        self.title = title
        self.embedding = np.array(embedding, dtype=np.float32)
        self.verdict = verdict
        self.trust_score = trust_score
        self.decision = decision
        self.playbook = playbook
        self.outcome = outcome
        self.quality_score = quality_score


class HistoricalIncidentMemory:
    """Stores and retrieves historical incidents using cosine vector similarity."""

    def __init__(self, embedder: Optional[IncidentEmbedder] = None):
        self.embedder = embedder or IncidentEmbedder()
        self._records: list[HistoricalIncidentRecord] = []
        self._seed_default_historical_cases()

    def _seed_default_historical_cases(self) -> None:
        """Seeds standard verified historical incidents for retrieval benchmarks."""
        seeds = [
            (
                "Historical Scenario 101: Cobalt Strike C2 PowerShell Beaconing",
                "powershell cmd CommandLine WinEventLog Security 185.220.101.5 malicious c2 beacon t1059.001 critical 443",
                AgentVerdict.MALICIOUS,
                0.88,
                ApprovalStatus.APPROVED,
                "Isolate Host & Revoke User Session",
                "Successfully contained within 4 minutes. No lateral movement.",
            ),
            (
                "Historical Scenario 102: SSH Brute Force Against Jump Host",
                "auth ssh failed brute force root t1110.001 high 194.26.29.112 wazuh port 22 tcp",
                AgentVerdict.MALICIOUS,
                0.82,
                ApprovalStatus.APPROVED,
                "Block Source IP at Perimeter Firewall",
                "Automated IP block prevented credential compromise.",
            ),
            (
                "Historical Scenario 103: Automated Terraform CI/CD Deployment",
                "cloud aws iam assumerole s3 deploy benign t1078.004 low terraform",
                AgentVerdict.BENIGN,
                0.92,
                ApprovalStatus.APPROVED,
                "No Action Required (Whitelisted Pipeline)",
                "Verified legitimate scheduled deployment.",
            ),
            (
                "Historical Scenario 104: Ransomware Payload Dropper Execution",
                "malware sha256 44d88612fea8a8f36de82e1278abb02f svchost_updater ransomware lockbit critical dropper",
                AgentVerdict.MALICIOUS,
                0.95,
                ApprovalStatus.APPROVED,
                "Isolate Host & Kill Process Tree",
                "Binary terminated prior to volume shadow copy deletion.",
            ),
            (
                "Historical Scenario 105: High-Volume SYN Flood DDoS Attack",
                "network ddos syn flood port 80 traffic attack packet high flow duration",
                AgentVerdict.MALICIOUS,
                0.86,
                ApprovalStatus.APPROVED,
                "Activate Anti-DDoS Rate Limiting & Filter Flow",
                "Traffic scrubber mitigated volumetric flood.",
            ),
            (
                "Historical Scenario 106: Unauthorized AWS S3 Bucket Public ACL Policy Mutation",
                "cloud aws s3 bucket putbucketpolicy unverified contractor privileged critical",
                AgentVerdict.MALICIOUS,
                0.84,
                ApprovalStatus.APPROVED,
                "Restrict S3 Public Access & Revoke IAM Credentials",
                "Bucket ACL reverted to private; IAM access key deleted.",
            ),
            (
                "Historical Scenario 107: Benign Employee VPN Sign-In",
                "identity vpn auth success mfa true bob engineering united states low",
                AgentVerdict.BENIGN,
                0.89,
                ApprovalStatus.APPROVED,
                "No Action Required (Valid Multi-Factor Authentication)",
                "Standard authorized employee VPN session.",
            ),
        ]

        for title, text_desc, verdict, trust, decision, playbook, outcome in seeds:
            dummy_alert = NormalizedAlert(
                source_format="synthetic",
                signature=title,
                raw_severity="high",
                description=text_desc,
            )
            emb = self.embedder.generate_embedding(dummy_alert)
            self._records.append(
                HistoricalIncidentRecord(
                    case_id=uuid4(),
                    title=title,
                    embedding=emb,
                    verdict=verdict,
                    trust_score=trust,
                    decision=decision,
                    playbook=playbook,
                    outcome=outcome,
                    quality_score=1.0,
                )
            )

    def retrieve_similar_cases(
        self,
        alert: NormalizedAlert,
        consensus: Optional[ConsensusAssessment] = None,
        top_k: int = 3,
        similarity_threshold: float = 0.25,
    ) -> tuple[list[HistoricalCase], float]:
        """Retrieves top-K nearest historical incidents and computes H factor."""
        if not self._records:
            return [], 0.0

        query_emb = np.array(
            self.embedder.generate_embedding(alert, consensus), dtype=np.float32
        )

        scored_records: list[tuple[float, HistoricalIncidentRecord]] = []
        for rec in self._records:
            dot_product = np.dot(query_emb, rec.embedding)
            norm_q = np.linalg.norm(query_emb)
            norm_r = np.linalg.norm(rec.embedding)
            sim = dot_product / (norm_q * norm_r + 1e-7)
            sim = max(0.0, min(1.0, float(sim)))
            if sim >= similarity_threshold:
                scored_records.append((sim, rec))

        scored_records.sort(key=lambda x: x[0], reverse=True)
        top_matches = scored_records[:top_k]

        if not top_matches:
            logger.info("No historical matches found above similarity threshold; H=0.0 (Cold Start)")
            return [], 0.0

        historical_cases: list[HistoricalCase] = []
        similarity_scores: list[float] = []

        for sim, rec in top_matches:
            similarity_scores.append(sim * rec.quality_score)
            historical_cases.append(
                HistoricalCase(
                    case_id=rec.case_id,
                    incident_title=rec.title,
                    similarity_score=round(sim, 4),
                    historical_verdict=rec.verdict,
                    historical_trust_score=rec.trust_score,
                    analyst_decision=rec.decision,
                    executed_playbook=rec.playbook,
                    outcome_summary=rec.outcome,
                )
            )

        H_score = round(float(np.mean(similarity_scores)), 4)
        logger.info(
            "Historical retrieval complete",
            extra={"top_k_found": len(historical_cases), "H_score": H_score},
        )
        return historical_cases, H_score
