"""MITRE ATT&CK STIX 2.1 Provider and Technique Mapper."""
from typing import Optional
from pydantic import BaseModel
from src.domain.models import MITRETechnique


class MitreTechniqueDetails(BaseModel):
    technique_id: str
    name: str
    tactic: str
    description: str


class MitreAttackProvider:
    """Local MITRE Enterprise ATT&CK Knowledge Base."""

    TECHNIQUES_DB: dict[str, MitreTechniqueDetails] = {
        "T1059.001": MitreTechniqueDetails(
            technique_id="T1059.001",
            name="PowerShell",
            tactic="Execution",
            description="Adversaries may abuse PowerShell commands and scripts for execution.",
        ),
        "T1059.004": MitreTechniqueDetails(
            technique_id="T1059.004",
            name="Unix Shell",
            tactic="Execution",
            description="Adversaries may abuse Unix shell commands for execution.",
        ),
        "T1110.001": MitreTechniqueDetails(
            technique_id="T1110.001",
            name="Password Guessing",
            tactic="Credential Access",
            description="Adversaries may systematically guess passwords to gain unauthorized access.",
        ),
        "T1071.001": MitreTechniqueDetails(
            technique_id="T1071.001",
            name="Web Protocols (HTTP/S)",
            tactic="Command and Control",
            description="Adversaries may communicate using application layer protocols (HTTP/HTTPS).",
        ),
        "T1078.004": MitreTechniqueDetails(
            technique_id="T1078.004",
            name="Cloud Accounts",
            tactic="Defense Evasion",
            description="Adversaries may obtain and abuse credentials of cloud accounts.",
        ),
        "T1486": MitreTechniqueDetails(
            technique_id="T1486",
            name="Data Encrypted for Impact",
            tactic="Impact",
            description="Adversaries may encrypt data on target systems to interrupt availability (Ransomware).",
        ),
        "T1046": MitreTechniqueDetails(
            technique_id="T1046",
            name="Network Service Discovery",
            tactic="Discovery",
            description="Adversaries may attempt to enumerate network services using port scans.",
        ),
        "T1053.005": MitreTechniqueDetails(
            technique_id="T1053.005",
            name="Scheduled Task",
            tactic="Persistence",
            description="Adversaries may configure scheduled tasks to execute malicious binaries.",
        ),
        "T1543.003": MitreTechniqueDetails(
            technique_id="T1543.003",
            name="Windows Service",
            tactic="Persistence",
            description="Adversaries may create or modify Windows services to execute malicious commands.",
        ),
    }

    def get_technique(self, technique_id: str) -> Optional[MitreTechniqueDetails]:
        return self.TECHNIQUES_DB.get(technique_id)

    def map_technique(self, technique_id: str, confidence: float = 0.85) -> Optional[MITRETechnique]:
        details = self.get_technique(technique_id)
        if not details:
            return None
        return MITRETechnique(
            technique_id=details.technique_id,
            technique_name=details.name,
            tactic=details.tactic,
            confidence=confidence,
        )
