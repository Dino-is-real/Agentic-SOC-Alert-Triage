"""MITRE ATT&CK Synthesis and Deduplication Engine."""
from typing import Optional
from src.domain.enums import AgentDomain
from src.domain.models import AgentFinding, MITRETechnique
from src.integrations.mitre import MitreAttackProvider


class MitreSynthesisEngine:
    """Aggregates and dedupes MITRE ATT&CK techniques from domain agent findings."""

    def __init__(self, provider: Optional[MitreAttackProvider] = None):
        self.provider = provider or MitreAttackProvider()

    def aggregate_techniques(self, findings: list[AgentFinding]) -> list[MITRETechnique]:
        technique_map: dict[str, MITRETechnique] = {}

        for finding in findings:
            for tech_id in finding.mitre_techniques:
                if tech_id not in technique_map:
                    mapped = self.provider.map_technique(tech_id, confidence=finding.confidence)
                    if mapped:
                        mapped.mapped_by_agents = [finding.domain]
                        technique_map[tech_id] = mapped
                    else:
                        # Unregistered technique fallback
                        technique_map[tech_id] = MITRETechnique(
                            technique_id=tech_id,
                            technique_name=f"Technique {tech_id}",
                            tactic="Defense Evasion",
                            confidence=finding.confidence,
                            mapped_by_agents=[finding.domain],
                        )
                else:
                    if finding.domain not in technique_map[tech_id].mapped_by_agents:
                        technique_map[tech_id].mapped_by_agents.append(finding.domain)
                    # Boost confidence when multiple domain agents corroborate technique
                    technique_map[tech_id].confidence = min(
                        0.99, round(technique_map[tech_id].confidence + 0.05, 3)
                    )

        return list(technique_map.values())
