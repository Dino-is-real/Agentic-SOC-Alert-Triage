export type AlertSeverity = 'low' | 'medium' | 'high' | 'critical';
export type AgentDomain = 'network' | 'endpoint' | 'identity' | 'cloud' | 'malware' | 'threat_intel';
export type AgentVerdict = 'benign' | 'suspicious' | 'malicious' | 'insufficient_data';
export type TrustDecision = 'AUTO_SUGGEST' | 'ESCALATE_TO_HUMAN';
export type ApprovalStatus = 'PENDING' | 'APPROVED' | 'REJECTED' | 'MODIFIED' | 'EXPIRED';

export interface EvidenceItem {
  id: string;
  evidence_type: string;
  key: string;
  value: string;
  source: string;
  confidence_weight: number;
}

export interface AgentFinding {
  finding_id: string;
  domain: AgentDomain;
  verdict: AgentVerdict;
  confidence: number;
  evidence_items: EvidenceItem[];
  mitre_techniques: string[];
  reasoning_summary: string;
  uncertainty_factors: string[];
  recommended_queries: string[];
}

export interface MITRETechnique {
  technique_id: string;
  technique_name: string;
  tactic: string;
  confidence: number;
  mapped_by_agents: AgentDomain[];
}

export interface HistoricalCase {
  case_id: string;
  incident_title: string;
  similarity_score: number;
  historical_verdict: AgentVerdict;
  historical_trust_score: number;
  analyst_decision: ApprovalStatus;
  executed_playbook: string;
  outcome_summary: string;
}

export interface TrustComponentBreakdown {
  consensus_score: number;
  historical_similarity: number;
  severity_penalty: number;
  weighted_consensus: number;
  weighted_historical: number;
  weighted_penalty: number;
}

export interface TrustAssessment {
  id: string;
  incident_id: string;
  trust_score: number;
  threshold: number;
  decision: TrustDecision;
  components: TrustComponentBreakdown;
  reason_codes: string[];
  calculation_version: string;
}

export interface RecommendedAction {
  action_id: string;
  action_type: string;
  target_entity: string;
  parameters: Record<string, any>;
  rationale: string;
  risk_level: AlertSeverity;
  is_reversible: boolean;
}

export interface Playbook {
  playbook_id: string;
  incident_id: string;
  title: string;
  actions: RecommendedAction[];
  suggested_by: string;
}

export interface ApprovalRequest {
  request_id: string;
  incident_id: string;
  playbook_id: string;
  trust_score: number;
  status: ApprovalStatus;
  requested_at: string;
  expires_at: string;
}

export interface InvestigationDossier {
  incident_id: string;
  normalized_alert: {
    alert_id: string;
    source_format: string;
    signature: string;
    raw_severity: AlertSeverity;
    category: string;
    description: string;
    network?: any;
    endpoint?: any;
    identity?: any;
    cloud?: any;
    raw_payload: any;
  };
  routing_decision: {
    probabilities: Record<AgentDomain, number>;
    selected_domains: AgentDomain[];
    routing_latency_ms: number;
  };
  agent_findings: Record<string, AgentFinding>;
  consensus_assessment: {
    overall_verdict: AgentVerdict;
    consensus_score: number;
    has_conflict: boolean;
    aggregated_mitre: MITRETechnique[];
  };
  historical_cases: HistoricalCase[];
  trust_assessment: TrustAssessment;
  playbook: Playbook;
  approval_request: ApprovalRequest;
  audit_timeline: Array<{ stage: string; [key: string]: any }>;
}
