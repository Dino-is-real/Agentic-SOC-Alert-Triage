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

export interface AnalyticsData {
  total_runs: number;
  executive_kpis: {
    total_runs: number;
    malicious_count: number;
    suspicious_count: number;
    benign_count: number;
    auto_suggest_count: number;
    escalated_count: number;
    auto_suggest_rate_pct: number;
    escalated_rate_pct: number;
    mean_trust_score: number;
    median_trust_score: number;
    std_dev_trust: number;
    avg_agents_per_run: number;
    mean_routing_latency_ms: number;
    mean_pipeline_latency_ms: number;
    approvals_summary: {
      approved: number;
      rejected: number;
      pending: number;
    };
  };
  trust_distribution: {
    bins: Array<{ range: string; count: number; pct: number }>;
    threshold: number;
    reason_codes: Record<string, number>;
    ece: number;
    brier_score: number;
  };
  domain_routing_analytics: {
    domain_names: string[];
    domain_activation_counts: Record<string, number>;
    domain_activation_pct: Record<string, number>;
    avg_domain_confidences: Record<string, number>;
    co_activation_matrix: number[][];
  };
  mitre_attack_analytics: {
    technique_frequencies: Array<{
      technique_id: string;
      name: string;
      tactic: string;
      count: number;
    }>;
    tactic_distribution: Record<string, number>;
  };
  latency_telemetry: {
    stage_breakdown_ms: {
      routing: number;
      specialist_analysis: number;
      synthesis: number;
      trust_gate: number;
      playbook_generation: number;
    };
    run_timeline: Array<{
      run_index: number;
      incident_id: string;
      signature: string;
      timestamp: string;
      latency_ms: number;
      trust_score: number;
      decision: string;
      verdict: string;
      domains_count: number;
      severity: string;
      source_format: string;
    }>;
  };
  containment_action_analytics: {
    action_types_distribution: Record<string, number>;
  };
  incident_runs: Array<any>;
}
