# Domain Model & Typed Schema Specification

**Document Version:** 1.0.0  
**Specification Type:** Pydantic v2 Core Schemas & Entity Contracts  
**Enforcement:** Mandatory Type Validation on Ingestion, Inter-Agent Messaging, and Persistence  

---

## 1. Domain Enumerations (`src/domain/enums/`)

```python
from enum import Enum

class AlertSourceFormat(str, Enum):
    WAZUH = "wazuh"
    SPLUNK = "splunk"
    CIC_IDS = "cic_ids"
    SYNTHETIC = "synthetic"

class AlertSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class AgentDomain(str, Enum):
    NETWORK = "network"
    ENDPOINT = "endpoint"
    IDENTITY = "identity"
    CLOUD = "cloud"
    MALWARE = "malware"
    THREAT_INTEL = "threat_intel"

class AgentVerdict(str, Enum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    INSUFFICIENT_DATA = "insufficient_data"

class EvidenceType(str, Enum):
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    FILE_HASH = "file_hash"
    PROCESS_LINE = "process_line"
    AUTH_EVENT = "auth_event"
    CLOUD_API = "cloud_api"
    NETWORK_FLOW = "network_flow"
    REGISTRY_KEY = "registry_key"

class TrustDecision(str, Enum):
    AUTO_SUGGEST = "AUTO_SUGGEST"
    ESCALATE_TO_HUMAN = "ESCALATE_TO_HUMAN"

class ActionType(str, Enum):
    SIMULATE_HOST_ISOLATION = "simulate_host_isolation"
    SIMULATE_IP_BLOCK = "simulate_ip_block"
    SIMULATE_SESSION_REVOCATION = "simulate_session_revocation"
    SIMULATE_ACCOUNT_DISABLE = "simulate_account_disable"
    NOTIFY_SOC_TIER2 = "notify_soc_tier2"
    COLLECT_FORENSIC_TRIAGE = "collect_forensic_triage"

class ApprovalStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    MODIFIED = "MODIFIED"
    EXPIRED = "EXPIRED"

class ExecutionStatus(str, Enum):
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    SIMULATED_SUCCESS = "SIMULATED_SUCCESS"
    SIMULATED_FAILURE = "SIMULATED_FAILURE"

class ExecutorType(str, Enum):
    SIMULATION = "simulation"
    RESTRICTED_PRODUCTION = "restricted_production"
```

---

## 2. Core Alert & Ingestion Models (`src/domain/models/alert.py`)

```python
from datetime import datetime
from typing import Optional, Any
from uuid import UUID, uuid4
from pydantic import BaseModel, Field, IPvAnyAddress

class NormalizedNetworkContext(BaseModel):
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = Field(None, ge=0, le=65535)
    dst_port: Optional[int] = Field(None, ge=0, le=65535)
    protocol: Optional[str] = None
    bytes_in: Optional[int] = Field(None, ge=0)
    bytes_out: Optional[int] = Field(None, ge=0)
    dns_query: Optional[str] = None
    http_uri: Optional[str] = None
    flags: Optional[list[str]] = Field(default_factory=list)

class NormalizedEndpointContext(BaseModel):
    hostname: Optional[str] = None
    agent_id: Optional[str] = None
    os_type: Optional[str] = None
    process_name: Optional[str] = None
    process_id: Optional[int] = None
    parent_process_name: Optional[str] = None
    parent_process_id: Optional[int] = None
    command_line: Optional[str] = None
    sha256: Optional[str] = None
    md5: Optional[str] = None
    file_path: Optional[str] = None
    registry_key: Optional[str] = None

class NormalizedIdentityContext(BaseModel):
    username: Optional[str] = None
    user_id: Optional[str] = None
    user_domain: Optional[str] = None
    auth_status: Optional[str] = None
    mfa_used: Optional[bool] = None
    src_geo_country: Optional[str] = None
    src_geo_city: Optional[str] = None
    is_privileged: Optional[bool] = None

class NormalizedCloudContext(BaseModel):
    cloud_provider: Optional[str] = None
    account_id: Optional[str] = None
    region: Optional[str] = None
    resource_arn: Optional[str] = None
    event_source: Optional[str] = None
    event_name: Optional[str] = None

class NormalizedAlert(BaseModel):
    alert_id: UUID = Field(default_factory=uuid4)
    source_format: AlertSourceFormat
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    signature: str = Field(..., min_length=1, description="Rule title or signature")
    raw_severity: AlertSeverity
    category: str = Field(default="uncategorized")
    description: str = Field(default="")
    network: NormalizedNetworkContext = Field(default_factory=NormalizedNetworkContext)
    endpoint: NormalizedEndpointContext = Field(default_factory=NormalizedEndpointContext)
    identity: NormalizedIdentityContext = Field(default_factory=NormalizedIdentityContext)
    cloud: NormalizedCloudContext = Field(default_factory=NormalizedCloudContext)
    raw_payload: dict[str, Any] = Field(default_factory=dict)
```

---

## 3. Router & Agent Models (`src/domain/models/routing.py`, `src/domain/models/agent.py`)

```python
class RoutingDecision(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    alert_id: UUID
    model_version: str
    probabilities: dict[AgentDomain, float] = Field(
        ..., description="Calibrated posterior probabilities per domain"
    )
    selected_domains: list[AgentDomain] = Field(
        ..., min_length=1, description="Domains exceeding routing threshold"
    )
    threshold_applied: float = Field(0.50, ge=0.0, le=1.0)
    routing_latency_ms: float = Field(..., ge=0.0)
    created_at: datetime = Field(default_factory=datetime.utcnow)

class Evidence(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    evidence_type: EvidenceType
    key: str
    value: str
    source: str
    confidence_weight: float = Field(1.0, ge=0.0, le=1.0)
    context_data: dict[str, Any] = Field(default_factory=dict)

class AgentFinding(BaseModel):
    finding_id: UUID = Field(default_factory=uuid4)
    domain: AgentDomain
    verdict: AgentVerdict
    confidence: float = Field(..., ge=0.0, le=1.0, description="Calibrated agent confidence")
    evidence_items: list[Evidence] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list, description="Technique IDs, e.g. T1059.001")
    reasoning_summary: str = Field(..., min_length=10)
    uncertainty_factors: list[str] = Field(default_factory=list)
    recommended_queries: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)
```

---

## 4. Synthesis & Historical Memory Models (`src/domain/models/synthesis.py`)

```python
class MITRETechnique(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    mapped_by_agents: list[AgentDomain] = Field(default_factory=list)

class HistoricalCase(BaseModel):
    case_id: UUID
    incident_title: str
    similarity_score: float = Field(..., ge=0.0, le=1.0)
    historical_verdict: AgentVerdict
    historical_trust_score: float
    analyst_decision: ApprovalStatus
    executed_playbook: str
    outcome_summary: str

class ConflictDetail(BaseModel):
    conflicting_domains: list[AgentDomain]
    verdicts: dict[AgentDomain, AgentVerdict]
    confidences: dict[AgentDomain, float]
    disagreement_severity: float = Field(..., ge=0.0, le=1.0)

class ConsensusAssessment(BaseModel):
    overall_verdict: AgentVerdict
    consensus_score: float = Field(..., ge=0.0, le=1.0, description="C_consensus in Trust Formula")
    has_conflict: bool
    conflict_details: Optional[ConflictDetail] = None
    aggregated_mitre: list[MITRETechnique] = Field(default_factory=list)
```

---

## 5. Trust Score Engine Models (`src/domain/models/trust.py`)

```python
class TrustWeights(BaseModel):
    w_C: float = Field(0.50, ge=0.0, le=1.0, description="Weight for agent consensus")
    w_H: float = Field(0.30, ge=0.0, le=1.0, description="Weight for historical similarity")
    w_S: float = Field(0.20, ge=0.0, le=1.0, description="Weight for severity penalty")

class TrustComponentBreakdown(BaseModel):
    consensus_score: float = Field(..., ge=0.0, le=1.0, description="C_consensus")
    historical_similarity: float = Field(..., ge=0.0, le=1.0, description="H")
    severity_penalty: float = Field(..., ge=0.0, le=1.0, description="S_penalty")
    weighted_consensus: float
    weighted_historical: float
    weighted_penalty: float

class TrustAssessment(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    incident_id: UUID
    trust_score: float = Field(..., ge=0.0, le=1.0, description="Final clamped T in [0, 1]")
    threshold: float = Field(0.65, ge=0.0, le=1.0)
    decision: TrustDecision
    components: TrustComponentBreakdown
    weights: TrustWeights
    reason_codes: list[str] = Field(default_factory=list)
    calculation_version: str = Field(default="v1.0.0")
    calculated_at: datetime = Field(default_factory=datetime.utcnow)
```

---

## 6. Response, Approval & Audit Models (`src/domain/models/response.py`, `src/domain/models/audit.py`)

```python
class RecommendedAction(BaseModel):
    action_id: UUID = Field(default_factory=uuid4)
    action_type: ActionType
    target_entity: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    rationale: str
    risk_level: AlertSeverity
    is_reversible: bool = True

class Playbook(BaseModel):
    playbook_id: UUID = Field(default_factory=uuid4)
    incident_id: UUID
    title: str
    actions: list[RecommendedAction] = Field(..., min_length=1)
    suggested_by: str = "AdaptiveTrustEngine"
    created_at: datetime = Field(default_factory=datetime.utcnow)

class ApprovalRequest(BaseModel):
    request_id: UUID = Field(default_factory=uuid4)
    incident_id: UUID
    playbook_id: UUID
    trust_score: float
    status: ApprovalStatus = ApprovalStatus.PENDING
    requested_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: datetime

class ApprovalDecision(BaseModel):
    decision_id: UUID = Field(default_factory=uuid4)
    request_id: UUID
    analyst_id: str
    decision: ApprovalStatus
    analyst_notes: str
    modified_actions: Optional[list[RecommendedAction]] = None
    decided_at: datetime = Field(default_factory=datetime.utcnow)
    signature_token: str

class ExecutionResult(BaseModel):
    execution_id: UUID = Field(default_factory=uuid4)
    decision_id: UUID
    executor_type: ExecutorType = ExecutorType.SIMULATION
    status: ExecutionStatus
    action_logs: list[dict[str, Any]]
    executed_at: datetime = Field(default_factory=datetime.utcnow)

class AuditEvent(BaseModel):
    event_id: UUID = Field(default_factory=uuid4)
    incident_id: UUID
    event_type: str
    actor: str
    action: str
    state_before: dict[str, Any] = Field(default_factory=dict)
    state_after: dict[str, Any] = Field(default_factory=dict)
    previous_integrity_hash: str
    integrity_hash: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
```
