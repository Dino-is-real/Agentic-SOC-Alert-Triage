# System Architecture & Technical Design

**System Name:** Adaptive Trust-Aware SOC Multi-Agent Platform  
**Document Version:** 1.0.0  
**Architecture Pattern:** Clean / Hexagonal Architecture (Ports and Adapters)  

---

## 1. Architectural Principles

1. **Clean Separation of Concerns:** Domain logic (`src/domain`, `src/trust`, `src/synthesis`) is isolated from external frameworks, databases, and UI layers.
2. **Explicit Contracts over Implicit Inference:** All inter-agent and inter-module communications use strictly validated Pydantic schemas. Unstructured string passing between agents is prohibited.
3. **Deterministic Safety Boundaries:** Safety-critical decisions (Trust Score computation, Human Approval verification, Playbook execution gates) are implemented as deterministic, non-LLM Python algorithms.
4. **Portability & Testability:** All external integrations (LLMs, Vector DB, Threat Intel APIs, SIEMs) use the Adapter pattern with accompanying deterministic mock providers.

---

## 2. High-Level System Architecture

```mermaid
graph TB
    subgraph Client Layer
        WebUI[React 18 + TypeScript Dashboard]
        CLI[Evaluation & Admin CLI]
    end

    subgraph API & Presentation Layer
        FastAPI[FastAPI Application Gateway]
        AuthMiddleware[JWT & RBAC Security Middleware]
        ReqTracer[Correlation & Audit Tracer]
    end

    subgraph Ingestion Layer
        RawIngest[Raw Alert Endpoint / Message Bus]
        WazuhParser[Wazuh Parser]
        SplunkParser[Splunk Parser]
        CICIDSParser[CIC-IDS Parser]
        SyntheticParser[Synthetic Parser]
        Normalizer[Alert Normalizer Engine]
    end

    subgraph ML Routing Subsystem
        FeatureEng[Feature Extraction & Scaling]
        MLClassifier[OneVsRest GradientBoosting Classifier]
        Calibrator[Probability Calibrator]
        RouterPolicy[Adaptive Routing Policy]
    end

    subgraph Agent Orchestration Layer LangGraph
        GraphEngine[LangGraph State Machine Engine]
        NetAgent[Network Specialist Agent]
        EndAgent[Endpoint Specialist Agent]
        IdAgent[Identity Specialist Agent]
        CldAgent[Cloud Specialist Agent]
        MalAgent[Malware Specialist Agent]
        IntelAgent[Threat Intel Specialist Agent]
    end

    subgraph Tool & Integration Adapters
        VTAdapter[VirusTotal Adapter / Mock]
        AbuseAdapter[AbuseIPDB Adapter / Mock]
        ShodanAdapter[Shodan Adapter / Mock]
        MitreSTIX[MITRE STIX 2.1 Provider]
        LLMProvider[Multi-Provider LLM Gateway / Mock]
    end

    subgraph Synthesis & Memory Subsystem
        ConsensusEngine[Evidence Consensus & Conflict Engine]
        MitreMapper[MITRE ATT&CK Mapper]
        Embedder[Incident Embedder]
        PgVectorRepo[PostgreSQL + pgvector Memory]
    end

    subgraph Trust Engine Gate 03
        TrustCalc[Deterministic Trust Calculator]
        CalibEngine[ECE & Reliability Calibration Engine]
        DecisionGate[Gate 03: Auto-Suggest vs Escalate]
    end

    subgraph Response & Approval Subsystem
        PlaybookGen[Response Playbook Generator]
        ApprovalEngine[Mandatory Human Approval Gate]
        SimExecutor[Safe Simulation Response Executor]
    end

    subgraph Data & Storage Persistence
        PostgreSQL[(PostgreSQL 16 Relational DB)]
        VectorStore[(pgvector Semantic Embeddings)]
        AuditLedger[(Immutable Append-Only Audit Log)]
        RedisCache[(Redis Cache & Task Queue)]
    end

    %% Connections
    WebUI --> FastAPI
    CLI --> FastAPI
    FastAPI --> AuthMiddleware --> ReqTracer
    ReqTracer --> RawIngest
    RawIngest --> WazuhParser & SplunkParser & CICIDSParser & SyntheticParser --> Normalizer
    Normalizer --> FeatureEng --> MLClassifier --> Calibrator --> RouterPolicy
    
    RouterPolicy --> GraphEngine
    GraphEngine --> NetAgent & EndAgent & IdAgent & CldAgent & MalAgent & IntelAgent
    
    NetAgent & EndAgent & IdAgent & CldAgent & MalAgent & IntelAgent --> VTAdapter & AbuseAdapter & ShodanAdapter & MitreSTIX & LLMProvider
    
    NetAgent & EndAgent & IdAgent & CldAgent & MalAgent & IntelAgent --> ConsensusEngine
    ConsensusEngine --> MitreMapper
    ConsensusEngine --> Embedder --> PgVectorRepo
    
    ConsensusEngine & MitreMapper & PgVectorRepo --> TrustCalc --> CalibEngine --> DecisionGate
    DecisionGate --> PlaybookGen --> ApprovalEngine
    
    WebUI -.->|Analyst Sign-off| ApprovalEngine
    ApprovalEngine -->|Approved Only| SimExecutor
    
    FastAPI --> PostgreSQL & VectorStore & AuditLedger & RedisCache
```

---

## 3. LangGraph Orchestration State Machine

The multi-agent workflow is modeled as a deterministic Directed Acyclic Graph (DAG) state machine using LangGraph.

### 3.1 State Schema (`InvestigationState`)

```python
class InvestigationState(TypedDict):
    incident_id: str
    normalized_alert: dict
    routing_decision: dict
    active_agents: list[str]
    agent_findings: dict[str, dict]
    consensus_assessment: Optional[dict]
    mitre_mappings: list[dict]
    historical_cases: list[dict]
    trust_assessment: Optional[dict]
    recommended_playbook: Optional[dict]
    approval_request: Optional[dict]
    execution_result: Optional[dict]
    audit_trail: list[dict]
    errors: list[str]
```

### 3.2 Graph Transitions & Control Flow

```mermaid
stateDiagram-v2
    [*] --> IngestAndNormalize
    IngestAndNormalize --> MLRouter
    MLRouter --> DispatchSpecialists
    
    state DispatchSpecialists {
        [*] --> Fork
        Fork --> NetworkAgent: P_net >= 0.50
        Fork --> EndpointAgent: P_end >= 0.50
        Fork --> IdentityAgent: P_id >= 0.50
        Fork --> CloudAgent: P_cld >= 0.50
        Fork --> MalwareAgent: P_mal >= 0.50
        Fork --> ThreatIntelAgent: P_ti >= 0.50
        
        NetworkAgent --> Join
        EndpointAgent --> Join
        IdentityAgent --> Join
        CloudAgent --> Join
        MalwareAgent --> Join
        ThreatIntelAgent --> Join
        Join --> [*]
    }
    
    DispatchSpecialists --> EvidenceSynthesis
    EvidenceSynthesis --> MitreAndMemoryLookup
    MitreAndMemoryLookup --> TrustScoreGate03
    
    state TrustScoreGate03 {
        [*] --> ComputeScore
        ComputeScore --> AutoSuggestBranch: Trust >= 0.65
        ComputeScore --> EscalateBranch: Trust < 0.65
        AutoSuggestBranch --> [*]
        EscalateBranch --> [*]
    }
    
    TrustScoreGate03 --> GeneratePlaybook
    GeneratePlaybook --> HumanApprovalGate
    
    state HumanApprovalGate {
        [*] --> AwaitHuman
        AwaitHuman --> Approved: Analyst Approves
        AwaitHuman --> Rejected: Analyst Rejects
        AwaitHuman --> Modified: Analyst Modifies
        Approved --> [*]
        Rejected --> [*]
        Modified --> [*]
    }
    
    HumanApprovalGate --> ExecuteRemediation: Status == APPROVED
    HumanApprovalGate --> RecordAnalystFeedback: Status != APPROVED
    ExecuteRemediation --> PersistAuditAndMemory
    RecordAnalystFeedback --> PersistAuditAndMemory
    PersistAuditAndMemory --> [*]
```

---

## 4. Database Schema & Relational Entity Model

```mermaid
erDiagram
    ALERTS ||--o{ INCIDENTS : "triggers"
    INCIDENTS ||--|| ROUTING_DECISIONS : "evaluated by"
    INCIDENTS ||--o{ AGENT_RUNS : "executes"
    AGENT_RUNS ||--o{ AGENT_FINDINGS : "produces"
    AGENT_FINDINGS ||--o{ EVIDENCE : "references"
    INCIDENTS ||--o{ MITRE_MAPPINGS : "associates"
    INCIDENTS ||--o{ HISTORICAL_MATCHES : "matches"
    INCIDENTS ||--|| TRUST_ASSESSMENTS : "evaluated by"
    INCIDENTS ||--|| PLAYBOOKS : "generates"
    PLAYBOOKS ||--|| APPROVAL_REQUESTS : "requires"
    APPROVAL_REQUESTS ||--o| APPROVAL_DECISIONS : "adjudicated by"
    APPROVAL_DECISIONS ||--o| EXECUTION_RESULTS : "triggers"
    INCIDENTS ||--o{ AUDIT_EVENTS : "logs"

    ALERTS {
        uuid id PK
        string source_format
        timestamp received_at
        jsonb raw_payload
        jsonb normalized_payload
        string severity
        string status
    }

    INCIDENTS {
        uuid id PK
        uuid alert_id FK
        string status
        string current_stage
        float final_trust_score
        string triage_verdict
        timestamp created_at
        timestamp resolved_at
    }

    ROUTING_DECISIONS {
        uuid id PK
        uuid incident_id FK
        string model_version
        jsonb domain_probabilities
        string[] selected_domains
        float routing_latency_ms
        timestamp created_at
    }

    AGENT_RUNS {
        uuid id PK
        uuid incident_id FK
        string agent_name
        string status
        float execution_latency_ms
        integer prompt_tokens
        integer completion_tokens
        timestamp started_at
        timestamp completed_at
    }

    AGENT_FINDINGS {
        uuid id PK
        uuid agent_run_id FK
        string domain
        string verdict
        float confidence
        string reasoning_summary
        jsonb uncertainty_factors
        timestamp created_at
    }

    EVIDENCE {
        uuid id PK
        uuid finding_id FK
        string evidence_type
        string key
        string value
        string source_sensor
        float confidence_weight
    }

    MITRE_MAPPINGS {
        uuid id PK
        uuid incident_id FK
        string technique_id
        string technique_name
        string tactic
        float confidence
    }

    TRUST_ASSESSMENTS {
        uuid id PK
        uuid incident_id FK
        float trust_score
        float threshold
        string decision
        float consensus_score
        float historical_similarity
        float severity_penalty
        jsonb weights
        string[] reason_codes
        string calculation_version
        timestamp calculated_at
    }

    PLAYBOOKS {
        uuid id PK
        uuid incident_id FK
        string title
        jsonb actions
        string risk_tier
        timestamp created_at
    }

    APPROVAL_REQUESTS {
        uuid id PK
        uuid playbook_id FK
        uuid incident_id FK
        string status
        timestamp requested_at
        timestamp expires_at
    }

    APPROVAL_DECISIONS {
        uuid id PK
        uuid request_id FK
        string analyst_id
        string decision
        string analyst_notes
        jsonb modified_actions
        timestamp decided_at
    }

    EXECUTION_RESULTS {
        uuid id PK
        uuid decision_id FK
        string executor_type
        string status
        jsonb action_logs
        timestamp executed_at
    }

    AUDIT_EVENTS {
        uuid id PK
        uuid incident_id FK
        string event_type
        string actor
        string action
        jsonb state_before
        jsonb state_after
        string integrity_hash
        timestamp timestamp
    }
```

---

## 5. Security & Safety Architectural Guarantees

1. **Non-Bypassable Backend Approval Gate:**
   The `ExecutionEngine` service accepts only an `ApprovalToken` signed with HMAC-SHA256 containing `decision_id`, `analyst_id`, and `playbook_hash`. Directly calling the execution endpoint without a valid, unexpired approval token results in HTTP 403 Forbidden.
2. **Deterministic Response Sandbox:**
   By default, the platform activates `SimulationExecutor`. Simulated actions mutate an isolated mock environment state and record detailed execution diffs without issuing destructive live system commands.
3. **Structured Agent Parsing:**
   All agent responses are validated against Pydantic models. Any LLM output failing schema validation triggers a retry or falls back to `INSUFFICIENT_DATA` with explicit human escalation.
4. **Append-Only Tamper-Aware Audit Ledger:**
   Every `AuditEvent` stores a cryptographic hash chaining to the preceding event hash ($H_n = \text{SHA256}(H_{n-1} \parallel \text{EventPayload}_n)$), enabling automated tamper detection.
