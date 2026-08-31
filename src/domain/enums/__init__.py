"""Domain Enums for the Adaptive SOC Framework."""
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


class IncidentStatus(str, Enum):
    INGESTED = "INGESTED"
    ROUTED = "ROUTED"
    INVESTIGATING = "INVESTIGATING"
    SYNTHESIZED = "SYNTHESIZED"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    ESCALATED = "ESCALATED"
    RESOLVED = "RESOLVED"
    REJECTED = "REJECTED"
