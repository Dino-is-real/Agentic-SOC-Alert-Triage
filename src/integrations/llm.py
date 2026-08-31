"""LLM Provider Abstraction with Deterministic Mock Engine."""
import json
from abc import ABC, abstractmethod
from typing import Any, Optional
from src.core.config import settings
from src.core.logging import logger


class BaseLLMProvider(ABC):
    """Abstract interface for LLM backends."""

    @abstractmethod
    async def generate_structured(
        self,
        system_prompt: str,
        user_prompt: str,
        response_schema: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Generates validated structured JSON matching the requested schema."""
        pass


class MockLLMProvider(BaseLLMProvider):
    """Deterministic Mock LLM Provider for CI/CD, offline benchmarks, and testing."""

    async def generate_structured(
        self,
        system_prompt: str,
        user_prompt: str,
        response_schema: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        user_lower = user_prompt.lower()
        sys_lower = system_prompt.lower()

        if "network" in sys_lower:
            is_mal = any(k in user_lower for k in ["syn flood", "ddos", "scan", "185.220", "beacon"])
            return {
                "verdict": "malicious" if is_mal else "benign",
                "confidence": 0.91 if is_mal else 0.82,
                "reasoning_summary": (
                    "Observed abnormal SYN connection cadence and known scanning activity on external ports."
                    if is_mal
                    else "Traffic patterns match normal operational baselines."
                ),
                "mitre_techniques": ["T1046", "T1071.001"] if is_mal else [],
                "uncertainty_factors": [] if is_mal else ["Limited flow payload inspection"],
                "recommended_queries": ["Check firewall drop logs for source IP"],
            }

        elif "endpoint" in sys_lower:
            is_mal = any(k in user_lower for k in ["powershell", "cmd.exe", "sudo", "encoded", "hash"])
            return {
                "verdict": "malicious" if is_mal else "benign",
                "confidence": 0.88 if is_mal else 0.80,
                "reasoning_summary": (
                    "Detected obfuscated command-line execution and anomalous parent-child process relationship."
                    if is_mal
                    else "Process execution conforms to signed corporate software standard."
                ),
                "mitre_techniques": ["T1059.001", "T1053.005"] if is_mal else [],
                "uncertainty_factors": [],
                "recommended_queries": ["Inspect parent process tree and registry keys"],
            }

        elif "identity" in sys_lower:
            is_mal = any(k in user_lower for k in ["brute", "failed", "mfa", "root", "privileged"])
            return {
                "verdict": "suspicious" if is_mal else "benign",
                "confidence": 0.84 if is_mal else 0.85,
                "reasoning_summary": (
                    "Multiple consecutive failed authentication attempts followed by privileged escalation anomaly."
                    if is_mal
                    else "Authentication successful with valid MFA assertion."
                ),
                "mitre_techniques": ["T1110.001", "T1078.004"] if is_mal else [],
                "uncertainty_factors": ["Geo-IP velocity logs not fully populated"],
                "recommended_queries": ["Check Azure AD / Okta sign-in logs for source city"],
            }

        elif "cloud" in sys_lower:
            is_mal = any(k in user_lower for k in ["assumerole", "s3", "bucket", "iam", "cloudtrail", "putbucket"])
            return {
                "verdict": "malicious" if is_mal else "benign",
                "confidence": 0.89 if is_mal else 0.90,
                "reasoning_summary": (
                    "Anomalous IAM policy modification granting full admin privileges from unverified external session."
                    if is_mal
                    else "Standard automated deployment pipeline IAM role invocation."
                ),
                "mitre_techniques": ["T1078.004"] if is_mal else [],
                "uncertainty_factors": [],
                "recommended_queries": ["Check CloudTrail event history for principal ARN"],
            }

        elif "malware" in sys_lower:
            is_mal = any(k in user_lower for k in ["sha256", "md5", "ransomware", "trojan", "payload", "44d886"])
            return {
                "verdict": "malicious" if is_mal else "benign",
                "confidence": 0.94 if is_mal else 0.85,
                "reasoning_summary": (
                    "File hash corresponds to known malicious payload signature with anti-analysis evasion tactics."
                    if is_mal
                    else "File hash is verified as clean in threat databases."
                ),
                "mitre_techniques": ["T1486"] if is_mal else [],
                "uncertainty_factors": [],
                "recommended_queries": ["Quarantine sample for static disassembly and sandbox detonation"],
            }

        elif "threat_intel" in sys_lower or "threat intelligence" in sys_lower or "threatintel" in sys_lower:
            is_mal = any(k in user_lower for k in ["185.220", "c2", "evil", "malicious", "sha256", "beacon"])
            return {
                "verdict": "malicious" if is_mal else "benign",
                "confidence": 0.93 if is_mal else 0.80,
                "reasoning_summary": (
                    "Correlated observable indicators against active threat feeds with positive multi-engine detections."
                    if is_mal
                    else "No active threat intelligence indicators found for target entities."
                ),
                "mitre_techniques": ["T1071.001"] if is_mal else [],
                "uncertainty_factors": [],
                "recommended_queries": ["Search internal proxy logs for historical connections to IOC"],
            }

        # Default fallback
        return {
            "verdict": "suspicious",
            "confidence": 0.70,
            "reasoning_summary": "General analysis indicates potential operational anomaly requiring analyst review.",
            "mitre_techniques": [],
            "uncertainty_factors": ["Generic telemetry payload"],
            "recommended_queries": [],
        }


def get_llm_provider() -> BaseLLMProvider:
    """Factory function returning the configured LLM provider."""
    return MockLLMProvider()
