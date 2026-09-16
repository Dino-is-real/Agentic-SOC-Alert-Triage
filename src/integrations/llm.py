"""LLM Provider Abstraction with Deterministic Mock Engine."""
import json
from abc import ABC, abstractmethod
from typing import Any, Optional
import httpx
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


class OpenAICompatibleLLMProvider(BaseLLMProvider):
    """Generic adapter for OpenAI-compatible REST APIs (Groq, OpenAI, Together, vLLM)."""

    def __init__(
        self,
        api_key: str,
        api_url: str,
        model: str,
        timeout: float = 30.0,
    ):
        self.api_key = api_key
        self.api_url = api_url
        self.model = model
        self.timeout = timeout
        self.fallback = MockLLMProvider()

    def _clean_json_text(self, text: str) -> str:
        """Strips markdown code blocks if the model wrapped the JSON."""
        stripped = text.strip()
        if stripped.startswith("```"):
            lines = stripped.splitlines()
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].startswith("```"):
                lines = lines[:-1]
            stripped = "\n".join(lines).strip()
        return stripped

    def _sanitize_output(self, data: dict[str, Any]) -> dict[str, Any]:
        """Ensures all expected keys and valid types exist for domain models."""
        verdict = str(data.get("verdict", "suspicious")).lower()
        if verdict not in ["benign", "suspicious", "malicious", "insufficient_data"]:
            verdict = "suspicious"

        try:
            confidence = float(data.get("confidence", 0.80))
            confidence = max(0.0, min(1.0, confidence))
        except (ValueError, TypeError):
            confidence = 0.80

        mitre = data.get("mitre_techniques", [])
        if not isinstance(mitre, list):
            mitre = [str(mitre)] if mitre else []

        uncertainty = data.get("uncertainty_factors", [])
        if not isinstance(uncertainty, list):
            uncertainty = [str(uncertainty)] if uncertainty else []

        queries = data.get("recommended_queries", [])
        if not isinstance(queries, list):
            queries = [str(queries)] if queries else []

        return {
            "verdict": verdict,
            "confidence": round(confidence, 4),
            "reasoning_summary": str(data.get("reasoning_summary", "Security analysis generated by LLM.")),
            "mitre_techniques": mitre,
            "uncertainty_factors": uncertainty,
            "recommended_queries": queries,
        }

    async def generate_structured(
        self,
        system_prompt: str,
        user_prompt: str,
        response_schema: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        instructions = (
            f"{system_prompt}\n\n"
            "CRITICAL: You must return ONLY a single valid JSON object with the exact keys:\n"
            "- \"verdict\": \"benign\" | \"suspicious\" | \"malicious\"\n"
            "- \"confidence\": float between 0.0 and 1.0\n"
            "- \"reasoning_summary\": concise technical justification\n"
            "- \"mitre_techniques\": list of ATT&CK IDs (e.g. [\"T1059.001\"])\n"
            "- \"uncertainty_factors\": list of strings\n"
            "- \"recommended_queries\": list of strings"
        )
        payload = {
            "model": self.model,
            "response_format": {"type": "json_object"},
            "temperature": 0.1,
            "messages": [
                {"role": "system", "content": instructions},
                {"role": "user", "content": user_prompt},
            ],
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(self.api_url, headers=headers, json=payload)
                if resp.status_code != 200:
                    logger.warning(
                        f"LLM API request failed (HTTP {resp.status_code}): {resp.text}. Falling back to deterministic mock."
                    )
                    return await self.fallback.generate_structured(system_prompt, user_prompt, response_schema)

                data = resp.json()
                content = data["choices"][0]["message"]["content"]
                cleaned = self._clean_json_text(content)
                parsed = json.loads(cleaned)
                return self._sanitize_output(parsed)

        except Exception as e:
            logger.warning(
                f"LLM generation exception ({type(e).__name__}: {e}). Gracefully falling back to deterministic mock."
            )
            return await self.fallback.generate_structured(system_prompt, user_prompt, response_schema)


class GroqLLMProvider(OpenAICompatibleLLMProvider):
    """Groq Cloud LPU Provider for ultra-fast Llama-3 inference."""

    def __init__(
        self,
        api_key: str,
        model: Optional[str] = None,
        timeout: float = 20.0,
    ):
        selected_model = model or settings.GROQ_MODEL or "llama-3.3-70b-versatile"
        super().__init__(
            api_key=api_key,
            api_url="https://api.groq.com/openai/v1/chat/completions",
            model=selected_model,
            timeout=timeout,
        )


class OpenAILLMProvider(OpenAICompatibleLLMProvider):
    """Official OpenAI Provider (GPT-4o, GPT-4o-mini)."""

    def __init__(
        self,
        api_key: str,
        model: Optional[str] = None,
        timeout: float = 30.0,
    ):
        selected_model = model or settings.OPENAI_MODEL or "gpt-4o-mini"
        super().__init__(
            api_key=api_key,
            api_url="https://api.openai.com/v1/chat/completions",
            model=selected_model,
            timeout=timeout,
        )


class OllamaLLMProvider(BaseLLMProvider):
    """Local Ollama Provider for offline, private open-source models."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        timeout: float = 60.0,
    ):
        self.base_url = (base_url or settings.LOCAL_OLLAMA_URL).rstrip("/")
        self.model = model or settings.OLLAMA_MODEL or "llama3.1"
        self.timeout = timeout
        self.fallback = MockLLMProvider()

    async def generate_structured(
        self,
        system_prompt: str,
        user_prompt: str,
        response_schema: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        payload = {
            "model": self.model,
            "format": "json",
            "stream": False,
            "system": f"{system_prompt}\nReturn ONLY JSON with keys: verdict, confidence, reasoning_summary, mitre_techniques, uncertainty_factors, recommended_queries.",
            "prompt": user_prompt,
        }
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(f"{self.base_url}/api/generate", json=payload)
                if resp.status_code == 200:
                    raw_text = resp.json().get("response", "{}")
                    return json.loads(raw_text)
        except Exception as e:
            logger.warning(f"Ollama call failed ({e}). Falling back to deterministic mock.")

        return await self.fallback.generate_structured(system_prompt, user_prompt, response_schema)


def get_llm_provider() -> BaseLLMProvider:
    """Factory function returning the configured LLM provider."""
    provider = (settings.LLM_PROVIDER or "mock").lower().strip()

    # 1. Groq (explicit or auto-detected by key prefix)
    if provider == "groq" or (settings.GROQ_API_KEY and settings.GROQ_API_KEY.startswith("gsk_")):
        if settings.GROQ_API_KEY:
            logger.info(f"Using Groq LLM Provider with model: {settings.GROQ_MODEL}")
            return GroqLLMProvider(api_key=settings.GROQ_API_KEY)
        logger.warning("LLM_PROVIDER is set to 'groq' but GROQ_API_KEY is empty. Falling back to MockLLMProvider.")
        return MockLLMProvider()

    # 2. OpenAI
    elif provider == "openai":
        if settings.OPENAI_API_KEY:
            logger.info(f"Using OpenAI LLM Provider with model: {settings.OPENAI_MODEL}")
            return OpenAILLMProvider(api_key=settings.OPENAI_API_KEY)
        logger.warning("LLM_PROVIDER is set to 'openai' but OPENAI_API_KEY is empty. Falling back to MockLLMProvider.")
        return MockLLMProvider()

    # 3. Local Ollama
    elif provider == "ollama":
        logger.info(f"Using Local Ollama LLM Provider at {settings.LOCAL_OLLAMA_URL}")
        return OllamaLLMProvider(base_url=settings.LOCAL_OLLAMA_URL)

    # 4. Default: Deterministic Mock
    return MockLLMProvider()

