"""Global Application Configuration and Settings."""
from typing import Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    APP_NAME: str = "adaptive-soc"
    APP_ENV: str = "development"
    DEBUG: bool = True
    API_PREFIX: str = "/api/v1"
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    SECRET_KEY: str = "dev_secret_key_change_in_production_f728c31e9a4d8b5"

    # Database
    DATABASE_URL: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/adaptive_soc"
    DATABASE_SYNC_URL: str = "postgresql://postgres:postgres@localhost:5432/adaptive_soc"

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"

    # Trust Engine Parameters
    TRUST_WEIGHT_CONSENSUS: float = Field(0.60, ge=0.0, le=1.0)
    TRUST_WEIGHT_HISTORICAL: float = Field(0.25, ge=0.0, le=1.0)
    TRUST_WEIGHT_PENALTY: float = Field(0.15, ge=0.0, le=1.0)
    TRUST_DEFAULT_THRESHOLD: float = Field(0.50, ge=0.0, le=1.0)
    ROUTER_CONFIDENCE_THRESHOLD: float = Field(0.50, ge=0.0, le=1.0)

    # LLM Provider
    LLM_PROVIDER: str = "mock"  # "mock", "groq", "openai", "anthropic", "ollama"
    GROQ_API_KEY: Optional[str] = None
    GROQ_MODEL: str = "openai/gpt-oss-120b"
    OPENAI_API_KEY: Optional[str] = None
    OPENAI_MODEL: str = "gpt-4o-mini"
    ANTHROPIC_API_KEY: Optional[str] = None
    LOCAL_OLLAMA_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "llama3.1"

    # External Threat Intel Integrations
    VIRUSTOTAL_API_KEY: Optional[str] = None
    ABUSEIPDB_API_KEY: Optional[str] = None
    SHODAN_API_KEY: Optional[str] = None
    ENABLE_MOCK_INTEGRATIONS: bool = True


settings = Settings()
