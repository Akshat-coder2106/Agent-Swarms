"""Configuration management for Sentinel environments."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    """Settings with proper field ordering."""
    
    sentinel_environment: str
    
    allowed_origins: list[str] = field(
        default_factory=lambda: [
            "http://localhost:5173",
            "http://localhost:8000",
        ]
    )
    trusted_hosts: list[str] = field(
        default_factory=lambda: ["localhost", "127.0.0.1"]
    )
    
    auth_issuer: str = "sentinel:local"
    auth_secret: str = field(
        default_factory=lambda: os.getenv(
            "SENTINEL_AUTH_SECRET",
            "dev-secret-change-in-prod"
        )
    )
    token_ttl_seconds: int = 3600
    allow_dev_tokens: bool = field(
        default_factory=lambda: os.getenv(
            "SENTINEL_ALLOW_DEV_TOKENS",
            "true"
        ).lower() == "true"
    )
    
    allowed_repo_roots: list[str] = field(
        default_factory=lambda: [
            str(Path(__file__).parent.parent.parent / "examples"),
            os.getenv("SENTINEL_ALLOWED_REPO_ROOT", "/workspace"),
        ]
    )
    
    llm_provider: str = field(
        default_factory=lambda: os.getenv("SENTINEL_LLM_PROVIDER", "azure")
    )
    llm_timeout_seconds: int = 60
    
    azure_openai_key: str = field(
        default_factory=lambda: os.getenv("AZURE_OPENAI_KEY", "")
    )
    azure_openai_endpoint: str = field(
        default_factory=lambda: os.getenv("AZURE_OPENAI_ENDPOINT", "")
    )
    azure_openai_deployment: str = field(
        default_factory=lambda: os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4o")
    )
    
    anthropic_api_key: str | None = field(
        default_factory=lambda: os.getenv("ANTHROPIC_API_KEY")
    )
    anthropic_model: str = "claude-3-opus-20240229"
    
    sandbox_engine: str = field(
        default_factory=lambda: os.getenv("SENTINEL_SANDBOX_ENGINE", "local")
    )
    sandbox_timeout_seconds: int = 300
    sandbox_vcpu_count: int = 2
    sandbox_memory_mb: int = 512
    sandbox_pool_size: int = 4
    sandbox_snapshot_dir: str = "/tmp/sentinel-snapshots"
    
    session_store_backend: str = field(
        default_factory=lambda: os.getenv("SENTINEL_SESSION_STORE", "sqlite")
    )
    session_db: str = field(
        default_factory=lambda: os.getenv(
            "SENTINEL_SESSION_DB",
            str(Path("/tmp") / "sentinel-sessions.db")
        )
    )
    redis_url: str = field(
        default_factory=lambda: os.getenv(
            "SENTINEL_REDIS_URL",
            "redis://localhost:6379"
        )
    )
    postgres_dsn: str = field(
        default_factory=lambda: os.getenv(
            "SENTINEL_POSTGRES_DSN",
            "postgresql://sentinel:sentinel@localhost/sentinel"
        )
    )
    
    policy_confidence_threshold: float = 0.92
    policy_require_human_approval: bool = True
    
    enable_opentelemetry: bool = field(
        default_factory=lambda: os.getenv(
            "SENTINEL_OPENTELEMETRY_ENABLED",
            "false"
        ).lower() == "true"
    )
    azure_insights_connection_string: str = field(
        default_factory=lambda: os.getenv(
            "APPLICATIONINSIGHTS_CONNECTION_STRING",
            ""
        )
    )
    
    def __post_init__(self) -> None:
        """Validate after initialization."""
        if self.sentinel_environment == "production":
            if not self.azure_openai_key:
                raise ValueError("AZURE_OPENAI_KEY required in production")
            if not self.azure_openai_endpoint:
                raise ValueError("AZURE_OPENAI_ENDPOINT required in production")


def load_settings() -> Settings:
    """Load settings from environment."""
    env = os.getenv("SENTINEL_ENVIRONMENT", "development")
    settings = Settings(sentinel_environment=env)
    
    import logging
    logger = logging.getLogger(__name__)
    logger.info(f"Settings loaded: env={env}, llm={settings.llm_provider}")
    
    return settings
