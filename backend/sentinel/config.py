"""Configuration management for Sentinel environments."""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    """Settings with proper field ordering."""

    sentinel_environment: str

    allowed_origins: list[str] = field(default_factory=list)
    trusted_hosts: list[str] = field(default_factory=list)

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
    allowed_repo_roots: tuple[Path, ...] = field(default_factory=tuple)

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
    enforce_request_signatures: bool = False
    enable_langgraph: bool = True
    token_budget: int = 1000000
    max_file_bytes: int = 1000000

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
        roots = self.allowed_repo_roots or default_allowed_repo_roots(
            self.sentinel_environment
        )
        object.__setattr__(
            self,
            "allowed_repo_roots",
            tuple(Path(root).expanduser().resolve() for root in roots),
        )
        if not self.allowed_origins:
            object.__setattr__(
                self,
                "allowed_origins",
                default_allowed_origins(self.sentinel_environment),
            )
        if not self.trusted_hosts:
            object.__setattr__(
                self,
                "trusted_hosts",
                default_trusted_hosts(self.sentinel_environment),
            )
        if self.sentinel_environment == "production":
            object.__setattr__(self, "enforce_request_signatures", True)

        if self.sentinel_environment == "production":
            if not self.azure_openai_key:
                raise ValueError("AZURE_OPENAI_KEY required in production")
            if not self.azure_openai_endpoint:
                raise ValueError("AZURE_OPENAI_ENDPOINT required in production")
            if self.allow_dev_tokens:
                raise ValueError("SENTINEL_ALLOW_DEV_TOKENS must be false in production")


def _csv_paths(value: str) -> tuple[Path, ...]:
    return tuple(
        Path(item.strip()).expanduser().resolve()
        for item in value.split(",")
        if item.strip()
    )


def _csv_strings(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def default_allowed_origins(environment: str) -> list[str]:
    configured = _csv_strings(os.getenv("SENTINEL_ALLOWED_ORIGINS", ""))
    if configured:
        return configured
    if environment == "production":
        return ["https://sentinel.yourdomain.com"]
    return [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ]


def default_trusted_hosts(environment: str) -> list[str]:
    configured = _csv_strings(os.getenv("SENTINEL_TRUSTED_HOSTS", ""))
    if configured:
        return configured
    if environment == "production":
        return ["sentinel.yourdomain.com"]
    return ["localhost", "127.0.0.1", "testserver"]


def default_allowed_repo_roots(environment: str) -> tuple[Path, ...]:
    """Return least-privilege repo roots for each runtime environment."""
    configured = _csv_paths(os.getenv("SENTINEL_ALLOWED_REPO_ROOTS", ""))
    if configured:
        return configured

    repo_root = Path(__file__).resolve().parents[2]
    roots = [
        repo_root / "examples",
        Path(os.getenv("SENTINEL_ALLOWED_REPO_ROOT", "/workspace")),
    ]
    if environment != "production":
        roots.extend(
            [
                Path(tempfile.gettempdir()),
                Path("/private/tmp"),
                repo_root,
            ]
        )
    return tuple(path.expanduser().resolve() for path in roots)


def load_settings() -> Settings:
    """Load settings from environment."""
    env = os.getenv("SENTINEL_ENVIRONMENT", os.getenv("SENTINEL_ENV", "development"))
    settings = Settings(
        sentinel_environment=env,
        enforce_request_signatures=os.getenv(
            "SENTINEL_ENFORCE_REQUEST_SIGNATURES",
            "false",
        ).lower() == "true",
    )

    import logging

    logger = logging.getLogger(__name__)
    logger.info("Settings loaded: env=%s, llm=%s", env, settings.llm_provider)

    return settings
