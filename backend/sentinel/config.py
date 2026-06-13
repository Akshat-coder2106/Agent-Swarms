from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    environment: str
    allowed_origins: tuple[str, ...]
    trusted_hosts: tuple[str, ...]
    auth_secret: str
    auth_issuer: str
    token_ttl_seconds: int
    allow_dev_tokens: bool
    allowed_repo_roots: tuple[Path, ...]
    max_file_bytes: int
    sandbox_timeout_seconds: int
    token_budget: int
    # Azure OpenAI is the primary provider for this project
    # Anthropic kept as optional fallback — not required for judges
    anthropic_api_key: str = ""
    anthropic_model: str = "claude-sonnet-4-20250514"
    azure_openai_deployment: str
    llm_provider: str
    llm_timeout_seconds: int
    policy_confidence_threshold: float
    enable_langgraph: bool
    # Sandbox settings
    sandbox_engine: str = "auto"  # "auto" | "firecracker" | "local"
    sandbox_vcpu_count: int = 1
    sandbox_memory_mb: int = 256
    sandbox_snapshot_dir: str = "/tmp/sentinel_snapshots"
    sandbox_pool_size: int = 1
    sandbox_enable_network: bool = False


def _csv(value: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in value.split(",") if item.strip())


def load_settings() -> Settings:
    cwd = Path.cwd().resolve()
    default_roots = (
        cwd,
        cwd.parent,
        Path(tempfile.gettempdir()).resolve(),
        Path("/private/tmp").resolve(),
        Path("/tmp").resolve(),  # noqa: S108
    )
    allowed_roots = tuple(
        Path(root).expanduser().resolve()
        for root in _csv(os.getenv("SENTINEL_ALLOWED_REPO_ROOTS", ""))
    ) or default_roots
    environment = os.getenv("SENTINEL_ENV", "development")
    default_origins = {
        "development": "http://localhost:5173,http://127.0.0.1:5173,http://localhost:8000,http://127.0.0.1:8000",
        "staging": "https://sentinel-staging.yourdomain.com",
        "production": "https://sentinel.yourdomain.com",
    }
    return Settings(
        environment=environment,
        allowed_origins=_csv(os.getenv("SENTINEL_ALLOWED_ORIGINS", default_origins[environment])),
        trusted_hosts=_csv(
            os.getenv("SENTINEL_TRUSTED_HOSTS", "localhost,127.0.0.1,*.yourdomain.com")
        ),
        auth_secret=os.getenv("SENTINEL_AUTH_SECRET", "development-only-change-me"),
        auth_issuer=os.getenv("SENTINEL_AUTH_ISSUER", "project-sentinel"),
        token_ttl_seconds=int(os.getenv("SENTINEL_TOKEN_TTL_SECONDS", "3600")),
        allow_dev_tokens=os.getenv("SENTINEL_ALLOW_DEV_TOKENS", "true").lower() == "true",
        allowed_repo_roots=allowed_roots,
        max_file_bytes=int(os.getenv("SENTINEL_MAX_FILE_BYTES", "262144")),
        sandbox_timeout_seconds=int(os.getenv("SENTINEL_SANDBOX_TIMEOUT_SECONDS", "30")),
        token_budget=int(os.getenv("SENTINEL_TOKEN_BUDGET", "2000000")),
        # Azure OpenAI is primary — Anthropic is optional fallback
        anthropic_api_key=os.getenv("ANTHROPIC_API_KEY", ""),
        anthropic_model=os.getenv("SENTINEL_ANTHROPIC_MODEL", "claude-sonnet-4-20250514"),
        azure_openai_deployment=os.getenv(
            "AZURE_OPENAI_DEPLOYMENT", os.getenv("SENTINEL_AZURE_DEPLOYMENT", "gpt-4o")
        ),
        # Ensure Azure is always tried first
        llm_provider=os.getenv("SENTINEL_LLM_PROVIDER", "azure"),
        llm_timeout_seconds=int(os.getenv("SENTINEL_LLM_TIMEOUT_SECONDS", "90")),
        policy_confidence_threshold=float(os.getenv("SENTINEL_POLICY_CONFIDENCE_THRESHOLD", "0.92")),
        enable_langgraph=os.getenv("SENTINEL_ENABLE_LANGGRAPH", "true").lower() == "true",
        sandbox_engine=os.getenv("SENTINEL_SANDBOX_ENGINE", "auto"),
        sandbox_vcpu_count=int(os.getenv("SENTINEL_SANDBOX_VCPU_COUNT", "1")),
        sandbox_memory_mb=int(os.getenv("SENTINEL_SANDBOX_MEMORY_MB", "256")),
        sandbox_snapshot_dir=os.getenv("SENTINEL_SANDBOX_SNAPSHOT_DIR", "/tmp/sentinel_snapshots"),
        sandbox_pool_size=int(os.getenv("SENTINEL_SANDBOX_POOL_SIZE", "1")),
        sandbox_enable_network=os.getenv("SENTINEL_SANDBOX_ENABLE_NETWORK", "false").lower() == "true",
    )
