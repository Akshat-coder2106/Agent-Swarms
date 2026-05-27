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
    anthropic_api_key: str
    anthropic_model: str
    llm_timeout_seconds: int
    enable_langgraph: bool


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
        anthropic_api_key=os.getenv("ANTHROPIC_API_KEY", ""),
        anthropic_model=os.getenv("SENTINEL_ANTHROPIC_MODEL", "claude-sonnet-4-20250514"),
        llm_timeout_seconds=int(os.getenv("SENTINEL_LLM_TIMEOUT_SECONDS", "45")),
        enable_langgraph=os.getenv("SENTINEL_ENABLE_LANGGRAPH", "true").lower() == "true",
    )
