"""Build an honest, runtime-aware capability manifest for judges and the UI."""

from __future__ import annotations

import os
import platform
import shutil
from typing import TYPE_CHECKING

from .config import Settings
from .models import CapabilityItem, CapabilityStatus, RuntimeStatus, SystemCapabilities

if TYPE_CHECKING:
    from .llm import LLMProvider


_EXTERNAL_SCANNERS: tuple[tuple[str, str], ...] = (
    ("semgrep", "Semgrep"),
    ("gitleaks", "Gitleaks"),
    ("trivy", "Trivy"),
    ("checkov", "Checkov"),
)


def _available_external_scanners() -> list[str]:
    return [label for binary, label in _EXTERNAL_SCANNERS if shutil.which(binary)]


def _session_persistence_label(settings: Settings) -> str:
    if os.getenv("SENTINEL_SESSION_DB", "").strip():
        return "sqlite (SENTINEL_SESSION_DB)"
    if settings.session_store_backend == "sqlite":
        return f"sqlite ({settings.session_db})"
    if settings.sentinel_environment == "production":
        return "sqlite (data/sentinel_sessions.db)"
    return "in-memory (development)"


def build_system_capabilities(
    *,
    settings: Settings,
    sandbox_engine: str,
    llm_provider: LLMProvider | None,
) -> SystemCapabilities:
    available_scanners = _available_external_scanners()
    llm_enabled = bool(llm_provider and llm_provider.is_available)
    llm_name = llm_provider.provider_name if llm_provider else "disabled"
    is_firecracker = sandbox_engine == "firecracker-microvm"
    isolation = "hardware" if is_firecracker else "process"
    azure_configured = bool(
        os.getenv("AZURE_OPENAI_KEY") and os.getenv("AZURE_OPENAI_ENDPOINT")
    )
    ado_configured = bool(os.getenv("AZURE_DEVOPS_PAT"))

    if available_scanners:
        scanner_detail = (
            f"11 built-in rules plus optional CLI scanners. "
            f"Detected: {', '.join(available_scanners)}."
        )
    else:
        scanner_detail = (
            "11 built-in deterministic rules. Install semgrep, gitleaks, trivy, or checkov to extend."
        )

    runtime = RuntimeStatus(
        platform=platform.system(),
        sandbox_engine=sandbox_engine,
        sandbox_isolation=isolation,
        llm_provider=llm_name,
        llm_enabled=llm_enabled,
        langgraph_enabled=settings.enable_langgraph,
        deterministic_rules=True,
        external_scanners_available=available_scanners,
        session_persistence=_session_persistence_label(settings),
    )

    summary_parts = [
        "Microsoft-ready DevSecOps: Azure OpenAI, Azure DevOps export, SARIF for GitHub Advanced Security.",
        f"Sandbox: {sandbox_engine} ({isolation}).",
    ]
    if llm_enabled:
        summary_parts.append(f"LLM: {llm_name}.")
    else:
        summary_parts.append("LLM offline; deterministic remediation active.")

    return SystemCapabilities(
        spec_version="Project Sentinel v4.0",
        production_complete=False,
        summary=" ".join(summary_parts),
        runtime=runtime,
        capabilities=[
            CapabilityItem(
                key="repository_ingestion",
                label="Repository ingestion and analysis",
                status=CapabilityStatus.IMPLEMENTED,
                detail="Indexes source, symbol graph, and built-in security rules.",
            ),
            CapabilityItem(
                key="azure_openai",
                label="Azure OpenAI (Microsoft)",
                status=CapabilityStatus.IMPLEMENTED,
                detail=(
                    "Set AZURE_OPENAI_ENDPOINT, AZURE_OPENAI_KEY, AZURE_OPENAI_DEPLOYMENT. "
                    f"Prefer via SENTINEL_LLM_PROVIDER=azure. Configured: {azure_configured}."
                ),
            ),
            CapabilityItem(
                key="sarif_export",
                label="SARIF 2.1 export (GitHub Advanced Security)",
                status=CapabilityStatus.IMPLEMENTED,
                detail="GET /api/sessions/{id}/export/sarif — OWASP-tagged results for code scanning upload.",
            ),
            CapabilityItem(
                key="azure_devops",
                label="Azure DevOps work items",
                status=CapabilityStatus.IMPLEMENTED if ado_configured else CapabilityStatus.MVP_ADAPTER,
                detail=(
                    "POST /api/sessions/{id}/export/azure creates work items from findings. "
                    f"PAT configured: {ado_configured}."
                ),
            ),
            CapabilityItem(
                key="responsible_ai_policy",
                label="Responsible AI patch policy gate",
                status=CapabilityStatus.IMPLEMENTED,
                detail=(
                    f"GET /api/sessions/{{id}}/policy — confidence ≥ {settings.policy_confidence_threshold}, "
                    "sandbox APPROVE, and risk limits before auto-approve eligibility."
                ),
            ),
            CapabilityItem(
                key="semantic_kernel",
                label="Semantic Kernel plugin (Microsoft)",
                status=CapabilityStatus.IMPLEMENTED,
                detail=(
                    "4 agent functions registered as SK @kernel_function: "
                    "architect_analyse, scout_retrieve, engineer_patch, critic_validate. "
                    "GET /api/system/sk_status for live kernel state."
                ),
            ),
            CapabilityItem(
                key="autogen_swarm",
                label="AutoGen multi-agent GroupChat (Microsoft)",
                status=CapabilityStatus.IMPLEMENTED,
                detail=(
                    "4-agent GroupChat (Architect, Scout, Engineer, Critic) produces "
                    "human-readable audit transcript per session. "
                    "GET /api/sessions/{id}/autogen_transcript"
                ),
            ),
            CapabilityItem(
                key="azure_foundry_embeddings",
                label="Azure AI Foundry embeddings",
                status=CapabilityStatus.IMPLEMENTED,
                detail=(
                    "text-embedding-3-small via azure-ai-inference SDK replaces "
                    "token-overlap search. Falls back gracefully without AZURE_AI_KEY."
                ),
            ),
            CapabilityItem(
                key="sandbox_validation",
                label="Sandboxed patch validation",
                status=CapabilityStatus.IMPLEMENTED,
                detail=f"Active: {sandbox_engine} ({isolation}).",
            ),
            CapabilityItem(
                key="github_action",
                label="GitHub Actions integration",
                status=CapabilityStatus.IMPLEMENTED,
                detail="action.yml runs Sentinel audit on push and pull_request.",
            ),
            CapabilityItem(
                key="external_scanners",
                label="Semgrep, Trivy, Checkov, Gitleaks",
                status=CapabilityStatus.MVP_ADAPTER,
                detail=scanner_detail,
            ),
            CapabilityItem(
                key="kubernetes_temporal",
                label="Kubernetes, Temporal, Kafka",
                status=CapabilityStatus.PLANNED,
                detail="Scaffolded; default API uses SQLite or in-memory sessions.",
            ),
        ],
    )
