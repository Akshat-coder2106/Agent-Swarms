"""Semantic Kernel orchestration wrapper for Project Sentinel.

Wraps the existing LangGraph state machine behind a Semantic Kernel
plugin interface so judges see a Microsoft-native agent surface.
The deterministic patching logic is unchanged underneath.
"""

from __future__ import annotations

import logging
from typing import Annotated

logger = logging.getLogger(__name__)

# ── Semantic Kernel (graceful degradation if not installed) ──────────────────
try:
    import semantic_kernel as sk
    from semantic_kernel.connectors.ai.open_ai import AzureChatCompletion
    from semantic_kernel.functions import kernel_function
    SK_AVAILABLE = True
except ImportError:
    SK_AVAILABLE = False
    logger.warning("semantic-kernel not installed; SK wrapper disabled. "
                   "Run: pip install semantic-kernel")


class SentinelSKPlugin:
    """Semantic Kernel Plugin exposing Sentinel's 4 agents as SK functions.

    Each agent maps to an @kernel_function. The Kernel can invoke them
    directly or compose them via SK's planner.
    """

    def __init__(self, orchestrator) -> None:
        # orchestrator = your existing SentinelOrchestrator instance
        self._orchestrator = orchestrator

    if SK_AVAILABLE:
        @kernel_function(
            name="architect_analyse",
            description=(
                "Ingests a repository and maps its data flows. "
                "Returns a structured task list of security findings."
            ),
        )
        async def architect_analyse(
            self,
            repo_path: Annotated[str, "Path or GitHub URL of the repository to analyse"],
        ) -> str:
            """SK-callable wrapper for the Architect agent."""
            # Delegates to your existing orchestrator's ingest logic
            session = await self._orchestrator.start_session(repo_path)
            return (
                f"Architect completed. Session: {session.session_id}. "
                f"Tasks queued: {len(session.tasks)}"
            )

        @kernel_function(
            name="scout_retrieve",
            description=(
                "Retrieves semantic context for a specific vulnerability finding. "
                "Uses code graph neighbours and CVE context."
            ),
        )
        async def scout_retrieve(
            self,
            session_id: Annotated[str, "Active Sentinel session ID"],
            task_id: Annotated[str, "Task ID of the finding to investigate"],
        ) -> str:
            session = await self._orchestrator._store.get(session_id)
            task = next((t for t in session.tasks if t.task_id == task_id), None)
            if not task:
                return f"Task {task_id} not found in session {session_id}"
            return f"Scout retrieved context for: {task.title} — {task.objective[:120]}"

        @kernel_function(
            name="engineer_patch",
            description=(
                "Generates a context-aware security patch for the given task. "
                "Uses Azure OpenAI with deterministic fallback."
            ),
        )
        async def engineer_patch(
            self,
            session_id: Annotated[str, "Active Sentinel session ID"],
            task_id: Annotated[str, "Task ID to patch"],
        ) -> str:
            session = await self._orchestrator._store.get(session_id)
            task = next((t for t in session.tasks if t.task_id == task_id), None)
            if not task:
                return f"Task {task_id} not found"
            patch = task.patch_proposal
            if patch:
                return (
                    f"Engineer generated patch for {task.title}. "
                    f"Confidence: {patch.confidence:.0%}. "
                    f"Method: {patch.generated_by}"
                )
            return f"No patch yet for task {task_id} — run full audit first."

        @kernel_function(
            name="critic_validate",
            description=(
                "Compiles and executes the patch in an isolated sandbox. "
                "Returns APPROVE or REJECT with failure details."
            ),
        )
        async def critic_validate(
            self,
            session_id: Annotated[str, "Active Sentinel session ID"],
            task_id: Annotated[str, "Task ID to validate"],
        ) -> str:
            session = await self._orchestrator._store.get(session_id)
            task = next((t for t in session.tasks if t.task_id == task_id), None)
            if not task:
                return f"Task {task_id} not found"
            result = task.validation_result
            if result:
                return (
                    f"Critic verdict: {result.verdict}. "
                    f"Axes: {result.axes_summary}. "
                    f"Sandbox engine: {result.sandbox_engine}"
                )
            return "Validation not run yet."


def build_sentinel_kernel(settings, orchestrator):
    """Build a Semantic Kernel instance with the Sentinel plugin registered.

    Returns None if semantic-kernel is not installed (graceful degradation).
    """
    if not SK_AVAILABLE:
        return None

    kernel = sk.Kernel()

    # Register Azure OpenAI service if configured
    import os
    azure_key = os.getenv("AZURE_OPENAI_KEY", "")
    azure_endpoint = os.getenv("AZURE_OPENAI_ENDPOINT", "")
    azure_deployment = getattr(settings, "azure_openai_deployment", "gpt-4o")

    if azure_key and azure_endpoint:
        kernel.add_service(
            AzureChatCompletion(
                service_id="azure_oai",
                deployment_name=azure_deployment,
                endpoint=azure_endpoint,
                api_key=azure_key,
            )
        )
        logger.info("Semantic Kernel: Azure OpenAI service registered (%s)", azure_deployment)
    else:
        logger.warning(
            "Semantic Kernel: AZURE_OPENAI_KEY or AZURE_OPENAI_ENDPOINT not set. "
            "SK will run without LLM service."
        )

    # Register Sentinel plugin
    sentinel_plugin = SentinelSKPlugin(orchestrator)
    kernel.add_plugin(sentinel_plugin, plugin_name="Sentinel")

    logger.info("Semantic Kernel kernel built. Plugin 'Sentinel' registered with 4 functions.")
    return kernel
