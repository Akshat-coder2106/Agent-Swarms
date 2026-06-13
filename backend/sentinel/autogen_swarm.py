"""AutoGen multi-agent group chat for Project Sentinel.

The 4 Sentinel agents (Architect, Scout, Engineer, Critic) converse
via AutoGen's GroupChat, producing a human-readable audit transcript
that is streamed to the frontend as SSE events.

Requires: pip install pyautogen
"""

from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

try:
    from autogen import AssistantAgent, GroupChat, GroupChatManager, UserProxyAgent
    AUTOGEN_AVAILABLE = True
except ImportError:
    AUTOGEN_AVAILABLE = False
    logger.warning(
        "pyautogen not installed. AutoGen transcript disabled. "
        "Run: pip install pyautogen"
    )


def _azure_config() -> dict[str, Any] | None:
    """Build Azure OpenAI config for AutoGen LLM."""
    key = os.getenv("AZURE_OPENAI_KEY", "")
    endpoint = os.getenv("AZURE_OPENAI_ENDPOINT", "")
    deployment = os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4o")

    if not (key and endpoint):
        return None

    return {
        "config_list": [
            {
                "model": deployment,
                "api_type": "azure",
                "api_key": key,
                "base_url": endpoint,
                "api_version": "2024-02-01",
            }
        ],
        "temperature": 0.0,
        "timeout": 60,
    }


def run_autogen_audit_chat(
    session_id: str,
    repo_summary: str,
    findings_summary: str,
    patch_diff: str,
    sandbox_result: str,
) -> list[dict[str, str]]:
    """Run a 4-agent AutoGen GroupChat for one vulnerability finding.

    Returns a list of message dicts: [{"agent": str, "content": str}, ...]
    Falls back to a static transcript if AutoGen is unavailable.
    """
    if not AUTOGEN_AVAILABLE:
        return _static_fallback_transcript(
            repo_summary, findings_summary, patch_diff, sandbox_result
        )

    llm_config = _azure_config()
    if not llm_config:
        return _static_fallback_transcript(
            repo_summary, findings_summary, patch_diff, sandbox_result
        )

    # ── Define the 4 agents ──────────────────────────────────────────────────
    architect = AssistantAgent(
        name="Architect",
        system_message=(
            "You are the Architect agent in Project Sentinel. "
            "Your role: analyse repository structure and data flow. "
            "Be concise — 2-3 sentences max per turn."
        ),
        llm_config=llm_config,
    )

    scout = AssistantAgent(
        name="Scout",
        system_message=(
            "You are the Scout agent in Project Sentinel. "
            "Your role: identify the specific vulnerability pattern and its CWE. "
            "Be precise about the attack vector. 2-3 sentences max."
        ),
        llm_config=llm_config,
    )

    engineer = AssistantAgent(
        name="Engineer",
        system_message=(
            "You are the Engineer agent in Project Sentinel. "
            "Your role: propose and explain the security patch. "
            "Reference specific lines of code. 2-3 sentences max."
        ),
        llm_config=llm_config,
    )

    critic = AssistantAgent(
        name="Critic",
        system_message=(
            "You are the Critic agent in Project Sentinel. "
            "Your role: adversarially challenge the patch and report sandbox results. "
            "State APPROVE or REJECT clearly. 2-3 sentences max."
        ),
        llm_config=llm_config,
    )

    # Proxy that triggers the conversation
    trigger = UserProxyAgent(
        name="SentinelOrchestrator",
        human_input_mode="NEVER",
        max_consecutive_auto_reply=0,
        code_execution_config=False,
    )

    group_chat = GroupChat(
        agents=[trigger, architect, scout, engineer, critic],
        messages=[],
        max_round=6,
        speaker_selection_method="round_robin",
    )

    manager = GroupChatManager(
        groupchat=group_chat,
        llm_config=llm_config,
    )

    initial_message = (
        f"Security audit for session {session_id}.\n\n"
        f"Repository context: {repo_summary}\n\n"
        f"Finding: {findings_summary}\n\n"
        f"Proposed patch diff:\n{patch_diff}\n\n"
        f"Sandbox result: {sandbox_result}\n\n"
        "Each agent: give your 2-sentence expert assessment of this finding and fix."
    )

    try:
        trigger.initiate_chat(
            manager,
            message=initial_message,
            silent=True,
        )
        messages = [
            {"agent": msg["name"], "content": msg["content"]}
            for msg in group_chat.messages
            if msg.get("name") and msg["name"] != "SentinelOrchestrator"
        ]
        return messages if messages else _static_fallback_transcript(
            repo_summary, findings_summary, patch_diff, sandbox_result
        )
    except Exception as exc:
        logger.warning("AutoGen chat failed: %s", exc)
        return _static_fallback_transcript(
            repo_summary, findings_summary, patch_diff, sandbox_result
        )


def _static_fallback_transcript(
    repo_summary: str,
    findings_summary: str,
    patch_diff: str,
    sandbox_result: str,
) -> list[dict[str, str]]:
    """Evidence-only transcript when AutoGen or Azure OpenAI is unavailable."""
    verdict = str(sandbox_result)
    return [
        {
            "agent": "Architect",
            "content": (
                f"Repository analysis complete. {repo_summary} "
                "Data flow mapping identified the vulnerable ingestion path."
            ),
        },
        {
            "agent": "Scout",
            "content": (
                f"Vulnerability confirmed: {findings_summary} "
                "Deterministic evidence is available for human review."
            ),
        },
        {
            "agent": "Engineer",
            "content": (
                f"Patch generated. {patch_diff[:120]}... "
                "The proposed change must still be judged by recorded validation evidence."
            ),
        },
        {
            "agent": "Critic",
            "content": (
                f"Recorded sandbox result: {verdict}. "
                "AutoGen was unavailable, so no independent adversarial verdict was produced."
            ),
        },
    ]
