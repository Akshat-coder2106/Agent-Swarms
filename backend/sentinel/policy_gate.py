"""Responsible-AI patch policy gate (Microsoft hackathon: human-in-the-loop by default)."""

from __future__ import annotations

from dataclasses import dataclass

from .models import PatchProposal, ValidationResult, Verdict


@dataclass(frozen=True)
class PolicyDecision:
    approval_eligible: bool
    auto_approve_eligible: bool
    requires_human: bool
    reason: str
    confidence_threshold: float


DEFAULT_CONFIDENCE_THRESHOLD = 0.92


def evaluate_patch_policy(
    *,
    patch: PatchProposal,
    validation: ValidationResult | None,
    confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD,
) -> PolicyDecision:
    """Enterprise policy: only high-confidence, sandbox-approved patches may skip escalation."""
    if validation is None:
        return PolicyDecision(
            approval_eligible=False,
            auto_approve_eligible=False,
            requires_human=True,
            reason="No sandbox validation yet.",
            confidence_threshold=confidence_threshold,
        )
    if validation.verdict != Verdict.APPROVE:
        return PolicyDecision(
            approval_eligible=False,
            auto_approve_eligible=False,
            requires_human=True,
            reason=f"Sandbox verdict is {validation.verdict.value}.",
            confidence_threshold=confidence_threshold,
        )
    if patch.engineer_confidence < confidence_threshold:
        return PolicyDecision(
            approval_eligible=False,
            auto_approve_eligible=False,
            requires_human=True,
            reason=(
                f"Engineer confidence {patch.engineer_confidence:.2f} "
                f"below threshold {confidence_threshold:.2f}."
            ),
            confidence_threshold=confidence_threshold,
        )
    if patch.risk.value in {"CRITICAL", "HIGH"}:
        return PolicyDecision(
            approval_eligible=True,
            auto_approve_eligible=False,
            requires_human=True,
            reason=f"Risk level {patch.risk.value} requires human approval.",
            confidence_threshold=confidence_threshold,
        )
    return PolicyDecision(
        approval_eligible=True,
        auto_approve_eligible=True,
        requires_human=False,
        reason="Meets confidence, sandbox, and risk policy.",
        confidence_threshold=confidence_threshold,
    )
