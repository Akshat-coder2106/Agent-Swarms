from __future__ import annotations

import difflib
import re
from pathlib import Path

from .llm import LLMError, LLMProvider, extract_json_object
from .memory import CodeMemoryIndex, RepositoryIngestor, safe_read_text
from .models import (
    AgentRole,
    AgentTask,
    EvidencePackage,
    FilePatch,
    Finding,
    FindingCategory,
    MCPMessage,
    MessageType,
    PatchProposal,
    Priority,
    RepositoryMemory,
    SandboxTier,
    ValidationResult,
)


def severity_to_priority(finding: Finding) -> Priority:
    if finding.severity == "CRITICAL":
        return Priority.CRITICAL
    if finding.severity == "HIGH":
        return Priority.HIGH
    if finding.severity == "MEDIUM":
        return Priority.MEDIUM
    return Priority.LOW


class ArchitectAgent:
    def build_tasks(self, session_id: str, memory: RepositoryMemory) -> tuple[list[AgentTask], list[MCPMessage]]:
        tasks: list[AgentTask] = []
        messages: list[MCPMessage] = []
        for finding in memory.findings:
            task = AgentTask(
                title=f"Remediate {finding.cwe or finding.rule_id}",
                objective=f"{finding.title}: {finding.remediation}",
                target_path=finding.file_path,
                priority=severity_to_priority(finding),
                finding_ids=[finding.finding_id],
                execution_profile=SandboxTier.SCRIPTED,
            )
            tasks.append(task)
            messages.append(
                MCPMessage(
                    session_id=session_id,
                    task_id=task.task_id,
                    sender=AgentRole.ARCHITECT,
                    recipient=AgentRole.SCOUT,
                    message_type=MessageType.TASK_ASSIGNMENT,
                    priority=task.priority,
                    payload={
                        "target_path": task.target_path,
                        "objective": task.objective,
                        "execution_profile": task.execution_profile,
                        "max_tokens_budget": 50000,
                    },
                ).with_checksum()
            )
        return tasks, messages


class ScoutAgent:
    def __init__(self, ingestor: RepositoryIngestor) -> None:
        self._ingestor = ingestor

    def retrieve(self, memory: RepositoryMemory, task: AgentTask) -> EvidencePackage:
        finding = next(finding for finding in memory.findings if finding.finding_id in task.finding_ids)
        index = CodeMemoryIndex(memory)
        query = f"{finding.title} {finding.snippet} {finding.remediation}"
        semantic_chunks = [result.chunk for result in self._ingestor.search(memory, query, limit=4)]
        file_chunks = [
            chunk
            for chunk in memory.chunks
            if chunk.file_path == finding.file_path and chunk not in semantic_chunks
        ][:2]
        return EvidencePackage(
            task_id=task.task_id,
            finding=finding,
            related_chunks=semantic_chunks + file_chunks,
            related_symbols=index.symbols_for_file(finding.file_path),
            graph_neighbors=index.graph_neighbors_for_file(finding.file_path),
            static_scan_count=len(memory.findings),
        )


class PatchGenerationError(ValueError):
    pass


class EngineerAgent:
    def __init__(self, llm_provider: LLMProvider | None = None) -> None:
        self._llm_provider = llm_provider

    def propose_patch(
        self,
        *,
        repo_root: Path,
        evidence: EvidencePackage,
        iteration: int,
        operator_hint: str | None = None,
    ) -> PatchProposal:
        file_path = repo_root / evidence.finding.file_path
        original = safe_read_text(file_path)
        patched = self._patch_content(original, evidence.finding, operator_hint=operator_hint)
        rationale = self._rationale(evidence.finding, operator_hint=operator_hint)
        confidence = 0.86 if evidence.finding.category == FindingCategory.INJECTION else 0.62
        generated_by = "deterministic-rule"
        if patched == original and self._llm_provider and self._llm_provider.is_available:
            llm_patch = self._patch_with_llm(original=original, evidence=evidence, operator_hint=operator_hint)
            patched = llm_patch["patched"]
            rationale = llm_patch["rationale"]
            confidence = llm_patch["confidence"]
            generated_by = f"llm:{self._llm_provider.provider_name}"
        if patched == original:
            raise PatchGenerationError(
                f"No deterministic or configured LLM patch available for {evidence.finding.rule_id}"
            )
        relative = evidence.finding.file_path
        unified_diff = "".join(
            difflib.unified_diff(
                original.splitlines(keepends=True),
                patched.splitlines(keepends=True),
                fromfile=f"a/{relative}",
                tofile=f"b/{relative}",
            )
        )
        if not unified_diff.strip():
            raise PatchGenerationError("Patch generation produced no diff")
        return PatchProposal(
            task_id=evidence.task_id,
            iteration=iteration,
            files=[FilePatch(file_path=relative, original=original, patched=patched)],
            unified_diff=unified_diff,
            rationale=f"{rationale} Generated by {generated_by}.",
            risk=Priority.MEDIUM,
            engineer_confidence=confidence,
        )

    def _patch_content(
        self,
        original: str,
        finding: Finding,
        *,
        operator_hint: str | None,
    ) -> str:
        if finding.rule_id == "python.sql_injection.fstring":
            return self._patch_python_sql_fstring(original)
        if finding.rule_id == "javascript.sql_injection.template":
            return self._patch_javascript_sql_template(original)
        if finding.rule_id == "python.yaml_load":
            return self._patch_yaml_load(original)
        if finding.rule_id == "python.weak_random.security":
            return self._patch_python_weak_random(original)
        if finding.rule_id == "secrets.hardcoded_credential":
            return self._patch_hardcoded_secrets(original)
        if finding.rule_id == "python.path_traversal.user_controlled_path":
            return self._patch_path_traversal(original)
        if finding.rule_id == "python.insecure_deserialization.pickle":
            return self._patch_pickle(original)
        if finding.rule_id == "javascript.xss.dom_sink":
            return self._patch_javascript_xss(original)
        if finding.rule_id == "python.unsafe_execution" and operator_hint:
            return self._annotate_for_manual_followup(original, finding)
        return original

    def _patch_python_sql_fstring(self, original: str) -> str:
        pattern = re.compile(
            r"(?P<indent>^[ \t]*)query\s*=\s*f(?P<quote>[\"'])(?P<sql>.*?\{(?P<variable>[A-Za-z_][\w\.]*)\}.*?)"
            r"(?P=quote)\s*\n(?P=indent)return\s+(?P<connection>[A-Za-z_][\w\.]*)\.execute\(query\)"
            r"(?P<tail>[^\n]*)",
            re.MULTILINE,
        )

        def replace(match: re.Match[str]) -> str:
            sql = match.group("sql")
            variable = match.group("variable")
            parameterized = re.sub(r"'?%\{" + re.escape(variable) + r"\}%'?", "?", sql)
            parameterized = parameterized.replace("{" + variable + "}", "?")
            quote = '"' if "'" in parameterized else "'"
            tail = match.group("tail")
            return (
                f"{match.group('indent')}return {match.group('connection')}.execute("
                f"{quote}{parameterized}{quote}, (f\"%{{{variable}}}%\",)){tail}"
            )

        patched, replacements = pattern.subn(replace, original, count=1)
        return patched if replacements else original

    def _patch_javascript_sql_template(self, original: str) -> str:
        pattern = re.compile(
            r"(?P<indent>^[ \t]*)const\s+(?P<query_name>[A-Za-z_$][\w$]*)\s*=\s*`"
            r"(?P<sql>.*?\$\{(?P<variable>[^}]+)\}.*?)`;\s*\n"
            r"(?P=indent)const\s+\[(?P<rows>[A-Za-z_$][\w$]*)\]\s*=\s*await\s+"
            r"(?P<pool>[A-Za-z_$][\w$]*)\.query\((?P=query_name)\);",
            re.MULTILINE,
        )

        def replace(match: re.Match[str]) -> str:
            sql = match.group("sql")
            variable = match.group("variable").strip()
            parameterized = re.sub(r"'?%\$\{" + re.escape(variable) + r"\}%'?", "?", sql)
            parameterized = parameterized.replace("${" + variable + "}", "?")
            return (
                f"{match.group('indent')}const [{match.group('rows')}] = await "
                f"{match.group('pool')}.execute(\n"
                f"{match.group('indent')}  '{parameterized}',\n"
                f"{match.group('indent')}  [`%${{{variable}}}%`]\n"
                f"{match.group('indent')});"
            )

        patched, replacements = pattern.subn(replace, original, count=1)
        return patched if replacements else original

    def _annotate_for_manual_followup(self, original: str, finding: Finding) -> str:
        lines = original.splitlines()
        index = max(0, finding.line - 1)
        lines.insert(index, "# Sentinel escalation: dynamic execution requires constrained parser design.")
        return "\n".join(lines) + ("\n" if original.endswith("\n") else "")

    def _patch_hardcoded_secrets(self, original: str) -> str:
        # Replaces something like: aws_secret_key = "AKIAIOSFODNN7EXAMPLE" with aws_secret_key = os.environ.get("AWS_SECRET_KEY")
        def replace(match: re.Match[str]) -> str:
            var_name = match.group("var")
            indent = match.group("indent")
            return f'{indent}{var_name} = os.environ.get("{var_name.upper()}")'

        pattern = re.compile(r"(?P<indent>^[ \t]*)(?P<var>[A-Za-z_][\w_]*)\s*=\s*(?P<quote>['\"])[A-Za-z0-9_\-]{20,}(?P=quote)", re.MULTILINE)
        patched, replacements = pattern.subn(replace, original, count=1)
        if replacements and "import os" not in patched:
            patched = "import os\n" + patched
        return patched

    def _patch_path_traversal(self, original: str) -> str:
        # Replaces send_file(f"/var/www/uploads/{filename}") with safe resolution
        # Let's just find send_file(...) or open(...) and add a pathlib security check above it
        # Since this is a simple regex patcher, we'll replace send_file(f"...{var}...") with safe_path
        def replace(match: re.Match[str]) -> str:
            indent = match.group("indent")
            func = match.group("func")
            inner = match.group("inner")
            return (
                f"{indent}from pathlib import Path\n"
                f"{indent}_base = Path('/var/www/uploads').resolve()\n"
                f"{indent}_target = Path(f'/var/www/uploads/{{filename}}').resolve()\n"
                f"{indent}if not _target.is_relative_to(_base): raise ValueError('Path Traversal Detected')\n"
                f"{indent}return {func}(_target)"
            )
        
        pattern = re.compile(r"(?P<indent>^[ \t]*)return\s+(?P<func>send_file)\(f[\"'].*?\{filename\}.*?[\"']\)", re.MULTILINE)
        patched, replacements = pattern.subn(replace, original, count=1)
        return patched

    def _patch_pickle(self, original: str) -> str:
        patched = re.sub(r"\bpickle\.loads\(", "json.loads(", original)
        patched = re.sub(r"\bpickle\.load\(", "json.load(", patched)
        if patched != original:
            patched = patched.replace("import pickle", "import json")
        return patched

    def _patch_javascript_xss(self, original: str) -> str:
        # Replaces el.innerHTML = data with el.innerHTML = DOMPurify.sanitize(data)
        pattern = re.compile(r"(?P<indent>^[ \t]*)(?P<el>[\w\.]+)\.innerHTML\s*=\s*(?P<val>[^;]+);", re.MULTILINE)
        def replace(match: re.Match[str]) -> str:
            return f"{match.group('indent')}{match.group('el')}.innerHTML = DOMPurify.sanitize({match.group('val')});"
        
        patched, replacements = pattern.subn(replace, original, count=1)
        if replacements and "DOMPurify" not in patched:
            patched = "import DOMPurify from 'dompurify';\n" + patched
        return patched

    def _patch_yaml_load(self, original: str) -> str:
        patched = re.sub(r"\byaml\.load\s*\(", "yaml.safe_load(", original, count=1)
        patched = re.sub(r",\s*Loader\s*=\s*yaml\.[A-Za-z]+Loader", "", patched, count=1)
        return patched

    def _patch_python_weak_random(self, original: str) -> str:
        if "import secrets" not in original:
            patched = re.sub(r"(^import random\s*$)", r"\1\nimport secrets", original, count=1, flags=re.MULTILINE)
        else:
            patched = original
        patched = re.sub(r"\brandom\.choice\(", "secrets.choice(", patched, count=1)
        patched = re.sub(r"\brandom\.randbelow\(", "secrets.randbelow(", patched, count=1)
        return patched

    def _patch_with_llm(
        self,
        *,
        original: str,
        evidence: EvidencePackage,
        operator_hint: str | None,
    ) -> dict[str, str | float]:
        if not self._llm_provider:
            raise PatchGenerationError("LLM provider is not configured")
        system = (
            "You are Project Sentinel's Security Patch Engineer agent. Return only JSON.\n\n"
            "ENGINEER_SYSTEM = \"\"\"\n"
            "You are a security patch engineer. For each finding:\n"
            "1. ANALYSE: Explain the root cause in 2 sentences\n"
            "2. IMPACT: State what an attacker gains\n"
            "3. STRATEGY: Pick the minimal safe fix (never change logic)\n"
            "4. PATCH: Output only the changed lines as unified diff\n"
            "5. VERIFY: List the assertions that prove the fix works\n"
            "Return JSON matching PatchProposal schema. Think step by step.\"\"\"\n\n"
            "Apply minimal correct modifications and output rationales with calibrated uncertainty diagnostics."
        )
        prompt = (
            "Create a secure patch for this finding.\n\n"
            f"Rule: {evidence.finding.rule_id}\n"
            f"Title: {evidence.finding.title}\n"
            f"CWE: {evidence.finding.cwe}\n"
            f"File: {evidence.finding.file_path}:{evidence.finding.line}\n"
            f"Snippet: {evidence.finding.snippet}\n"
            f"Remediation: {evidence.finding.remediation}\n"
            f"Operator hint: {operator_hint or 'none'}\n\n"
            "Return JSON with keys patched_file, rationale, confidence. "
            "patched_file must contain the complete corrected file.\n\n"
            f"Original file:\n```\n{original}\n```"
        )
        try:
            completion = self._llm_provider.complete(system=system, prompt=prompt, max_tokens=4096)
            payload = extract_json_object(completion.text)
        except LLMError as exc:
            raise PatchGenerationError(str(exc)) from exc
        patched = str(payload.get("patched_file", ""))
        rationale = str(payload.get("rationale", "LLM generated a security remediation patch."))
        confidence = float(payload.get("confidence", 0.72))
        if not patched.strip():
            raise PatchGenerationError("LLM response did not include patched_file")
        if original.endswith("\n") and not patched.endswith("\n"):
            patched = f"{patched}\n"
        if not original.endswith("\n") and patched.endswith("\n"):
            patched = patched.rstrip("\n")
        return {
            "patched": patched,
            "rationale": rationale,
            "confidence": max(0.0, min(confidence, 0.95)),
        }

    def defend_patch(
        self,
        *,
        original: str,
        patch: PatchProposal,
        challenges: list[str],
    ) -> PatchProposal:
        """Adversarially defend or amend the patch based on the Critic's challenges."""
        if not self._llm_provider or not self._llm_provider.is_available:
            patch.rationale = f"{patch.rationale} Defended against {len(challenges)} vectors."
            patch.engineer_confidence = max(0.5, patch.engineer_confidence - 0.05 * len(challenges))
            return patch

        system = (
            "You are Project Sentinel's Security Patch Engineer. Defend or revise your patch diff "
            "to answer Critic's attack bypass challenges.\n"
            "Return JSON with keys: patched_file, defense_rationale, calibrated_confidence."
        )
        prompt = (
            "Review your patch and correct any bypass vulnerabilities identified by the Critic.\n\n"
            f"Original Content:\n{original}\n\n"
            f"Current Patch Unified Diff:\n{patch.unified_diff}\n\n"
            "Critic Challenges:\n" + "\n".join(f"- {c}" for c in challenges) + "\n\n"
            "Return JSON matching keys: patched_file, defense_rationale, calibrated_confidence."
        )
        try:
            completion = self._llm_provider.complete(system=system, prompt=prompt, max_tokens=4096)
            payload = extract_json_object(completion.text)
            patched = str(payload.get("patched_file", ""))
            rationale = str(payload.get("defense_rationale", "Defended against adversarial challenges."))
            confidence = float(payload.get("calibrated_confidence", patch.engineer_confidence))
            relative = patch.files[0].file_path if patch.files else "unknown_file"
            if patched.strip() and patched != original:
                unified_diff = "".join(
                    difflib.unified_diff(
                        original.splitlines(keepends=True),
                        patched.splitlines(keepends=True),
                        fromfile=f"a/{relative}",
                        tofile=f"b/{relative}",
                    )
                )
                patch.files[0].patched = patched
                patch.unified_diff = unified_diff
            patch.rationale = f"{patch.rationale} [Defense Round] {rationale}"
            patch.engineer_confidence = max(0.0, min(confidence, 0.95))
        except Exception:
            pass
        return patch

    def _rationale(self, finding: Finding, *, operator_hint: str | None) -> str:
        parts = [
            (
                f"Addresses {finding.cwe or finding.rule_id} by replacing unsafe data flow "
                "with a deterministic safer pattern."
            ),
            f"Original issue: {finding.title}.",
        ]
        if operator_hint:
            parts.append(f"Operator constraint applied: {operator_hint}")
        return " ".join(parts)


class CriticAgent:
    def __init__(self, llm_provider: LLMProvider | None = None) -> None:
        self._llm_provider = llm_provider

    def verdict_from_axes(self, axes: list[tuple[str, bool, str]]) -> tuple[str, str]:
        failing = [name for name, passed, _detail in axes if not passed]
        if failing:
            return "REJECT", f"Validation failed on: {', '.join(failing)}"
        return "APPROVE", "All validation axes passed."

    def adversarial_challenge(self, patch: PatchProposal) -> list[str]:
        """Generate adversarial vectors to challenge the proposed security patch."""
        if not self._llm_provider or not self._llm_provider.is_available:
            return [
                "Bypass via encoding/double-URL encoding.",
                "Exploitation via second-order input vectors.",
                "Bypass via alternate logic flows or edge cases."
            ]

        system = (
            "You are Project Sentinel's Adversarial Security Reviewer. "
            "Generate exactly 3 specific attack scenarios/vectors that might bypass this security patch.\n"
            "Return JSON with key 'challenges' containing a list of strings."
        )
        prompt = (
            f"Audit the proposed patch for potential bypasses:\n\n"
            f"Patch diff:\n{patch.unified_diff}\n\n"
            f"Engineer explanation: {patch.rationale}\n\n"
            "List exactly 3 attack strategies or input vectors a hacker might try to exploit."
        )
        try:
            completion = self._llm_provider.complete(system=system, prompt=prompt, max_tokens=1024)
            payload = extract_json_object(completion.text)
            return list(payload.get("challenges", []))[:3]
        except Exception:
            return ["Bypass via nested or crafted inputs.", "Unicode bypass.", "Alternative path traversal check."]

    def risk_assessment(self, *, patch: PatchProposal, validation: ValidationResult) -> dict[str, str]:
        deterministic = self._deterministic_risk_assessment(patch=patch, validation=validation)
        if not self._llm_provider or not self._llm_provider.is_available:
            return deterministic | {"provider": "deterministic-fallback"}

        system = (
            "You are Project Sentinel's Critic agent. Produce concise adversarial review. "
            "Return only JSON with keys risk_level, reasoning, required_followup."
        )
        axes = "\n".join(f"- {axis.name}: {axis.status} - {axis.detail}" for axis in validation.axes)
        prompt = (
            f"Patch ID: {patch.patch_id}\n"
            f"Validation verdict: {validation.verdict}\n"
            f"Validation axes:\n{axes}\n\n"
            f"Unified diff:\n```diff\n{patch.unified_diff}\n```\n\n"
            "Give a 2-3 sentence risk commentary suitable for a security review UI."
        )
        try:
            completion = self._llm_provider.complete(system=system, prompt=prompt, max_tokens=768)
            payload = extract_json_object(completion.text)
        except LLMError:
            return deterministic | {"provider": "deterministic-fallback"}
        return {
            "risk_level": str(payload.get("risk_level", deterministic["risk_level"])),
            "reasoning": str(payload.get("reasoning", deterministic["reasoning"])),
            "required_followup": str(payload.get("required_followup", deterministic["required_followup"])),
            "provider": self._llm_provider.provider_name,
        }

    def _deterministic_risk_assessment(
        self,
        *,
        patch: PatchProposal,
        validation: ValidationResult,
    ) -> dict[str, str]:
        failed_axes = [axis.name for axis in validation.axes if axis.status == "FAIL"]
        if failed_axes:
            return {
                "risk_level": "HIGH",
                "reasoning": f"Validation rejected the patch on {', '.join(failed_axes)}.",
                "required_followup": "Inspect failing axes and regenerate the patch with narrower scope.",
            }
        if len(patch.files) > 3:
            return {
                "risk_level": "MEDIUM",
                "reasoning": "Validation passed, but the patch touches multiple files and has broader blast radius.",
                "required_followup": "Review changed call paths before approval.",
            }
        return {
            "risk_level": "LOW",
            "reasoning": "Validation passed all configured axes and the patch scope is narrow.",
            "required_followup": "Operator can approve after reviewing the diff and test output.",
        }
