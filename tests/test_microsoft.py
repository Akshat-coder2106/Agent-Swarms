from __future__ import annotations

import tempfile
import unittest

from sentinel.config import load_settings
from sentinel.models import (
    AuditSession,
    Finding,
    FindingCategory,
    FindingSeverity,
    RepositoryMemory,
)
from sentinel.policy_gate import evaluate_patch_policy
from sentinel.sarif_export import session_to_sarif
from sentinel.session_store import SQLiteSessionStore


class MicrosoftIntegrationsTest(unittest.TestCase):
    def test_sarif_export_contains_results(self) -> None:
        finding = Finding(
            rule_id="python.sql_injection.fstring",
            title="SQL injection",
            category=FindingCategory.INJECTION,
            severity=FindingSeverity.HIGH,
            file_path="app/users.py",
            line=10,
            snippet="query = f'SELECT ...'",
            confidence=0.95,
            cwe="CWE-89",
            remediation="Use parameterized queries.",
        )
        with tempfile.TemporaryDirectory() as repo_dir:
            session = AuditSession(
                objective="test",
                repo_path=repo_dir,
                memory=RepositoryMemory(
                    root_path=repo_dir,
                    files_indexed=1,
                    chunks=[],
                    symbols=[],
                    edges=[],
                    findings=[finding],
                    validation_commands=[],
                ),
            )
            sarif = session_to_sarif(session)
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(len(sarif["runs"][0]["results"]), 1)
        self.assertEqual(sarif["runs"][0]["results"][0]["ruleId"], finding.rule_id)

    def test_sqlite_session_store_roundtrip(self) -> None:
        import asyncio

        with tempfile.TemporaryDirectory() as repo_dir:
            session = AuditSession(objective="persist", repo_path=repo_dir)

            async def _run() -> None:
                store = SQLiteSessionStore(":memory:")
                await store.create(session)
                loaded = await store.get(session.session_id)
                self.assertEqual(loaded.session_id, session.session_id)

            asyncio.run(_run())

    def test_policy_gate_requires_human_for_high_risk(self) -> None:
        from sentinel.models import (
            FilePatch,
            PatchProposal,
            Priority,
            ValidationAxis,
            ValidationAxisStatus,
            ValidationResult,
            Verdict,
        )

        patch = PatchProposal(
            task_id="t1",
            iteration=1,
            files=[
                FilePatch(file_path="a.py", original="x", patched="y"),
            ],
            unified_diff="",
            rationale="fix",
            risk=Priority.HIGH,
            engineer_confidence=0.99,
        )
        validation = ValidationResult(
            task_id="t1",
            patch_id=patch.patch_id,
            verdict=Verdict.APPROVE,
            axes=[ValidationAxis(name="tests", status=ValidationAxisStatus.PASS, detail="ok")],
            exit_code=0,
            stdout="",
            stderr="",
            passing_tests=1,
            total_tests=1,
            resolved_findings=1,
            total_findings=1,
            duration_ms=10,
        )
        decision = evaluate_patch_policy(
            patch=patch,
            validation=validation,
            confidence_threshold=load_settings().policy_confidence_threshold,
        )
        self.assertTrue(decision.requires_human)


if __name__ == "__main__":
    unittest.main()
