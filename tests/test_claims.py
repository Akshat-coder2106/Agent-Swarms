from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from sentinel.agents import CriticAgent, EngineerAgent, PatchGenerationError
from sentinel.memory import detect_findings
from sentinel.models import (
    CodeChunk,
    EvidencePackage,
    Finding,
    FindingCategory,
    FindingSeverity,
    PatchProposal,
    Priority,
    sha256_text,
)
from sentinel.sandbox import _calculate_coverage_delta


class LowConfidenceFakeLLM:
    @property
    def is_available(self) -> bool:
        return True

    @property
    def provider_name(self) -> str:
        return "low-confidence"

    def complete(self, *, system: str, prompt: str, max_tokens: int = 2048):
        class Completion:
            text = (
                '{"patched_file":"x = 1\\n","rationale":"weak fix","confidence":0.60}'
            )
            model = "fake"
            provider = "low-confidence"

        return Completion()


class SyntaxErrorFakeLLM:
    @property
    def is_available(self) -> bool:
        return True

    @property
    def provider_name(self) -> str:
        return "syntax-bad"

    def complete(self, *, system: str, prompt: str, max_tokens: int = 2048):
        class Completion:
            text = '{"patched_file":"def broken(\\n","rationale":"bad","confidence":0.95}'
            model = "fake"
            provider = "syntax-bad"

        return Completion()


class ClaimsTest(unittest.TestCase):
    def test_confidence_threshold_rejects_low_confidence_patch(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = Path(temp_dir)
            target = repo / "loader.py"
            original = "import pickle\n\ndef load_user(data):\n    return pickle.loads(data)\n"
            target.write_text(original, encoding="utf-8")
            finding = Finding(
                rule_id="python.insecure_deserialization.unsupported",
                title="Pickle deserialization",
                category=FindingCategory.DESERIALIZATION,
                severity=FindingSeverity.CRITICAL,
                file_path="loader.py",
                line=4,
                snippet="pickle.loads(data)",
                confidence=0.9,
                cwe="CWE-502",
                remediation="Use JSON instead of pickle.",
            )
            evidence = EvidencePackage(
                task_id="task_1",
                finding=finding,
                related_chunks=[
                    CodeChunk(
                        chunk_id="c1",
                        file_path="loader.py",
                        start_line=1,
                        end_line=4,
                        text=original,
                        token_fingerprint=sha256_text("c1"),
                    )
                ],
                related_symbols=[],
                graph_neighbors=[],
                static_scan_count=1,
            )
            with self.assertRaises(PatchGenerationError) as ctx:
                EngineerAgent(LowConfidenceFakeLLM()).propose_patch(
                    repo_root=repo,
                    evidence=evidence,
                    iteration=1,
                )
            self.assertIn("0.85", str(ctx.exception))

    def test_ast_hallucination_guard_rejects_invalid_python(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = Path(temp_dir)
            target = repo / "broken.py"
            original = "def run():\n    return 1\n"
            target.write_text(original, encoding="utf-8")
            finding = Finding(
                rule_id="python.custom.unsupported",
                title="Custom issue",
                category=FindingCategory.MISC,
                severity=FindingSeverity.HIGH,
                file_path="broken.py",
                line=1,
                snippet="def run",
                confidence=0.9,
                cwe="CWE-20",
                remediation="Fix the function.",
            )
            evidence = EvidencePackage(
                task_id="task_2",
                finding=finding,
                related_chunks=[],
                related_symbols=[],
                graph_neighbors=[],
                static_scan_count=1,
            )
            with self.assertRaises(PatchGenerationError) as ctx:
                EngineerAgent(SyntaxErrorFakeLLM()).propose_patch(
                    repo_root=repo,
                    evidence=evidence,
                    iteration=1,
                )
            self.assertIn("Hallucination Protection", str(ctx.exception))

    def test_adversarial_debate_improves_patch_rationale(self) -> None:
        patch = PatchProposal(
            task_id="t1",
            iteration=1,
            files=[],
            unified_diff="--- a\n+++ b\n",
            rationale="Initial fix for SQLi.",
            risk=Priority.MEDIUM,
            engineer_confidence=0.9,
        )
        challenges = CriticAgent(None).adversarial_challenge(patch)
        defended = EngineerAgent(None).defend_patch(
            original="query = f'SELECT {x}'",
            patch=patch,
            challenges=challenges,
        )
        self.assertIn("Defense Round", defended.rationale)

    def test_git_conflict_detector_finds_markers(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            path = root / "conflicted.py"
            source = "<<<<<<< HEAD\nfoo = 1\n=======\nfoo = 2\n>>>>>>> main\n"
            findings = detect_findings(root, path, source)
            self.assertTrue(any(f.rule_id == "git.merge_conflict" for f in findings))

    def test_coverage_delta_from_test_output(self) -> None:
        stdout = "Ran 5 tests in 0.01s\nOK\n"
        delta = _calculate_coverage_delta(stdout, "", passing_tests=5, total_tests=5)
        self.assertGreater(delta, 0.0)
        self.assertLessEqual(delta, 100.0)


if __name__ == "__main__":
    unittest.main()
