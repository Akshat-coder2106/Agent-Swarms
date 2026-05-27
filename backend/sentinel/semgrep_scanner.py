"""Semgrep integration for OWASP/CWE static analysis."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from .models import (
    Finding,
    FindingCategory,
    FindingSeverity,
    sha256_text,
)


class SemgrepRuleSet(StrEnum):
    """Semgrep rule sets."""

    OWASP_TOP_10 = "owasp-top-10"
    CWE_TOP_25 = "cwe-top-25"
    SECURITY = "security"
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    GO = "go"
    RUST = "rust"
    JAVA = "java"


@dataclass
class SemgrepConfig:
    """Configuration for Semgrep integration."""

    rulesets: list[SemgrepRuleSet] = None
    custom_rules_path: str | None = None
    max_findings: int = 1000
    timeout_seconds: int = 300

    def __post_init__(self) -> None:
        if self.rulesets is None:
            self.rulesets = [
                SemgrepRuleSet.OWASP_TOP_10,
                SemgrepRuleSet.CWE_TOP_25,
                SemgrepRuleSet.SECURITY,
            ]


@dataclass
class SemgrepMatch:
    """Semgrep match result."""

    rule_id: str
    severity: str
    message: str
    path: str
    start_line: int
    end_line: int
    snippet: str
    cwe: list[str] | None = None
    metadata: dict[str, Any] | None = None


class SemgrepScanner:
    """Semgrep static analysis scanner."""

    def __init__(self, config: SemgrepConfig) -> None:
        self._config = config

    def scan_repository(
        self,
        repo_path: str,
        session_id: str,
    ) -> list[Finding]:
        """Scan a repository with Semgrep."""
        matches = self._run_semgrep(repo_path)
        findings = self._convert_to_findings(matches, session_id, repo_path)
        return findings[: self._config.max_findings]

    def _run_semgrep(self, repo_path: str) -> list[SemgrepMatch]:
        """Run Semgrep on the repository."""
        cmd = [
            "semgrep",
            "scan",
            "--json",
            "--config",
            "auto",
            "--no-git-ignore",
            str(repo_path),
        ]

        # Add custom rules if specified
        if self._config.custom_rules_path:
            cmd.extend(["--config", self._config.custom_rules_path])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self._config.timeout_seconds,
                check=True,
            )
        except subprocess.TimeoutExpired:
            return []
        except subprocess.CalledProcessError as e:
            # Semgrep returns non-zero if findings are found
            if e.stdout:
                result = e
            else:
                return []

        # Parse JSON output
        try:
            output = json.loads(result.stdout)
        except json.JSONDecodeError:
            return []

        matches = []
        for result_item in output.get("results", []):
            match = SemgrepMatch(
                rule_id=result_item.get("check_id", "unknown"),
                severity=result_item.get("extra", {}).get("severity", "WARNING"),
                message=result_item.get("extra", {}).get("message", ""),
                path=result_item.get("path", ""),
                start_line=result_item.get("start", {}).get("line", 0),
                end_line=result_item.get("end", {}).get("line", 0),
                snippet=self._extract_snippet(result_item),
                cwe=result_item.get("extra", {}).get("metadata", {}).get("cwe"),
                metadata=result_item.get("extra", {}).get("metadata", {}),
            )
            matches.append(match)

        return matches

    def _extract_snippet(self, result_item: dict[str, Any]) -> str:
        """Extract code snippet from Semgrep result."""
        lines = result_item.get("extra", {}).get("lines", "")
        if lines:
            return lines.strip()

        # Fallback to the code snippet
        snippet = result_item.get("extra", {}).get("snippet", "")
        return snippet.strip()

    def _convert_to_findings(
        self,
        matches: list[SemgrepMatch],
        session_id: str,
        repo_path: str,
    ) -> list[Finding]:
        """Convert Semgrep matches to Sentinel findings."""
        findings = []
        repo_root = Path(repo_path)

        for match in matches:
            # Map Semgrep severity to FindingSeverity
            severity = self._map_severity(match.severity)

            # Determine category based on rule_id
            category = self._determine_category(match.rule_id)

            # Extract CWE if available
            cwe = None
            if match.cwe and isinstance(match.cwe, list) and match.cwe:
                cwe = match.cwe[0] if isinstance(match.cwe[0], str) else str(match.cwe[0])

            # Get relative file path
            try:
                relative_path = str(Path(match.path).relative_to(repo_root))
            except ValueError:
                relative_path = match.path

            finding = Finding(
                finding_id=f"semgrep_{sha256_text(f'{session_id}:{match.rule_id}:{match.path}:{match.start_line}')[:16]}",
                rule_id=match.rule_id,
                title=match.message,
                category=category,
                severity=severity,
                file_path=relative_path,
                line=match.start_line,
                snippet=match.snippet,
                confidence=0.85,  # Semgrep is generally high confidence
                cwe=cwe,
                remediation=self._generate_remediation(match),
            )
            findings.append(finding)

        return findings

    def _map_severity(self, semgrep_severity: str) -> FindingSeverity:
        """Map Semgrep severity to FindingSeverity."""
        mapping = {
            "ERROR": FindingSeverity.CRITICAL,
            "WARNING": FindingSeverity.HIGH,
            "INFO": FindingSeverity.MEDIUM,
        }
        return mapping.get(semgrep_severity.upper(), FindingSeverity.MEDIUM)

    def _determine_category(self, rule_id: str) -> FindingCategory:
        """Determine finding category from rule ID."""
        rule_lower = rule_id.lower()

        if any(
            keyword in rule_lower
            for keyword in ["injection", "sql", "xss", "command", "path"]
        ):
            return FindingCategory.INJECTION
        elif any(keyword in rule_lower for keyword in ["secret", "credential", "key", "token"]):
            return FindingCategory.SECRET
        elif any(
            keyword in rule_lower
            for keyword in ["exec", "eval", "shell", "system", "subprocess"]
        ):
            return FindingCategory.UNSAFE_EXECUTION
        elif "dependency" in rule_lower or "vulnerability" in rule_lower:
            return FindingCategory.DEPENDENCY
        else:
            return FindingCategory.CONFIGURATION

    def _generate_remediation(self, match: SemgrepMatch) -> str:
        """Generate remediation advice for a finding."""
        remediation = match.metadata.get("remediation", "") if match.metadata else ""
        if remediation:
            return remediation

        # Default remediation based on category
        category = self._determine_category(match.rule_id)

        if category == FindingCategory.INJECTION:
            return "Use parameterized queries or prepared statements to prevent injection attacks."
        elif category == FindingCategory.SECRET:
            return "Remove hardcoded credentials and use a secret management system."
        elif category == FindingCategory.UNSAFE_EXECUTION:
            return "Avoid dynamic code execution. Use explicit parsing or constrained evaluation."
        elif category == FindingCategory.DEPENDENCY:
            return "Update the dependency to a patched version or replace with a secure alternative."
        else:
            return "Review the code and apply security best practices."

    def scan_file(
        self,
        file_path: str,
        session_id: str,
    ) -> list[Finding]:
        """Scan a single file with Semgrep."""
        matches = self._run_semgrep(file_path)
        findings = self._convert_to_findings(matches, session_id, str(Path(file_path).parent))
        return findings

    def validate_patch(
        self,
        repo_path: str,
        patched_files: list[str],
    ) -> list[Finding]:
        """Re-scan patched files to ensure no new vulnerabilities were introduced."""
        matches = self._run_semgrep(repo_path)
        findings = self._convert_to_findings(matches, "validation", repo_path)

        # Filter to only patched files
        patched_findings = [
            f for f in findings if any(pf in f.file_path for pf in patched_files)
        ]

        return patched_findings
