"""Gitleaks integration for secret detection across git history."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from git import Repo

from .models import (
    Finding,
    FindingCategory,
    FindingSeverity,
    sha256_text,
)


@dataclass
class GitleaksConfig:
    """Configuration for Gitleaks integration."""

    config_path: str | None = None
    max_findings: int = 100
    timeout_seconds: int = 300
    scan_full_history: bool = True


@dataclass
class SecretFinding:
    """Gitleaks secret finding."""

    rule_id: str
    description: str
    severity: str
    file: str
    line: int
    commit: str
    author: str
    email: str
    date: str
    secret: str


class GitleaksScanner:
    """Scanner for secrets in git history using Gitleaks."""

    def __init__(self, config: GitleaksConfig) -> None:
        self._config = config

    def scan_repository(
        self,
        repo_path: str,
        session_id: str,
    ) -> list[Finding]:
        """Scan repository for secrets across git history."""
        findings = []
        secret_findings = self._run_gitleaks(repo_path)

        for secret in secret_findings:
            finding = self._secret_to_finding(secret, session_id, repo_path)
            findings.append(finding)

        return findings[: self._config.max_findings]

    def _run_gitleaks(self, repo_path: str) -> list[SecretFinding]:
        """Run Gitleaks on the repository."""
        cmd = [
            "gitleaks",
            "detect",
            "--source",
            str(repo_path),
            "--report-format",
            "json",
            "--report-path",
            "/dev/stdout",
        ]

        if self._config.scan_full_history:
            cmd.append("--git-history-tracing")

        if self._config.config_path:
            cmd.extend(["--config", self._config.config_path])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self._config.timeout_seconds,
                check=False,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []

        try:
            output = json.loads(result.stdout)
        except json.JSONDecodeError:
            return []

        findings = []
        for item in output.get("findings", []):
            secret = SecretFinding(
                rule_id=item.get("rule_id", "unknown"),
                description=item.get("description", ""),
                severity=item.get("severity", "HIGH"),
                file=item.get("file", ""),
                line=item.get("line", 0),
                commit=item.get("commit", ""),
                author=item.get("author", ""),
                email=item.get("email", ""),
                date=item.get("date", ""),
                secret=item.get("secret", ""),
            )
            findings.append(secret)

        return findings

    def _secret_to_finding(
        self,
        secret: SecretFinding,
        session_id: str,
        repo_path: str,
    ) -> Finding:
        """Convert Gitleaks finding to Sentinel finding."""
        severity = self._map_severity(secret.severity)

        # Get relative file path
        try:
            relative_path = str(Path(secret.file).relative_to(repo_path))
        except ValueError:
            relative_path = secret.file

        remediation = (
            f"Remove the secret from the code and rotate the leaked credential. "
            f"Commit: {secret.commit}, Author: {secret.author}"
        )

        return Finding(
            finding_id=f"gitleaks_{sha256_text(f'{session_id}:{secret.commit}:{secret.file}:{secret.line}')[:16]}",
            rule_id=secret.rule_id,
            title=f"Secret detected: {secret.description}",
            category=FindingCategory.SECRET,
            severity=severity,
            file_path=relative_path,
            line=secret.line,
            snippet=secret.secret[:100],  # Truncate for display
            confidence=0.95,  # Gitleaks is high confidence for secrets
            cwe="CWE-798",
            remediation=remediation,
        )

    def _map_severity(self, gitleaks_severity: str) -> FindingSeverity:
        """Map Gitleaks severity to FindingSeverity."""
        mapping = {
            "CRITICAL": FindingSeverity.CRITICAL,
            "HIGH": FindingSeverity.HIGH,
            "MEDIUM": FindingSeverity.MEDIUM,
            "LOW": FindingSeverity.LOW,
        }
        return mapping.get(gitleaks_severity.upper(), FindingSeverity.HIGH)

    def scan_commit(
        self,
        repo_path: str,
        commit_sha: str,
        session_id: str,
    ) -> list[Finding]:
        """Scan a specific commit for secrets."""
        cmd = [
            "gitleaks",
            "detect",
            "--source",
            str(repo_path),
            "--log-level",
            "info",
            "--commit",
            commit_sha,
            "--report-format",
            "json",
            "--report-path",
            "/dev/stdout",
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self._config.timeout_seconds,
                check=False,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []

        try:
            output = json.loads(result.stdout)
        except json.JSONDecodeError:
            return []

        findings = []
        for item in output.get("findings", []):
            secret = SecretFinding(
                rule_id=item.get("rule_id", "unknown"),
                description=item.get("description", ""),
                severity=item.get("severity", "HIGH"),
                file=item.get("file", ""),
                line=item.get("line", 0),
                commit=item.get("commit", ""),
                author=item.get("author", ""),
                email=item.get("email", ""),
                date=item.get("date", ""),
                secret=item.get("secret", ""),
            )
            finding = self._secret_to_finding(secret, session_id, repo_path)
            findings.append(finding)

        return findings

    def get_secret_history(
        self,
        repo_path: str,
        file_path: str,
    ) -> list[dict[str, Any]]:
        """Get history of secrets in a specific file across commits."""
        repo = Repo(repo_path)
        commits = list(repo.iter_commits(paths=file_path))

        secret_history = []
        for commit in commits:
            findings = self.scan_commit(repo_path, str(commit), "temp_session")
            file_findings = [f for f in findings if f.file_path == file_path]
            if file_findings:
                secret_history.append(
                    {
                        "commit": str(commit),
                        "date": commit.authored_datetime.isoformat(),
                        "author": commit.author.name,
                        "findings": [f.model_dump() for f in file_findings],
                    }
                )

        return secret_history

    def generate_gitleaks_config(
        self,
        output_path: str,
        custom_rules: list[dict[str, Any]] | None = None,
    ) -> None:
        """Generate a Gitleaks configuration file."""
        config = {
            "title": "Sentinel Gitleaks Configuration",
            "rules": [
                {
                    "id": "aws-access-key-id",
                    "description": "AWS Access Key ID",
                    "regex": r"(?i)AKIA[0-9A-Z]{16}",
                    "severity": "CRITICAL",
                    "keywords": ["AKIA"],
                },
                {
                    "id": "aws-secret-key",
                    "description": "AWS Secret Key",
                    "regex": r"(?i)aws(.{0,20})?(?:'|\")[0-9a-zA-Z/+]{40}(?:'|\")",
                    "severity": "CRITICAL",
                    "keywords": ["aws"],
                },
                {
                    "id": "github-token",
                    "description": "GitHub Token",
                    "regex": r"(?i)ghp_[a-zA-Z0-9]{36}",
                    "severity": "CRITICAL",
                    "keywords": ["ghp_"],
                },
                {
                    "id": "private-key",
                    "description": "Private Key",
                    "regex": r"-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----",
                    "severity": "CRITICAL",
                    "keywords": ["BEGIN", "PRIVATE KEY"],
                },
                {
                    "id": "api-key",
                    "description": "Generic API Key",
                    "regex": r"(?i)(api[_-]?key|secret|token)\s*[:=]\s*['\"][A-Za-z0-9_\-]{20,}['\"]",
                    "severity": "HIGH",
                    "keywords": ["api", "key", "secret", "token"],
                },
            ],
            "allowlist": {
                "regexes": [
                    r"AKIA[0-9A-Z]{16}",  # Example keys in documentation
                ],
                "commits": [
                    "^[0-9a-f]{7}$",  # Ignore example commits
                ],
                "repos": [
                    "https://github.com/example/.*",  # Ignore example repos
                ],
            },
        }

        if custom_rules:
            config["rules"].extend(custom_rules)

        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(output_file, "w") as f:
            json.dump(config, f, indent=2)
