"""Checkov integration for IaC security scanning."""

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


class CheckovSeverity(StrEnum):
    """Checkov severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class IaCPlatform(StrEnum):
    """Infrastructure as Code platforms."""

    TERRAFORM = "terraform"
    KUBERNETES = "kubernetes"
    CLOUDFORMATION = "cloudformation"
    AWS_CDK = "aws-cdk"
    ARM = "arm"
    HELM = "helm"
    KUSTOMIZE = "kustomize"


@dataclass
class CheckovConfig:
    """Configuration for Checkov integration."""

    platforms: list[IaCPlatform] = None
    severity_threshold: CheckovSeverity = CheckovSeverity.HIGH
    timeout_seconds: int = 300
    compact: bool = True
    framework: str = "all"

    def __post_init__(self) -> None:
        if self.platforms is None:
            self.platforms = [
                IaCPlatform.TERRAFORM,
                IaCPlatform.KUBERNETES,
                IaCPlatform.CLOUDFORMATION,
            ]


@dataclass
class CheckovResult:
    """Checkov scan result."""

    check_id: str
    check_name: str
    severity: CheckovSeverity
    file_path: str
    file_line_range: list[int]
    resource: str
    description: str
    remediation: str


class CheckovScanner:
    """Scanner for Infrastructure as Code using Checkov."""

    def __init__(self, config: CheckovConfig) -> None:
        self._config = config

    def scan_repository(
        self,
        repo_path: str,
        session_id: str,
    ) -> list[Finding]:
        """Scan repository for IaC security issues."""
        findings = []
        results = self._run_checkov(repo_path)

        for result in results:
            severity = CheckovSeverity(result.get("severity", "MEDIUM"))

            if not self._severity_meets_threshold(severity):
                continue

            finding = self._result_to_finding(result, session_id, repo_path)
            findings.append(finding)

        return findings

    def _run_checkov(self, repo_path: str) -> list[dict[str, Any]]:
        """Run Checkov scan."""
        cmd = [
            "checkov",
            "-d",
            str(repo_path),
            "--framework",
            self._config.framework,
            "--output",
            "json",
            "--compact",
            str(self._config.compact).lower(),
            "--quiet",
        ]

        # Add platform filters
        if self._config.platforms:
            platforms_str = ",".join([p.value for p in self._config.platforms])
            cmd.extend(["--framework", platforms_str])

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

        results = output.get("results", {}).get("failed_checks", [])
        return results

    def _severity_meets_threshold(self, severity: CheckovSeverity) -> bool:
        """Check if severity meets the threshold."""
        severity_order = {
            CheckovSeverity.CRITICAL: 4,
            CheckovSeverity.HIGH: 3,
            CheckovSeverity.MEDIUM: 2,
            CheckovSeverity.LOW: 1,
        }
        return severity_order[severity] >= severity_order[self._config.severity_threshold]

    def _result_to_finding(
        self,
        result: dict[str, Any],
        session_id: str,
        repo_path: str,
    ) -> Finding:
        """Convert Checkov result to Finding."""
        severity = CheckovSeverity(result.get("severity", "MEDIUM"))
        check_id = result.get("check_id", "unknown")
        check_name = result.get("check_name", "Unknown check")
        file_path = result.get("file_path", "")
        file_line_range = result.get("file_line_range", [1, 1])
        resource = result.get("resource", "unknown")
        description = result.get("check", {}).get("description", "")
        remediation = result.get("check", {}).get("remediation", "")

        # Get relative file path
        try:
            relative_path = str(Path(file_path).relative_to(repo_path))
        except ValueError:
            relative_path = file_path

        return Finding(
            finding_id=f"checkov_{sha256_text(f'{session_id}:{check_id}:{relative_path}')[:16]}",
            rule_id=check_id,
            title=f"{check_name}: {description}",
            category=FindingCategory.CONFIGURATION,
            severity=self._map_severity(severity),
            file_path=relative_path,
            line=file_line_range[0] if file_line_range else 1,
            snippet=f"Resource: {resource}",
            confidence=0.9,
            cwe=None,
            remediation=remediation or "Review and fix the IaC configuration",
        )

    def _map_severity(self, checkov_severity: CheckovSeverity) -> FindingSeverity:
        """Map Checkov severity to FindingSeverity."""
        mapping = {
            CheckovSeverity.CRITICAL: FindingSeverity.CRITICAL,
            CheckovSeverity.HIGH: FindingSeverity.HIGH,
            CheckovSeverity.MEDIUM: FindingSeverity.MEDIUM,
            CheckovSeverity.LOW: FindingSeverity.LOW,
        }
        return mapping[checkov_severity]

    def scan_terraform(
        self,
        terraform_path: str,
        session_id: str,
    ) -> list[Finding]:
        """Scan Terraform files."""
        cmd = [
            "checkov",
            "-d",
            str(terraform_path),
            "--framework",
            "terraform",
            "--output",
            "json",
            "--compact",
            str(self._config.compact).lower(),
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

        results = output.get("results", {}).get("failed_checks", [])
        findings = []

        for item in results:
            severity = CheckovSeverity(item.get("severity", "MEDIUM"))
            if not self._severity_meets_threshold(severity):
                continue

            finding = self._result_to_finding(item, session_id, terraform_path)
            findings.append(finding)

        return findings

    def scan_kubernetes(
        self,
        k8s_path: str,
        session_id: str,
    ) -> list[Finding]:
        """Scan Kubernetes manifests."""
        cmd = [
            "checkov",
            "-d",
            str(k8s_path),
            "--framework",
            "kubernetes",
            "--output",
            "json",
            "--compact",
            str(self._config.compact).lower(),
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

        results = output.get("results", {}).get("failed_checks", [])
        findings = []

        for item in results:
            severity = CheckovSeverity(item.get("severity", "MEDIUM"))
            if not self._severity_meets_threshold(severity):
                continue

            finding = self._result_to_finding(item, session_id, k8s_path)
            findings.append(finding)

        return findings

    def scan_cloudformation(
        self,
        cf_path: str,
        session_id: str,
    ) -> list[Finding]:
        """Scan CloudFormation templates."""
        cmd = [
            "checkov",
            "-d",
            str(cf_path),
            "--framework",
            "cloudformation",
            "--output",
            "json",
            "--compact",
            str(self._config.compact).lower(),
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

        results = output.get("results", {}).get("failed_checks", [])
        findings = []

        for item in results:
            severity = CheckovSeverity(item.get("severity", "MEDIUM"))
            if not self._severity_meets_threshold(severity):
                continue

            finding = self._result_to_finding(item, session_id, cf_path)
            findings.append(finding)

        return findings

    def get_summary_report(
        self,
        repo_path: str,
    ) -> dict[str, Any]:
        """Get a summary report of Checkov scan."""
        cmd = [
            "checkov",
            "-d",
            str(repo_path),
            "--framework",
            self._config.framework,
            "--compact",
            str(self._config.compact).lower(),
            "--summary",
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
            return {}

        return {
            "summary": result.stdout,
            "summary_table": result.stderr,
        }
