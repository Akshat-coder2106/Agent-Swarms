"""Trivy integration for container image scanning."""

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


class TrivySeverity(StrEnum):
    """Trivy severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class TrivyScanTarget(StrEnum):
    """Trivy scan target types."""

    FILESYSTEM = "filesystem"
    IMAGE = "image"
    REPOSITORY = "repository"


@dataclass
class TrivyConfig:
    """Configuration for Trivy integration."""

    severity_threshold: TrivySeverity = TrivySeverity.HIGH
    timeout_seconds: int = 300
    scan_vulnerabilities: bool = True
    scan_misconfigurations: bool = True
    scan_secrets: bool = True
    db_repository: str = "ghcr.io/aquasecurity/trivy-db"


@dataclass
class VulnerabilityResult:
    """Trivy vulnerability result."""

    vulnerability_id: str
    package_name: str
    installed_version: str
    fixed_version: str | None
    severity: TrivySeverity
    cvss_score: float | None
    cwe_ids: list[str]
    title: str
    description: str


@dataclass
class MisconfigurationResult:
    """Trivy misconfiguration result."""

    rule_id: str
    rule_description: str
    severity: TrivySeverity
    file_path: str
    message: str
    remediation: str


class TrivyScanner:
    """Scanner for container images using Trivy."""

    def __init__(self, config: TrivyConfig) -> None:
        self._config = config

    def scan_image(
        self,
        image_name: str,
        session_id: str,
    ) -> list[Finding]:
        """Scan a container image for vulnerabilities."""
        results = self._run_trivy(image_name, target_type=TrivyScanTarget.IMAGE)
        findings = []

        if self._config.scan_vulnerabilities:
            vuln_findings = self._process_vulnerabilities(results, session_id, image_name)
            findings.extend(vuln_findings)

        if self._config.scan_misconfigurations:
            misconfig_findings = self._process_misconfigurations(results, session_id, image_name)
            findings.extend(misconfig_findings)

        return findings

    def scan_filesystem(
        self,
        repo_path: str,
        session_id: str,
    ) -> list[Finding]:
        """Scan a filesystem (e.g., Dockerfile directory) for vulnerabilities."""
        results = self._run_trivy(repo_path, target_type=TrivyScanTarget.FILESYSTEM)
        findings = []

        if self._config.scan_vulnerabilities:
            vuln_findings = self._process_vulnerabilities(results, session_id, repo_path)
            findings.extend(vuln_findings)

        if self._config.scan_misconfigurations:
            misconfig_findings = self._process_misconfigurations(results, session_id, repo_path)
            findings.extend(misconfig_findings)

        return findings

    def _run_trivy(
        self,
        target: str,
        target_type: TrivyScanTarget,
    ) -> dict[str, Any]:
        """Run Trivy scan."""
        cmd = [
            "trivy",
            target_type.value,
            "--format",
            "json",
            "--output",
            "/dev/stdout",
        ]

        # Add severity filter
        severities = []
        for severity in TrivySeverity:
            if self._severity_meets_threshold(severity):
                severities.append(severity.value)
        cmd.extend(["--severity", ",".join(severities)])

        # Add scan options
        if self._config.scan_vulnerabilities:
            cmd.append("--vuln-type")
            cmd.append("os,library")

        if self._config.scan_misconfigurations:
            cmd.append("--scanners")
            cmd.append("vuln,misconfig")

        if self._config.scan_secrets:
            cmd.append("--scanners")
            cmd.append("secret")

        cmd.append(target)

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

        try:
            output = json.loads(result.stdout)
        except json.JSONDecodeError:
            return {}

        return output

    def _severity_meets_threshold(self, severity: TrivySeverity) -> bool:
        """Check if severity meets the threshold."""
        severity_order = {
            TrivySeverity.CRITICAL: 4,
            TrivySeverity.HIGH: 3,
            TrivySeverity.MEDIUM: 2,
            TrivySeverity.LOW: 1,
            TrivySeverity.UNKNOWN: 0,
        }
        return severity_order[severity] >= severity_order[self._config.severity_threshold]

    def _process_vulnerabilities(
        self,
        results: dict[str, Any],
        session_id: str,
        target: str,
    ) -> list[Finding]:
        """Process vulnerability results into findings."""
        findings = []
        results_data = results.get("Results", [])

        for result in results_data:
            vulnerabilities = result.get("Vulnerabilities", [])
            target_name = result.get("Target", target)

            for vuln in vulnerabilities:
                severity = TrivySeverity(vuln.get("Severity", "UNKNOWN"))

                if not self._severity_meets_threshold(severity):
                    continue

                vulnerability_id = vuln.get("VulnerabilityID", "UNKNOWN")
                finding_hash = sha256_text(f"{session_id}:{vulnerability_id}:{target_name}")[:16]
                finding = Finding(
                    finding_id=f"trivy_vuln_{finding_hash}",
                    rule_id=vulnerability_id,
                    title=vuln.get("Title", "Vulnerability in container"),
                    category=FindingCategory.DEPENDENCY,
                    severity=self._map_severity(severity),
                    file_path=f"container:{target_name}",
                    line=1,
                    snippet=f"{vuln.get('PkgName', 'unknown')}@{vuln.get('InstalledVersion', 'unknown')}",
                    confidence=1.0,
                    cwe=vuln.get("CWEIDs", [""])[0] if vuln.get("CWEIDs") else None,
                    remediation=self._generate_vuln_remediation(vuln),
                )
                findings.append(finding)

        return findings

    def _process_misconfigurations(
        self,
        results: dict[str, Any],
        session_id: str,
        target: str,
    ) -> list[Finding]:
        """Process misconfiguration results into findings."""
        findings = []
        results_data = results.get("Results", [])

        for result in results_data:
            misconfigs = result.get("Misconfigurations", [])
            target_name = result.get("Target", target)

            for misconfig in misconfigs:
                severity = TrivySeverity(misconfig.get("Severity", "UNKNOWN"))

                if not self._severity_meets_threshold(severity):
                    continue

                misconfig_id = misconfig.get("ID", "UNKNOWN")
                finding_hash = sha256_text(f"{session_id}:{misconfig_id}:{target_name}")[:16]
                finding = Finding(
                    finding_id=f"trivy_misconfig_{finding_hash}",
                    rule_id=misconfig_id,
                    title=misconfig.get("Title", "Container misconfiguration"),
                    category=FindingCategory.CONFIGURATION,
                    severity=self._map_severity(severity),
                    file_path=f"container:{target_name}",
                    line=1,
                    snippet=misconfig.get("Message", ""),
                    confidence=0.9,
                    cwe=None,
                    remediation=misconfig.get("Resolution", "Review and fix the misconfiguration"),
                )
                findings.append(finding)

        return findings

    def _map_severity(self, trivy_severity: TrivySeverity) -> FindingSeverity:
        """Map Trivy severity to FindingSeverity."""
        mapping = {
            TrivySeverity.CRITICAL: FindingSeverity.CRITICAL,
            TrivySeverity.HIGH: FindingSeverity.HIGH,
            TrivySeverity.MEDIUM: FindingSeverity.MEDIUM,
            TrivySeverity.LOW: FindingSeverity.LOW,
            TrivySeverity.UNKNOWN: FindingSeverity.MEDIUM,
        }
        return mapping[trivy_severity]

    def _generate_vuln_remediation(self, vuln: dict[str, Any]) -> str:
        """Generate remediation advice for a vulnerability."""
        pkg_name = vuln.get("PkgName", "unknown")
        installed_version = vuln.get("InstalledVersion", "unknown")
        fixed_version = vuln.get("FixedVersion", "latest")

        return f"Update {pkg_name} from {installed_version} to {fixed_version} or later"

    def scan_dockerfile(
        self,
        dockerfile_path: str,
        session_id: str,
    ) -> list[Finding]:
        """Scan a Dockerfile for security issues."""
        dockerfile_dir = str(Path(dockerfile_path).parent)
        return self.scan_filesystem(dockerfile_dir, session_id)

    def get_image_sbom(
        self,
        image_name: str,
    ) -> dict[str, Any]:
        """Get the SBOM of a container image."""
        cmd = [
            "trivy",
            "image",
            "--format",
            "json",
            "--sbom",
            image_name,
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

        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            return {}
