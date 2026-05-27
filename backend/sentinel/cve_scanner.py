"""OSV Scanner and NVD integration for CVE intelligence."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

import httpx

from .models import (
    Finding,
    FindingCategory,
    FindingSeverity,
    sha256_text,
)


class CVSSSeverity(StrEnum):
    """CVSS severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class CVEInfo:
    """CVE information."""

    cve_id: str
    cvss_score: float
    severity: CVSSSeverity
    summary: str
    affected_package: str
    affected_version: str
    fixed_version: str | None = None
    references: list[str] | None = None
    published_date: str | None = None
    modified_date: str | None = None


@dataclass
class OSVConfig:
    """Configuration for OSV/NVD integration."""

    osv_api_url: str = "https://api.osv.dev"
    nvd_api_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    min_cvss_score: float = 7.0
    timeout_seconds: int = 60


class CVEScanner:
    """Scanner for CVE vulnerabilities in dependencies."""

    def __init__(self, config: OSVConfig) -> None:
        self._config = config
        self._http_client = httpx.AsyncClient(timeout=config.timeout_seconds)

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._http_client.aclose()

    async def scan_sbom(
        self,
        sbom_data: dict[str, Any],
        session_id: str,
    ) -> list[Finding]:
        """Scan SBOM for CVE vulnerabilities."""
        findings = []
        components = sbom_data.get("components", [])

        for component in components:
            package_name = component.get("name", "")
            version = component.get("version", "")

            if not package_name or not version:
                continue

            # Query OSV for vulnerabilities
            cves = await self._query_osv(package_name, version)

            # Filter by CVSS score
            high_severity_cves = [
                cve for cve in cves if cve.cvss_score >= self._config.min_cvss_score
            ]

            for cve in high_severity_cves:
                finding = self._cve_to_finding(cve, session_id, package_name, version)
                findings.append(finding)

        return findings

    async def _query_osv(
        self,
        package_name: str,
        version: str,
    ) -> list[CVEInfo]:
        """Query OSV API for vulnerabilities."""
        try:
            response = await self._http_client.post(
                f"{self._config.osv_api_url}/v1/query",
                json={
                    "package": {
                        "name": package_name,
                        "version": version,
                    }
                },
            )
            response.raise_for_status()
            data = response.json()
        except Exception:
            return []

        cves = []
        for vuln in data.get("vulns", []):
            cve_id = vuln.get("id", "")
            summary = vuln.get("summary", "")
            published = vuln.get("published", "")
            modified = vuln.get("modified", "")

            # Extract CVSS score
            cvss_score = self._extract_cvss_score(vuln)
            severity = self._cvss_to_severity(cvss_score)

            # Extract affected versions
            affected = self._extract_affected_versions(vuln)
            fixed_version = affected.get("fixed")

            # Extract references
            references = [
                ref.get("url", "") for ref in vuln.get("references", []) if ref.get("url")
            ]

            cve = CVEInfo(
                cve_id=cve_id,
                cvss_score=cvss_score,
                severity=severity,
                summary=summary,
                affected_package=package_name,
                affected_version=version,
                fixed_version=fixed_version,
                references=references,
                published_date=published,
                modified_date=modified,
            )
            cves.append(cve)

        return cves

    def _extract_cvss_score(self, vuln: dict[str, Any]) -> float:
        """Extract CVSS score from vulnerability data."""
        severity = vuln.get("severity", [])
        for sev in severity:
            if sev.get("type") == "CVSS_V3":
                score = sev.get("score", 0.0)
                return float(score)
        return 0.0

    def _cvss_to_severity(self, score: float) -> CVSSSeverity:
        """Convert CVSS score to severity level."""
        if score >= 9.0:
            return CVSSSeverity.CRITICAL
        elif score >= 7.0:
            return CVSSSeverity.HIGH
        elif score >= 4.0:
            return CVSSSeverity.MEDIUM
        else:
            return CVSSSeverity.LOW

    def _extract_affected_versions(self, vuln: dict[str, Any]) -> dict[str, str]:
        """Extract affected and fixed versions."""
        affected = vuln.get("affected", [])
        if not affected:
            return {}

        pkg_affected = affected[0]
        ranges = pkg_affected.get("ranges", [])

        for range_info in ranges:
            events = range_info.get("events", [])
            for event in events:
                if "fixed" in event:
                    return {"fixed": event["fixed"]}

        return {}

    def _cve_to_finding(
        self,
        cve: CVEInfo,
        session_id: str,
        package_name: str,
        version: str,
    ) -> Finding:
        """Convert CVE info to a Finding."""
        severity = self._map_severity(cve.severity)

        remediation = f"Update {package_name} from {version} to {cve.fixed_version or 'latest secure version'}"
        if cve.references:
            remediation += f". References: {', '.join(cve.references[:2])}"

        return Finding(
            finding_id=f"cve_{sha256_text(f'{session_id}:{cve.cve_id}')[:16]}",
            rule_id=cve.cve_id,
            title=f"{cve.cve_id}: {cve.summary}",
            category=FindingCategory.DEPENDENCY,
            severity=severity,
            file_path=f"dependency:{package_name}",
            line=1,
            snippet=f"{package_name}@{version}",
            confidence=1.0,  # CVE data is authoritative
            cwe=None,  # CVEs don't always map to CWEs directly
            remediation=remediation,
        )

    def _map_severity(self, cve_severity: CVSSSeverity) -> FindingSeverity:
        """Map CVE severity to FindingSeverity."""
        mapping = {
            CVSSSeverity.CRITICAL: FindingSeverity.CRITICAL,
            CVSSSeverity.HIGH: FindingSeverity.HIGH,
            CVSSSeverity.MEDIUM: FindingSeverity.MEDIUM,
            CVSSSeverity.LOW: FindingSeverity.LOW,
        }
        return mapping[cve_severity]

    async def scan_with_osv_cli(
        self,
        repo_path: str,
        session_id: str,
    ) -> list[Finding]:
        """Scan repository using OSV CLI tool."""
        try:
            result = subprocess.run(
                ["osv-scanner", "--json", "--format", "json", str(repo_path)],
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
        for result_item in output.get("results", []):
            for vuln in result_item.get("vulns", []):
                cve_id = vuln.get("id", "")
                summary = vuln.get("summary", "")

                # Extract CVSS score
                cvss_score = self._extract_cvss_score(vuln)
                severity = self._cvss_to_severity(cvss_score)

                if cvss_score < self._config.min_cvss_score:
                    continue

                # Get package info
                package_info = result_item.get("package", {})
                package_name = package_info.get("name", "")
                version = package_info.get("version", "")

                cve = CVEInfo(
                    cve_id=cve_id,
                    cvss_score=cvss_score,
                    severity=severity,
                    summary=summary,
                    affected_package=package_name,
                    affected_version=version,
                )

                finding = self._cve_to_finding(cve, session_id, package_name, version)
                findings.append(finding)

        return findings

    async def query_nvd_cve(self, cve_id: str) -> CVEInfo | None:
        """Query NVD API for specific CVE details."""
        try:
            response = await self._http_client.get(
                f"{self._config.nvd_api_url}?cveId={cve_id}"
            )
            response.raise_for_status()
            data = response.json()
        except Exception:
            return None

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return None

        vuln = vulns[0]
        cve_data = vuln.get("cve", {})
        metrics = cve_data.get("metrics", {})

        # Extract CVSS score
        cvss_score = 0.0
        if "cvssMetricV31" in metrics:
            cvss_data = metrics["cvssMetricV31"][0]
            cvss_score = cvss_data.get("cvssData", {}).get("baseScore", 0.0)

        severity = self._cvss_to_severity(cvss_score)

        # Extract description
        descriptions = cve_data.get("descriptions", [])
        summary = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                summary = desc.get("value", "")
                break

        return CVEInfo(
            cve_id=cve_id,
            cvss_score=cvss_score,
            severity=severity,
            summary=summary,
            affected_package="",
            affected_version="",
        )
