"""Syft integration for SBOM generation (SPDX 2.3)."""

from __future__ import annotations

import json
import logging
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from .models import sha256_text

logger = logging.getLogger(__name__)


class SPDXVersion(StrEnum):
    """SPDX specification versions."""

    SPDX_2_3 = "SPDX-2.3"


@dataclass
class SBOMConfig:
    """Configuration for SBOM generation."""

    spdx_version: SPDXVersion = SPDXVersion.SPDX_2_3
    include_files: bool = True
    timeout_seconds: int = 120


@dataclass
class SPDXComponent:
    """SPDX component representation."""

    spdx_id: str
    name: str
    version: str
    purl: str | None = None
    supplier: str | None = None
    download_location: str | None = None
    files_analyzed: bool = False
    license_concluded: str | None = None
    license_declared: str | None = None
    external_references: list[dict[str, str]] | None = None
    checksums: list[dict[str, str]] | None = None


@dataclass
class SPDXDocument:
    """SPDX document representation."""

    spdx_version: str
    data_license: str
    spdx_id: str
    name: str
    document_namespace: str
    creation_info: dict[str, Any]
    packages: list[SPDXComponent]
    files: list[dict[str, Any]] | None = None


class SBOMGenerator:
    """SBOM generator using Syft."""

    def __init__(self, config: SBOMConfig) -> None:
        self._config = config

    def generate_sbom(
        self,
        repo_path: str,
        session_id: str,
    ) -> dict[str, Any]:
        """Generate SPDX 2.3 SBOM for a repository."""
        # Use Syft CLI to generate SBOM
        syft_output = self._run_syft(repo_path)

        # Convert to SPDX 2.3 format
        spdx_doc = self._convert_to_spdx(syft_output, repo_path, session_id)

        return spdx_doc

    def _run_syft(self, repo_path: str) -> dict[str, Any]:
        """Run Syft CLI to generate SBOM."""
        try:
            result = subprocess.run(
                [
                    "syft",
                    str(repo_path),
                    "--output",
                    "json",
                    "--file",
                    "/dev/stdout",
                ],
                capture_output=True,
                text=True,
                timeout=self._config.timeout_seconds,
                check=True,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.CalledProcessError):
            # Return empty structure if Syft fails
            return {"artifacts": [], "source": {"path": repo_path}}

        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            return {"artifacts": [], "source": {"path": repo_path}}

    def _convert_to_spdx(
        self,
        syft_output: dict[str, Any],
        repo_path: str,
        session_id: str,
    ) -> dict[str, Any]:
        """Convert Syft output to SPDX 2.3 format."""
        repo_name = Path(repo_path).name
        timestamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        namespace = f"https://sentinel.example/sbom/{session_id}/{repo_name}"

        # Extract artifacts from Syft output
        artifacts = syft_output.get("artifacts", [])

        # Convert to SPDX components
        packages = []
        for artifact in artifacts:
            component = self._artifact_to_component(artifact)
            packages.append(component)

        # Build SPDX document
        spdx_doc = {
            "spdxVersion": self._config.spdx_version.value,
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": f"{repo_name} SBOM",
            "documentNamespace": namespace,
            "creationInfo": {
                "created": timestamp,
                "creators": [
                    "Tool: syft",
                    "Organization: Project Sentinel",
                ],
            },
            "packages": [pkg.model_dump() for pkg in packages],
        }

        # Add files if requested
        if self._config.include_files:
            files = self._extract_files(repo_path)
            spdx_doc["files"] = files

        return spdx_doc

    def _artifact_to_component(self, artifact: dict[str, Any]) -> SPDXComponent:
        """Convert a Syft artifact to SPDX component."""
        name = artifact.get("name", "unknown")
        version = artifact.get("version", "unknown")
        purl = artifact.get("purl", "")
        location = artifact.get("locations", [{}])[0].get("path", "")

        # Generate SPDX ID
        spdx_id = f"SPDXRef-Package-{sha256_text(f'{name}:{version}')[:16]}"

        # Extract license if available
        licenses = artifact.get("licenses", [])
        license_declared = licenses[0] if licenses else "NOASSERTION"

        # Extract checksums
        checksums = []
        if "digest" in artifact:
            checksums.append(
                {
                    "algorithm": "SHA256",
                    "checksumValue": artifact["digest"],
                }
            )

        return SPDXComponent(
            spdx_id=spdx_id,
            name=name,
            version=version,
            purl=purl,
            download_location=location,
            files_analyzed=False,
            license_declared=license_declared,
            license_concluded=license_declared,
            checksums=checksums if checksums else None,
        )

    def _extract_files(self, repo_path: str) -> list[dict[str, Any]]:
        """Extract file information from repository."""
        files = []
        repo_root = Path(repo_path)

        # Get all source files
        for file_path in repo_root.rglob("*"):
            if not file_path.is_file():
                continue

            # Skip common ignore patterns
            if any(
                part in file_path.parts
                for part in [".git", "node_modules", "__pycache__", ".venv", "venv"]
            ):
                continue

            try:
                relative_path = str(file_path.relative_to(repo_root))
                file_id = f"SPDXRef-File-{sha256_text(relative_path)[:16]}"

                file_entry = {
                    "SPDXID": file_id,
                    "fileName": relative_path,
                    "fileTypes": [self._get_file_type(file_path)],
                    "licenseConcluded": "NOASSERTION",
                }

                # Add checksum if file is not too large
                if file_path.stat().st_size < 10 * 1024 * 1024:  # 10MB limit
                    import hashlib

                    with open(file_path, "rb") as f:
                        sha256 = hashlib.sha256(f.read()).hexdigest()
                    file_entry["checksums"] = [
                        {
                            "algorithm": "SHA256",
                            "checksumValue": sha256,
                        }
                    ]

                files.append(file_entry)
            except Exception:
                logger.debug("Skipping file during SBOM generation: %s", file_path, exc_info=True)
                continue

        return files

    def _get_file_type(self, file_path: Path) -> str:
        """Determine SPDX file type from extension."""
        suffix = file_path.suffix.lower()
        mapping = {
            ".py": "TEXT",
            ".js": "TEXT",
            ".jsx": "TEXT",
            ".ts": "TEXT",
            ".tsx": "TEXT",
            ".go": "TEXT",
            ".rs": "TEXT",
            ".java": "TEXT",
            ".c": "TEXT",
            ".cpp": "TEXT",
            ".h": "TEXT",
            ".json": "TEXT",
            ".yaml": "TEXT",
            ".yml": "TEXT",
            ".xml": "TEXT",
            ".md": "TEXT",
            ".txt": "TEXT",
            ".sh": "TEXT",
            ".dockerfile": "TEXT",
        }
        return mapping.get(suffix, "OTHER")

    def save_sbom(
        self,
        sbom: dict[str, Any],
        output_path: str,
    ) -> None:
        """Save SBOM to file."""
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(output_file, "w") as f:
            json.dump(sbom, f, indent=2)

    def get_dependency_count(self, sbom: dict[str, Any]) -> int:
        """Get the total number of dependencies in SBOM."""
        packages = sbom.get("packages", [])
        return len(packages)

    async def check_supply_chain(self, deps: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Query OSV.dev REST API for known dependency vulnerabilities to detect supply chain attacks."""
        import httpx
        vulns_detected = []
        async with httpx.AsyncClient(timeout=10.0) as client:
            for dep in deps:
                name = dep.get("name")
                version = dep.get("version")
                if not name or not version:
                    continue
                try:
                    payload = {"package": {"name": name, "ecosystem": "PyPI"}, "version": version}
                    res = await client.post("https://api.osv.dev/v1/query", json=payload)
                    if res.status_code == 200:
                        vulns = res.json().get("vulns", [])
                        for v in vulns:
                            vulns_detected.append({
                                "package": name,
                                "version": version,
                                "id": v.get("id"),
                                "summary": v.get("summary", "Known supply chain vulnerability"),
                                "severity": v.get("database_specific", {}).get("severity", "HIGH"),
                            })
                except Exception:
                    pass
        return vulns_detected

    def get_vulnerable_dependencies(
        self,
        sbom: dict[str, Any],
        cve_scanner,
        session_id: str,
    ) -> list[dict[str, Any]]:
        """Scan SBOM for vulnerable dependencies using CVE scanner."""
        findings = cve_scanner.scan_sbom(sbom, session_id)
        return findings

    def compare_sboms(
        self,
        original_sbom: dict[str, Any],
        new_sbom: dict[str, Any],
    ) -> dict[str, Any]:
        """Compare two SBOMs and identify changes."""
        original_packages = {
            (pkg["name"], pkg["version"]): pkg
            for pkg in original_sbom.get("packages", [])
        }
        new_packages = {
            (pkg["name"], pkg["version"]): pkg for pkg in new_sbom.get("packages", [])
        }

        added = set(new_packages.keys()) - set(original_packages.keys())
        removed = set(original_packages.keys()) - set(new_packages.keys())
        changed = []

        for key in set(original_packages.keys()) & set(new_packages.keys()):
            if original_packages[key] != new_packages[key]:
                changed.append(key)

        return {
            "added": [f"{name}@{version}" for name, version in added],
            "removed": [f"{name}@{version}" for name, version in removed],
            "changed": [f"{name}@{version}" for name, version in changed],
        }
