"""Export Sentinel findings as SARIF 2.1.0 for GitHub Advanced Security / Azure DevOps."""

from __future__ import annotations

from typing import Any

from .models import AuditSession, Finding, FindingSeverity
from .owasp_mapping import owasp_tags_for_cwe

_SARIF_VERSION = "2.1.0"
_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

_SEVERITY_LEVEL = {
    FindingSeverity.CRITICAL: "error",
    FindingSeverity.HIGH: "error",
    FindingSeverity.MEDIUM: "warning",
    FindingSeverity.LOW: "note",
}


def _rule_from_finding(finding: Finding) -> dict[str, Any]:
    return {
        "id": finding.rule_id,
        "name": finding.title,
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.remediation},
        "helpUri": f"https://cwe.mitre.org/data/definitions/{finding.cwe.replace('CWE-', '')}.html"
        if finding.cwe
        else None,
        "properties": {
            "tags": owasp_tags_for_cwe(finding.cwe),
            "category": finding.category.value,
        },
    }


def _result_from_finding(finding: Finding, repo_uri: str) -> dict[str, Any]:
    level = _SEVERITY_LEVEL.get(finding.severity, "warning")
    result: dict[str, Any] = {
        "ruleId": finding.rule_id,
        "level": level,
        "message": {"text": f"{finding.title}: {finding.remediation}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.file_path, "uriBaseId": "ROOTPATH"},
                    "region": {"startLine": finding.line},
                }
            }
        ],
        "properties": {
            "findingId": finding.finding_id,
            "confidence": finding.confidence,
            "cwe": finding.cwe,
            "snippet": finding.snippet[:500],
            "owasp": owasp_tags_for_cwe(finding.cwe),
        },
    }
    if finding.cwe:
        result["taxa"] = [{"id": finding.cwe, "toolComponent": {"name": "CWE"}}]
    return result


def session_to_sarif(session: AuditSession) -> dict[str, Any]:
    findings = session.memory.findings if session.memory else []
    rules = [_rule_from_finding(f) for f in findings]
    # Deduplicate rules by id
    seen: set[str] = set()
    unique_rules: list[dict[str, Any]] = []
    for rule in rules:
        if rule["id"] in seen:
            continue
        seen.add(rule["id"])
        if rule.get("helpUri") is None:
            rule.pop("helpUri", None)
        unique_rules.append(rule)

    repo_uri = session.repo_path
    return {
        "version": _SARIF_VERSION,
        "$schema": _SARIF_SCHEMA,
        "properties": {
            "sessionId": session.session_id,
            "objective": session.objective,
            "producer": "Project Sentinel",
        },
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Project Sentinel",
                        "version": "4.0",
                        "informationUri": "https://github.com/Akshat-coder2106/Agent-Swarms",
                        "rules": unique_rules,
                    }
                },
                "originalUriBaseIds": {
                    "ROOTPATH": {"uri": repo_uri if repo_uri.endswith("/") else f"{repo_uri}/"}
                },
                "results": [_result_from_finding(f, repo_uri) for f in findings],
            }
        ],
    }
