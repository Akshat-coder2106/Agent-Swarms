"""Map CWE identifiers to OWASP Top 10:2021 categories for Microsoft security dashboards."""

from __future__ import annotations

_CWE_TO_OWASP: dict[str, list[str]] = {
    "CWE-79": ["A03:2021-Injection", "A07:2021-Identification and Authentication Failures"],
    "CWE-89": ["A03:2021-Injection"],
    "CWE-94": ["A03:2021-Injection"],
    "CWE-22": ["A01:2021-Broken Access Control"],
    "CWE-502": ["A08:2021-Software and Data Integrity Failures"],
    "CWE-338": ["A02:2021-Cryptographic Failures"],
    "CWE-798": ["A07:2021-Identification and Authentication Failures"],
    "CWE-116": ["A05:2021-Security Misconfiguration"],
}


def owasp_tags_for_cwe(cwe: str | None) -> list[str]:
    if not cwe:
        return ["A06:2021-Vulnerable and Outdated Components"]
    normalized = cwe.upper() if cwe.startswith("CWE") else f"CWE-{cwe}"
    if not normalized.startswith("CWE-"):
        normalized = f"CWE-{normalized}"
    return _CWE_TO_OWASP.get(normalized, ["A10:2021-Server-Side Request Forgery (SSRF)"])
