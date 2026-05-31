import argparse
import asyncio
import json
import os
import sys

from sentinel.config import load_settings
from sentinel.github_integration import GitHubIntegrationError, create_github_pr
from sentinel.memory import RepositoryIngestor
from sentinel.models import AuditRequest, SessionStatus, Verdict
from sentinel.orchestrator import SentinelOrchestrator


async def run_full_audit(args, settings):
    """Run a full audit with LLM-powered patching."""
    auto_pr = args.auto_pr.lower() in ("true", "1", "yes")
    github_token = os.environ.get("GITHUB_TOKEN")

    orchestrator = SentinelOrchestrator(settings=settings)
    request = AuditRequest(repo_path=args.repo_path)

    print(f"Starting audit for repository: {args.repo_path}")
    session = await orchestrator.create_session(request)
    session = await orchestrator.run_session(session.session_id)

    print("\n" + "=" * 40)
    print("        SENTINEL AUDIT REPORT        ")
    print("=" * 40)

    if session.memory:
        print(f"\nTotal Findings: {len(session.memory.findings)}")
        for finding in session.memory.findings:
            print(f" - [{finding.severity.value}] {finding.category.value} in {finding.file_path}")

    print(f"\nTotal Tasks Generated: {len(session.tasks)}")
    for task in session.tasks:
        print(f" - {task.title} (Status: {task.status.value})")

    print(f"\nTotal Patches Evaluated: {len(session.patches)}")

    for val in session.validations:
        if val.verdict == Verdict.APPROVE:
            patch = next((p for p in session.patches if p.patch_id == val.patch_id), None)
            if patch and patch.engineer_confidence >= 0.8:
                print(f"\n✅ Approved Patch {patch.patch_id}")
                for file_patch in patch.files:
                    print(f"   Modified: {file_patch.file_path}")

                if auto_pr and github_token:
                    print("   Creating GitHub Pull Request...")
                    try:
                        pr_url = await create_github_pr(session, patch, github_token)
                        print(f"   🎉 PR Created Successfully: {pr_url}")
                    except GitHubIntegrationError as e:
                        print(f"   ❌ Failed to create PR: {e}")
                elif auto_pr and not github_token:
                    print("   ⚠️ Cannot create PR: GITHUB_TOKEN is not set.")

    print("\n" + "=" * 40)

    if session.status in (SessionStatus.ESCALATED, SessionStatus.FAILED):
        print(f"\n[ERROR] Audit ended with status: {session.status.value}. Unresolved issues require human review.")
        sys.exit(1)

    print("\n[SUCCESS] Audit completed successfully.")
    sys.exit(0)


def run_scan_only(args, settings):
    """Run scan-only mode when no LLM API key is available."""
    print(f"Starting scan-only audit for repository: {args.repo_path}")
    print("ℹ️  No LLM API key configured. Running built-in scanner without AI patching.\n")

    ingestor = RepositoryIngestor(settings)
    memory = ingestor.ingest(args.repo_path)

    print("=" * 40)
    print("     SENTINEL SCAN-ONLY REPORT     ")
    print("=" * 40)

    print(f"\nFiles Indexed: {memory.files_indexed}")
    print(f"Symbols Extracted: {len(memory.symbols)}")
    print(f"Total Findings: {len(memory.findings)}")

    if memory.findings:
        # Group by severity
        by_severity: dict[str, list] = {}
        for finding in memory.findings:
            sev = finding.severity.value
            by_severity.setdefault(sev, []).append(finding)

        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            findings_list = by_severity.get(severity, [])
            if findings_list:
                print(f"\n{'🔴' if severity == 'CRITICAL' else '🟠' if severity == 'HIGH' else '🟡' if severity == 'MEDIUM' else '🟢'} {severity} ({len(findings_list)}):")
                for finding in findings_list:
                    print(f"  - [{finding.rule_id}] {finding.title}")
                    print(f"    File: {finding.file_path}:{finding.line}")

        # Write JSON report for CI consumption
        report = {
            "files_indexed": memory.files_indexed,
            "findings": [f.model_dump(mode="json") for f in memory.findings],
        }
        with open("audit-report.json", "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print("\n📄 Report written to audit-report.json")
    else:
        print("\n✅ No security findings detected.")

    print("\n" + "=" * 40)


async def main():
    parser = argparse.ArgumentParser(description="Project Sentinel CLI")
    parser.add_argument("--repo-path", required=True)
    parser.add_argument("--auto-pr", default="true")
    parser.add_argument("--severity", default="HIGH")
    args = parser.parse_args()

    settings = load_settings()

    # Check if an LLM API key is available
    has_llm = bool(
        settings.anthropic_api_key
        or os.getenv("ANTHROPIC_API_KEY")
        or os.getenv("OPENROUTER_API_KEY")
        or os.getenv("AZURE_OPENAI_KEY")
    )

    if has_llm:
        await run_full_audit(args, settings)
    else:
        run_scan_only(args, settings)


if __name__ == "__main__":
    asyncio.run(main())
