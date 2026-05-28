import argparse
import asyncio
import os
import sys

from sentinel.config import Settings
from sentinel.github_integration import create_github_pr, GitHubIntegrationError
from sentinel.models import AuditRequest, SessionStatus, Verdict, FindingSeverity
from sentinel.orchestrator import SentinelOrchestrator

async def main():
    parser = argparse.ArgumentParser(description="Project Sentinel CLI")
    parser.add_argument("--repo-path", required=True)
    parser.add_argument("--auto-pr", default="true")
    parser.add_argument("--severity", default="HIGH")
    args = parser.parse_args()

    settings = Settings()
    
    auto_pr = args.auto_pr.lower() in ("true", "1", "yes")
    github_token = os.environ.get("GITHUB_TOKEN")
    
    orchestrator = SentinelOrchestrator(settings=settings)
    request = AuditRequest(repo_path=args.repo_path)
    
    print(f"Starting audit for repository: {args.repo_path}")
    session = await orchestrator.create_session(request)
    session = await orchestrator.run_session(session.session_id)
    
    print("\n" + "="*40)
    print("        SENTINEL AUDIT REPORT        ")
    print("="*40)
    
    if session.memory:
        print(f"\nTotal Findings: {len(session.memory.findings)}")
        for finding in session.memory.findings:
            print(f" - [{finding.severity.value}] {finding.category.value} in {finding.file_path}")
            
    print(f"\nTotal Tasks Generated: {len(session.tasks)}")
    for task in session.tasks:
        print(f" - {task.title} (Status: {task.status.value})")
        
    print(f"\nTotal Patches Evaluated: {len(session.patches)}")
    
    approved_patches = []
    for val in session.validations:
        if val.verdict == Verdict.APPROVE:
            patch = next((p for p in session.patches if p.patch_id == val.patch_id), None)
            if patch and patch.engineer_confidence >= 0.8:
                approved_patches.append(patch)
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
                    
    print("\n" + "="*40)
    
    if session.status in (SessionStatus.ESCALATED, SessionStatus.FAILED):
        print(f"\n[ERROR] Audit ended with status: {session.status.value}. Unresolved issues require human review.")
        sys.exit(1)
        
    print("\n[SUCCESS] Audit completed successfully.")
    sys.exit(0)

if __name__ == "__main__":
    asyncio.run(main())
