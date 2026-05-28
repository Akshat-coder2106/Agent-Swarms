"""
Temporal workflow definitions for durable execution.

Replaces in-memory LangGraph orchestrator.
"""
from datetime import timedelta

from temporalio import workflow

with workflow.unsafe.imports_passed_through():
    from .activities import analyze_repository, create_pr, generate_patch, validate_patch


@workflow.defn
class SentinelRemediationWorkflow:
    @workflow.run
    async def run(self, repo_url: str) -> dict:
        """Main durable workflow for security auditing and remediation."""
        
        # 1. Analyze the repository
        findings = await workflow.execute_activity(
            analyze_repository,
            repo_url,
            start_to_close_timeout=timedelta(minutes=10)
        )
        
        if not findings:
            return {"status": "clean", "findings": 0}

        # 2. For each finding, generate and validate a patch
        applied_patches = []
        for finding in findings:
            patch = await workflow.execute_activity(
                generate_patch,
                finding,
                start_to_close_timeout=timedelta(minutes=5)
            )
            
            is_valid = await workflow.execute_activity(
                validate_patch,
                {"repo": repo_url, "patch": patch},
                start_to_close_timeout=timedelta(minutes=5)
            )
            
            if is_valid:
                applied_patches.append(patch)

        # 3. Create PR if patches were successful
        if applied_patches:
            pr_url = await workflow.execute_activity(
                create_pr,
                {"repo": repo_url, "patches": applied_patches},
                start_to_close_timeout=timedelta(minutes=2)
            )
            return {"status": "remediated", "pr_url": pr_url}

        return {"status": "failed", "reason": "No valid patches generated"}
