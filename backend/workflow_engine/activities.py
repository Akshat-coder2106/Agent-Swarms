"""
Temporal Activities for Sentinel Workflow.

Activities perform discrete, retryable actions.
"""
from typing import Any, Dict, List
from temporalio import activity

@activity.defn
async def analyze_repository(repo_url: str) -> List[Dict[str, Any]]:
    """Analyzes a repository for security vulnerabilities."""
    activity.logger.info(f"Analyzing repository: {repo_url}")
    # In a real implementation, this invokes the Scanners or the Architect agent.
    # We return a stubbed finding.
    return [
        {
            "file_path": "src/api.py",
            "line_number": 42,
            "issue_type": "SQL Injection",
            "description": "Unsanitized input in query",
            "severity": "HIGH"
        }
    ]

@activity.defn
async def generate_patch(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Generates a secure patch for a given finding using the Engineer agent."""
    activity.logger.info(f"Generating patch for: {finding['file_path']}")
    # Returns a stubbed patch proposal.
    return {
        "rationale": "Use parameterized queries to prevent SQLi.",
        "patch_id": "patch-123",
        "files": []
    }

@activity.defn
async def validate_patch(payload: Dict[str, Any]) -> bool:
    """Validates the patch in the Firecracker Sandbox."""
    activity.logger.info("Validating patch in Sandbox...")
    # Real implementation calls the Sandbox Service
    return True

@activity.defn
async def create_pr(payload: Dict[str, Any]) -> str:
    """Creates a Pull Request via the GitHub App integration."""
    activity.logger.info("Creating PR via GitHub App...")
    return "https://github.com/demo/repo/pull/42"
