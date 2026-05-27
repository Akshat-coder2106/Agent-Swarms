"""
Pydantic schemas for structured LLM outputs.

Enforces deterministic schema validation for agents.
"""
from typing import List, Optional
from pydantic import BaseModel, Field

class IssueFinding(BaseModel):
    file_path: str = Field(..., description="Path to the file with the issue")
    line_number: int = Field(..., description="Line number of the issue")
    issue_type: str = Field(..., description="Type of security issue (e.g., XSS, SQLi)")
    description: str = Field(..., description="Detailed explanation of the vulnerability")
    severity: str = Field(..., description="Severity (LOW, MEDIUM, HIGH, CRITICAL)")

class PatchProposalSchema(BaseModel):
    rationale: str = Field(..., description="Explanation of why this patch fixes the issue safely")
    original_code: str = Field(..., description="The original vulnerable code snippet")
    patched_code: str = Field(..., description="The new secure code snippet")
    confidence_score: float = Field(..., ge=0.0, le=1.0, description="Agent confidence in the patch")

class ValidationResultSchema(BaseModel):
    is_safe: bool = Field(..., description="True if the patch compiles and passes tests")
    remaining_vulnerabilities: List[IssueFinding] = Field(default_factory=list)
    sandbox_exit_code: int = Field(..., description="Exit code from the sandbox execution")
