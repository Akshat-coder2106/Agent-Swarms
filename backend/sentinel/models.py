from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, computed_field, field_validator, model_validator


class AgentRole(StrEnum):
    ARCHITECT = "architect"
    SCOUT = "scout"
    ENGINEER = "engineer"
    CRITIC = "critic"
    ROUTER = "router"


class MessageType(StrEnum):
    TASK_ASSIGNMENT = "TASK_ASSIGNMENT"
    EVIDENCE_PACKAGE = "EVIDENCE_PACKAGE"
    PATCH_SUBMISSION = "PATCH_SUBMISSION"
    VALIDATION_VERDICT = "VALIDATION_VERDICT"
    ESCALATION = "ESCALATION"
    HEARTBEAT = "HEARTBEAT"


class Priority(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class SessionStatus(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    ESCALATED = "ESCALATED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    ROLLED_BACK = "ROLLED_BACK"


class TaskStatus(StrEnum):
    PENDING = "PENDING"
    ACTIVE = "ACTIVE"
    PASSED = "PASSED"
    FAILED = "FAILED"
    ESCALATED = "ESCALATED"


class FindingSeverity(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FindingCategory(StrEnum):
    INJECTION = "INJECTION"
    SECRET = "SECRET"
    UNSAFE_EXECUTION = "UNSAFE_EXECUTION"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    DESERIALIZATION = "DESERIALIZATION"
    XSS = "XSS"
    CRYPTOGRAPHY = "CRYPTOGRAPHY"
    DEPENDENCY = "DEPENDENCY"
    CONFIGURATION = "CONFIGURATION"
    MISC = "MISC"


class EventType(StrEnum):
    ARCHITECT_UPDATE = "ARCHITECT_UPDATE"
    SCOUT_RETRIEVAL = "SCOUT_RETRIEVAL"
    ENGINEER_PATCH = "ENGINEER_PATCH"
    VALIDATION_STARTED = "VALIDATION_STARTED"
    SANDBOX_LOG = "SANDBOX_LOG"
    SANDBOX_RESULT = "SANDBOX_RESULT"
    CRITIC_VERDICT = "CRITIC_VERDICT"
    CRITIC_REJECTION = "CRITIC_REJECTION"
    DELTA_UPDATE = "DELTA_UPDATE"
    BUDGET_UPDATE = "BUDGET_UPDATE"
    ESCALATION = "ESCALATION"
    ROLLBACK_INITIATED = "ROLLBACK_INITIATED"
    SESSION_COMPLETE = "SESSION_COMPLETE"
    AUDIT_LOG = "AUDIT_LOG"


class SandboxTier(StrEnum):
    SCRIPTED = "SCRIPTED"
    COMPILED = "COMPILED"


class ValidationAxisStatus(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    SKIP = "SKIP"


class Verdict(StrEnum):
    APPROVE = "APPROVE"
    REJECT = "REJECT"
    ESCALATE = "ESCALATE"


def utc_now() -> datetime:
    return datetime.now(UTC)


def stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class SessionNotFoundError(KeyError):
    """Raised when an audit session id is unknown."""


class MCPMessage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mcp_version: str = "1.2"
    message_id: str = Field(default_factory=lambda: f"msg_{uuid4().hex}")
    session_id: str
    task_id: str
    timestamp: datetime = Field(default_factory=utc_now)
    sender: AgentRole
    recipient: AgentRole
    message_type: MessageType
    priority: Priority
    payload: dict[str, Any]
    checksum: str | None = None

    @computed_field
    @property
    def computed_checksum(self) -> str:
        return sha256_text(stable_json(self.payload))

    def with_checksum(self) -> MCPMessage:
        return self.model_copy(update={"checksum": self.computed_checksum})

    def verify_checksum(self) -> bool:
        return self.checksum == self.computed_checksum


class CodeSymbol(BaseModel):
    model_config = ConfigDict(extra="forbid")

    symbol_id: str
    name: str
    kind: str
    file_path: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)


class CodeGraphEdge(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_id: str
    target_id: str
    relationship: str


class CodeChunk(BaseModel):
    model_config = ConfigDict(extra="forbid")

    chunk_id: str
    file_path: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    text: str
    token_fingerprint: str


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str = Field(default_factory=lambda: f"finding_{uuid4().hex}")
    rule_id: str
    title: str
    category: FindingCategory
    severity: FindingSeverity
    file_path: str
    line: int = Field(ge=1)
    snippet: str
    confidence: float = Field(ge=0.0, le=1.0)
    cwe: str | None = None
    remediation: str


class RepositoryMemory(BaseModel):
    model_config = ConfigDict(extra="forbid")

    root_path: str
    files_indexed: int
    chunks: list[CodeChunk]
    symbols: list[CodeSymbol]
    edges: list[CodeGraphEdge]
    findings: list[Finding]
    validation_commands: list[list[str]]


class AgentTask(BaseModel):
    model_config = ConfigDict(extra="forbid")

    task_id: str = Field(default_factory=lambda: f"task_{uuid4().hex}")
    title: str
    objective: str
    target_path: str
    priority: Priority
    status: TaskStatus = TaskStatus.PENDING
    finding_ids: list[str] = Field(default_factory=list)
    execution_profile: SandboxTier = SandboxTier.SCRIPTED


class EvidencePackage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    task_id: str
    finding: Finding
    related_chunks: list[CodeChunk]
    related_symbols: list[CodeSymbol]
    graph_neighbors: list[CodeGraphEdge]
    static_scan_count: int
    cve_context: dict | None = None


class FilePatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    file_path: str
    original: str
    patched: str

    @computed_field
    @property
    def original_sha256(self) -> str:
        return sha256_text(self.original)

    @computed_field
    @property
    def patched_sha256(self) -> str:
        return sha256_text(self.patched)


class PatchProposal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    patch_id: str = Field(default_factory=lambda: f"patch_{uuid4().hex}")
    task_id: str
    iteration: int = Field(ge=1)
    files: list[FilePatch]
    unified_diff: str
    rationale: str
    risk: Priority
    engineer_confidence: float = Field(ge=0.0, le=1.0)


class ValidationAxis(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    status: ValidationAxisStatus
    detail: str


class SandboxMetadata(BaseModel):
    """Dynamic metadata about the sandbox engine used for validation."""

    model_config = ConfigDict(extra="forbid")

    engine: str  # "firecracker-microvm" | "process-sandbox"
    boot_time_ms: int = 0
    vsock_status: str = "N/A"  # "ESTABLISHED" | "N/A"
    vcpu_count: int = 1
    memory_mb: int = 256
    snapshot_used: bool = False
    isolation_level: str = "process"  # "hardware" | "process"
    workspace_path: str = ""
    workspace_transferred: bool = False
    workspace_sha256: str = ""


class ValidationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    validation_id: str = Field(default_factory=lambda: f"validation_{uuid4().hex}")
    task_id: str
    patch_id: str
    verdict: Verdict
    axes: list[ValidationAxis]
    exit_code: int
    stdout: str
    stderr: str
    passing_tests: int = Field(ge=0)
    total_tests: int = Field(ge=0)
    resolved_findings: int = Field(ge=0)
    total_findings: int = Field(ge=0)
    coverage_delta: float = 0.0
    duration_ms: int = Field(ge=0)
    sandbox_metadata: SandboxMetadata | None = None


class EvidenceBundle(BaseModel):
    """Immutable evidence identity for a validated patch."""

    model_config = ConfigDict(extra="forbid")

    evidence_id: str = Field(default_factory=lambda: f"evidence_{uuid4().hex}")
    session_id: str
    patch_id: str
    patch_sha256: str
    repository_path: str
    validation_id: str
    validation_sha256: str
    sandbox_engine: str
    sandbox_isolation: str
    workspace_sha256: str = ""
    created_at: datetime = Field(default_factory=utc_now)


class ApprovalRecord(BaseModel):
    """Human authorization bound to an exact evidence and patch digest."""

    model_config = ConfigDict(extra="forbid")

    approval_id: str = Field(default_factory=lambda: f"approval_{uuid4().hex}")
    patch_id: str
    patch_sha256: str
    evidence_id: str
    approved_by: str
    approver_role: str
    approved_at: datetime = Field(default_factory=utc_now)


class LogicalDeltaSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    iteration: int
    delta: float
    accumulated_delta: float
    passing_tests: int
    total_tests: int
    resolved_findings: int
    total_findings: int
    coverage_delta: float


class DiagnosisReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    escalation_id: str = Field(default_factory=lambda: f"esc_{uuid4().hex}")
    session_id: str
    task_id: str
    iteration_count: int
    logical_delta_history: list[float]
    deadlock_type: str
    last_failing_test: str | None = None
    last_stack_trace: str | None = None
    last_critic_directive: str
    last_engineer_diff: str
    suggested_hint: str
    tokens_consumed: int
    tokens_remaining: int


class RollbackReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rollback_id: str = Field(default_factory=lambda: f"rb_{uuid4().hex}")
    session_id: str
    patch_id: str
    regression_type: str
    affected_files: list[str]
    rollback_duration_sec: float
    root_cause_hypothesis: str
    recommended_action: str


class AuditEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(default_factory=lambda: f"evt_{uuid4().hex}")
    session_id: str
    event_type: EventType
    timestamp: datetime = Field(default_factory=utc_now)
    agent: AgentRole
    task_id: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)


class AuditSession(BaseModel):
    model_config = ConfigDict(extra="forbid")

    session_id: str = Field(default_factory=lambda: f"sess_{uuid4().hex}")
    objective: str
    repo_path: str
    status: SessionStatus = SessionStatus.PENDING
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    memory: RepositoryMemory | None = None
    tasks: list[AgentTask] = Field(default_factory=list)
    messages: list[MCPMessage] = Field(default_factory=list)
    patches: list[PatchProposal] = Field(default_factory=list)
    validations: list[ValidationResult] = Field(default_factory=list)
    delta_history: list[LogicalDeltaSnapshot] = Field(default_factory=list)
    events: list[AuditEvent] = Field(default_factory=list)
    diagnosis: DiagnosisReport | None = None
    rollback: RollbackReport | None = None
    operator_hint: str | None = None
    approved_patch_ids: list[str] = Field(default_factory=list)
    validated_patch_ids: list[str] = Field(default_factory=list)
    evidence_bundles: list[EvidenceBundle] = Field(default_factory=list)
    approval_records: list[ApprovalRecord] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def _migrate_legacy_approval_fields(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        legacy = data.pop("approved_patch_id", None)
        if legacy:
            ids = list(data.get("approved_patch_ids") or [])
            if legacy not in ids:
                ids.append(legacy)
            data["approved_patch_ids"] = ids
        return data

    @computed_field
    @property
    def approved_patch_id(self) -> str | None:
        """Most recently operator-approved patch (backward compatible)."""
        return self.approved_patch_ids[-1] if self.approved_patch_ids else None


class AuditRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    repo_path: str
    objective: str = "Audit repository for security vulnerabilities"

    @field_validator("repo_path")
    @classmethod
    def repo_path_must_not_be_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("repo_path is required")
        if value.startswith("http://") or value.startswith("https://"):
            return value.strip()
        return str(Path(value).expanduser())


class ApprovalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    patch_id: str


class OperatorHintRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hint: str = Field(min_length=1, max_length=500)


class RollbackRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    patch_id: str
    regression_type: str = "OPERATOR_REJECTED_PATCH"
    root_cause_hypothesis: str = "Operator requested rollback after validation."


class AuthTokenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    subject: str = Field(default="local-operator", min_length=1, max_length=120)
    role: str = Field(default="Admin", min_length=1, max_length=40)


class AuthContext(BaseModel):
    model_config = ConfigDict(extra="forbid")

    subject: str
    session_id: str | None
    expires_at: datetime
    issuer: str
    role: str


class CapabilityStatus(StrEnum):
    IMPLEMENTED = "IMPLEMENTED"
    MVP_ADAPTER = "MVP_ADAPTER"
    PLANNED = "PLANNED"


class CapabilityItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key: str
    label: str
    status: CapabilityStatus
    detail: str


class RuntimeStatus(BaseModel):
    model_config = ConfigDict(extra="forbid")

    platform: str
    sandbox_engine: str
    sandbox_isolation: str
    llm_provider: str
    llm_enabled: bool
    langgraph_enabled: bool
    deterministic_rules: bool
    external_scanners_available: list[str]
    session_persistence: str


class SystemCapabilities(BaseModel):
    model_config = ConfigDict(extra="forbid")

    spec_version: str
    production_complete: bool
    summary: str
    runtime: RuntimeStatus
    capabilities: list[CapabilityItem]
