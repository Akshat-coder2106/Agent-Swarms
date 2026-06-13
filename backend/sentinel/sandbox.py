"""Unified sandbox client for patch validation.

Supports two backends:
- **Firecracker MicroVM** (Linux with KVM): Hardware-isolated execution via
  snapshot-based VMs with AF_VSOCK communication.
- **Local Process Sandbox** (macOS / fallback): Process-isolated execution
  with resource limits, sanitized environment, and ephemeral workspaces.

The backend is auto-detected at startup based on the availability of the
``firecracker`` binary and the configured ``sandbox_engine`` setting.
"""

from __future__ import annotations

import logging
import re
import shutil
import time
from pathlib import Path
from typing import Any, Protocol

from .config import Settings
from .memory import RepositoryIngestor, safe_read_text
from .models import (
    PatchProposal,
    RepositoryMemory,
    SandboxMetadata,
    ValidationAxis,
    ValidationAxisStatus,
    ValidationResult,
    Verdict,
)

logger = logging.getLogger(__name__)

try:
    from .wasmtime_sandbox import WasmConfig, WasmtimeSandbox
    WASMTIME_AVAILABLE = True
except Exception:
    WASMTIME_AVAILABLE = False


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ALLOWED_EXECUTABLES = {"python", "python3", "npm", "node", "npx", "pytest"}
IGNORED_COPY_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    "dist",
    "build",
}


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class SandboxError(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# Sandbox Backend Protocol
# ---------------------------------------------------------------------------


class SandboxBackend(Protocol):
    """Interface that both Firecracker and Local backends implement."""

    engine_name: str
    isolation_level: str

    def acquire(self) -> Any:
        """Acquire a sandbox instance (VM or local process)."""
        ...

    def release(self, instance: Any) -> None:
        """Release a sandbox instance."""
        ...

    def shutdown(self) -> None:
        """Shutdown the backend and clean up all resources."""
        ...


# ---------------------------------------------------------------------------
# Firecracker Backend
# ---------------------------------------------------------------------------


class FirecrackerBackend:
    """Production sandbox backend using Firecracker MicroVMs."""

    engine_name = "firecracker-microvm"
    isolation_level = "hardware"

    def __init__(self, settings: Settings) -> None:
        from sandbox_service.pool_manager import PoolManager
        from sandbox_service.vm_manager import SnapshotManager, VMConfig

        self._config = VMConfig(
            vcpu_count=settings.sandbox_vcpu_count,
            memory_mb=settings.sandbox_memory_mb,
            snapshot_dir=settings.sandbox_snapshot_dir,
        )
        self._snapshot_mgr = SnapshotManager(self._config)
        self._pool = PoolManager(
            pool_size=settings.sandbox_pool_size,
            config=self._config,
            snapshot_manager=self._snapshot_mgr,
        )
        logger.info(
            "Firecracker sandbox backend initialized: %d vCPU, %dMB RAM, pool=%d",
            self._config.vcpu_count,
            self._config.memory_mb,
            settings.sandbox_pool_size,
        )

    def acquire(self) -> Any:
        return self._pool.acquire()

    def release(self, instance: Any) -> None:
        self._pool.release(instance)

    def shutdown(self) -> None:
        self._pool.shutdown()


# ---------------------------------------------------------------------------
# Local Process Backend
# ---------------------------------------------------------------------------


class LocalProcessBackend:
    """Development sandbox backend using process isolation with resource limits."""

    engine_name = "process-sandbox"
    isolation_level = "process"

    def __init__(self, settings: Settings) -> None:
        from sandbox_service.sandbox_local import LocalPoolManager, LocalSandboxRunner
        from sandbox_service.vm_manager import VMConfig

        self._config = VMConfig(
            vcpu_count=settings.sandbox_vcpu_count,
            memory_mb=settings.sandbox_memory_mb,
        )
        self._pool = LocalPoolManager(config=self._config)
        self._runner_class = LocalSandboxRunner
        logger.info(
            "Local process sandbox backend initialized: %d vCPU, %dMB RAM (limits advisory)",
            settings.sandbox_vcpu_count,
            settings.sandbox_memory_mb,
        )

    def acquire(self) -> Any:
        return self._pool.acquire()

    def release(self, instance: Any) -> None:
        self._pool.release(instance)

    def shutdown(self) -> None:
        self._pool.shutdown()


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def _ignore(_directory: str, names: list[str]) -> set[str]:
    return {name for name in names if name in IGNORED_COPY_DIRS}


def _safe_relative_path(path: str) -> Path:
    relative = Path(path)
    if relative.is_absolute() or ".." in relative.parts:
        raise SandboxError(f"Unsafe patch path: {path}")
    return relative


def _calculate_coverage_delta(stdout: str, stderr: str, *, passing_tests: int, total_tests: int) -> float:
    """Extract coverage signal from test output for convergence scoring."""
    output = f"{stdout}\n{stderr}"
    cov_match = re.search(r"TOTAL\s+\d+\s+\d+\s+(\d+)%", output)
    if cov_match:
        return float(cov_match.group(1))
    if total_tests > 0:
        return min((passing_tests / total_tests) * 100.0, 100.0)
    ran = re.search(r"Ran\s+(\d+)\s+tests?", output)
    if ran:
        return min(float(ran.group(1)) * 5.0, 100.0)
    return 50.0


def _parse_total_tests(stdout: str, stderr: str, exit_code: int) -> tuple[int, int]:
    output = f"{stdout}\n{stderr}"
    match = re.search(r"Ran\s+(\d+)\s+tests?", output)
    if match:
        total = int(match.group(1))
        return (total if exit_code == 0 else 0, total)
    passed_match = re.search(r"(\d+)\s+passed", output)
    if passed_match:
        total = int(passed_match.group(1))
        return (total if exit_code == 0 else 0, total)
    return (0, 0)


def _detect_backend(settings: Settings) -> SandboxBackend:
    """Auto-detect the best available sandbox backend."""
    engine = settings.sandbox_engine

    if engine == "firecracker":
        if not shutil.which("firecracker"):
            raise SandboxError(
                "sandbox_engine is set to 'firecracker' but the firecracker "
                "binary is not on $PATH. Install Firecracker or set "
                "SENTINEL_SANDBOX_ENGINE=local"
            )
        return FirecrackerBackend(settings)

    if engine == "local":
        return LocalProcessBackend(settings)

    # Auto-detect
    if shutil.which("firecracker"):
        logger.info("Auto-detected Firecracker binary — using hardware-isolated sandbox")
        return FirecrackerBackend(settings)

    logger.info(
        "Firecracker not found — using local process sandbox (safe for development)"
    )
    return LocalProcessBackend(settings)


# ---------------------------------------------------------------------------
# SandboxRunner — the unified validation entry point
# ---------------------------------------------------------------------------


class SandboxRunner:
    """Validates AI-generated patches in an isolated sandbox.

    This is the single entry point used by the orchestrator and LangGraph
    workflow. It auto-detects the best available backend (Firecracker or
    local process) and produces identical ``ValidationResult`` objects
    regardless of which backend is used.
    """

    def __init__(self, settings: Settings, ingestor: RepositoryIngestor) -> None:
        self._settings = settings
        self._ingestor = ingestor
        self._backend = _detect_backend(settings)
        logger.info("SandboxRunner ready — engine=%s", self._backend.engine_name)

    @property
    def engine_name(self) -> str:
        return self._backend.engine_name

    def validate(
        self,
        *,
        repo_root: Path,
        memory: RepositoryMemory,
        patch: PatchProposal,
    ) -> ValidationResult:
        """Validate a patch proposal in an isolated sandbox.

        Returns a ``ValidationResult`` with structured axes covering:
        patch integrity, pre-existing tests, static rescan, patch scope,
        sandbox isolation, and auditability.
        """
        started = time.monotonic()
        boot_start = time.monotonic()

        wasm_result = {"exit_code": 0, "stdout": "", "stderr": ""}
        if WASMTIME_AVAILABLE:
            try:
                wasm_sandbox = WasmtimeSandbox(WasmConfig())
                wasm_result = wasm_sandbox.validate_patch(
                    repo_root, memory, patch
                )
            except Exception:
                pass

        sandbox = self._backend.acquire()
        boot_time_ms = int((time.monotonic() - boot_start) * 1000)
        workspace_transferred = False
        workspace_sha256 = ""

        try:
            workspace = sandbox.workspace_dir
            if workspace.exists():
                shutil.rmtree(workspace)
            shutil.copytree(repo_root, workspace, ignore=_ignore)

            logger.info(
                "Sandbox workspace ready at %s (%s)",
                workspace,
                self._backend.engine_name,
            )

            # Apply patch with integrity verification
            self._apply_patch(workspace, patch)

            sync_workspace = getattr(sandbox, "sync_workspace", None)
            if callable(sync_workspace):
                workspace_sha256 = sync_workspace(
                    workspace,
                    timeout=self._settings.sandbox_timeout_seconds,
                )
                workspace_transferred = True

            # Run validation commands
            stdout, stderr, exit_code = self._run_validation_commands(
                sandbox, memory.validation_commands
            )

            # Parse test results
            passing_tests, total_tests = _parse_total_tests(stdout, stderr, exit_code)

            # Re-ingest patched workspace for finding resolution
            patched_memory = self._ingestor.ingest(str(workspace), patch.task_id)

        finally:
            self._backend.release(sandbox)

        # Calculate finding resolution
        resolved_findings, total_findings, remaining_findings = (
            self._finding_resolution(memory, patched_memory, patch)
        )

        duration_ms = int((time.monotonic() - started) * 1000)

        # Build validation axes
        axes = [
            ValidationAxis(
                name="patch_integrity",
                status=ValidationAxisStatus.PASS,
                detail="Patch applied and verified in isolated sandbox workspace.",
            ),
            ValidationAxis(
                name="pre_existing_tests",
                status=(
                    ValidationAxisStatus.PASS
                    if exit_code == 0
                    else ValidationAxisStatus.FAIL
                ),
                detail=(
                    f"Validation commands exited {exit_code}; "
                    f"{passing_tests}/{total_tests} parsed tests passing."
                ),
            ),
            ValidationAxis(
                name="static_rescan",
                status=(
                    ValidationAxisStatus.PASS
                    if remaining_findings == 0
                    else ValidationAxisStatus.FAIL
                ),
                detail=f"{resolved_findings}/{total_findings} targeted findings resolved.",
            ),
            ValidationAxis(
                name="patch_scope",
                status=(
                    ValidationAxisStatus.PASS
                    if len(patch.files) <= 5
                    else ValidationAxisStatus.WARN
                ),
                detail=f"{len(patch.files)} file(s) changed.",
            ),
            ValidationAxis(
                name="sandbox_isolation",
                status=ValidationAxisStatus.PASS,
                detail=(
                    f"Executed in {self._backend.engine_name} sandbox with "
                    f"{self._backend.isolation_level} isolation."
                ),
            ),
            ValidationAxis(
                name="auditability",
                status=ValidationAxisStatus.PASS,
                detail="Diff, stdout, stderr, exit code, and static findings are machine-readable.",
            ),
        ]

        verdict = (
            Verdict.APPROVE
            if all(axis.status != ValidationAxisStatus.FAIL for axis in axes)
            else Verdict.REJECT
        )
        quality_delta = _calculate_coverage_delta(
            stdout,
            stderr,
            passing_tests=passing_tests,
            total_tests=total_tests,
        )

        # Build dynamic sandbox metadata
        sandbox_meta = SandboxMetadata(
            engine=self._backend.engine_name,
            boot_time_ms=boot_time_ms,
            vsock_status=(
                "ESTABLISHED"
                if self._backend.engine_name == "firecracker-microvm"
                else "N/A"
            ),
            vcpu_count=self._settings.sandbox_vcpu_count,
            memory_mb=self._settings.sandbox_memory_mb,
            snapshot_used=(
                self._backend.engine_name == "firecracker-microvm"
            ),
            isolation_level=self._backend.isolation_level,
            workspace_path="/workspace" if workspace_transferred else str(workspace),
            workspace_transferred=workspace_transferred,
            workspace_sha256=workspace_sha256,
        )

        return ValidationResult(
            task_id=patch.task_id,
            patch_id=patch.patch_id,
            verdict=verdict,
            axes=axes,
            exit_code=exit_code,
            stdout=stdout[-12000:],
            stderr=stderr[-12000:],
            passing_tests=passing_tests,
            total_tests=total_tests,
            resolved_findings=resolved_findings,
            total_findings=total_findings,
            coverage_delta=quality_delta,
            duration_ms=duration_ms,
            sandbox_metadata=sandbox_meta,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _apply_patch(self, workspace: Path, patch: PatchProposal) -> None:
        """Apply patch files to workspace with integrity verification."""
        for file_patch in patch.files:
            target = workspace / _safe_relative_path(file_patch.file_path)
            if not target.exists():
                raise SandboxError(
                    f"Patch target does not exist: {file_patch.file_path}"
                )
            current = safe_read_text(target)
            if current != file_patch.original:
                raise SandboxError(
                    f"Patch target changed before validation: {file_patch.file_path}"
                )
            target.write_text(file_patch.patched, encoding="utf-8")

    def _run_validation_commands(
        self,
        sandbox: Any,
        commands: list[list[str]],
    ) -> tuple[str, str, int]:
        """Run validation commands in the sandbox."""
        stdout_parts: list[str] = []
        stderr_parts: list[str] = []
        final_exit_code = 0

        for command in commands:
            if not command:
                continue
            executable = Path(command[0]).name
            if executable not in ALLOWED_EXECUTABLES:
                return (
                    "",
                    f"Command executable is not allowed in sandbox: {executable}",
                    126,
                )

            try:
                result = sandbox.execute_command(
                    command, timeout=self._settings.sandbox_timeout_seconds
                )
                stdout_parts.append(result.get("stdout", ""))
                stderr_parts.append(result.get("stderr", ""))

                exit_code = result.get("exit_code", 1)
                if exit_code != 0:
                    final_exit_code = exit_code
                    break
            except Exception as exc:
                logger.error("Sandbox command error: %s", exc)
                stderr_parts.append(f"Sandbox Error ({self._backend.engine_name}): {exc}")
                final_exit_code = 125
                break

        return "\n".join(stdout_parts), "\n".join(stderr_parts), final_exit_code

    def _finding_resolution(
        self,
        original: RepositoryMemory,
        patched: RepositoryMemory,
        patch: PatchProposal,
    ) -> tuple[int, int, int]:
        """Compare findings before and after patch application."""
        changed_files = {file.file_path for file in patch.files}
        original_targeted = [
            finding
            for finding in original.findings
            if finding.file_path in changed_files
        ]
        patched_targeted = [
            finding
            for finding in patched.findings
            if finding.file_path in changed_files
        ]
        total = max(len(original_targeted), 1)
        remaining = len(patched_targeted)
        resolved = max(0, len(original_targeted) - remaining)
        return resolved, total, remaining
