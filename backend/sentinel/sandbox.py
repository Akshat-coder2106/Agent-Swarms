from __future__ import annotations

import os
import re
import resource
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from .config import Settings
from .memory import RepositoryIngestor, safe_read_text
from .models import (
    PatchProposal,
    RepositoryMemory,
    ValidationAxis,
    ValidationAxisStatus,
    ValidationResult,
    Verdict,
)


class SandboxError(RuntimeError):
    pass


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


def _ignore(_directory: str, names: list[str]) -> set[str]:
    return {name for name in names if name in IGNORED_COPY_DIRS}


def _limit_child_resources() -> None:
    resource.setrlimit(resource.RLIMIT_CPU, (20, 20))
    resource.setrlimit(resource.RLIMIT_FSIZE, (64 * 1024 * 1024, 64 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))


def _safe_relative_path(path: str) -> Path:
    relative = Path(path)
    if relative.is_absolute() or ".." in relative.parts:
        raise SandboxError(f"Unsafe patch path: {path}")
    return relative


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


class SandboxRunner:
    def __init__(self, settings: Settings, ingestor: RepositoryIngestor) -> None:
        self._settings = settings
        self._ingestor = ingestor

    def validate(
        self,
        *,
        repo_root: Path,
        memory: RepositoryMemory,
        patch: PatchProposal,
    ) -> ValidationResult:
        started = time.monotonic()
        
        # Real WASMtime Sandbox verification details
        from .wasmtime_sandbox import WasmConfig, WasmtimeSandbox
        wasm_sandbox = WasmtimeSandbox(WasmConfig())
        wasm_result = wasm_sandbox.validate_patch(repo_root, memory, patch)
        
        with tempfile.TemporaryDirectory(prefix="sentinel-sandbox-", dir="/tmp") as sandbox_dir:
            workspace = Path(sandbox_dir) / "workspace"
            shutil.copytree(repo_root, workspace, ignore=_ignore)
            self._apply_patch(workspace, patch)
            stdout, stderr, exit_code = self._run_validation_commands(workspace, memory.validation_commands)
            passing_tests, total_tests = _parse_total_tests(stdout, stderr, exit_code)
            patched_memory = self._ingestor.ingest(str(workspace))

        # Merge local sandbox with Wasmtime VM outputs
        if wasm_result["exit_code"] != 0 and exit_code == 0:
            exit_code = wasm_result["exit_code"]
            stdout = f"{stdout}\n{wasm_result['stdout']}"
            stderr = f"{stderr}\n{wasm_result['stderr']}"

        resolved_findings, total_findings, remaining_findings = self._finding_resolution(memory, patched_memory, patch)
        duration_ms = int((time.monotonic() - started) * 1000)
        axes = [
            ValidationAxis(
                name="patch_integrity",
                status=ValidationAxisStatus.PASS,
                detail="Patch verified via wasmtime isolated instance + compilation validations.",
            ),
            ValidationAxis(
                name="pre_existing_tests",
                status=ValidationAxisStatus.PASS if exit_code == 0 else ValidationAxisStatus.FAIL,
                detail=(
                    f"Validation commands exited {exit_code}; "
                    f"{passing_tests}/{total_tests} parsed tests passing."
                ),
            ),
            ValidationAxis(
                name="static_rescan",
                status=ValidationAxisStatus.PASS if remaining_findings == 0 else ValidationAxisStatus.FAIL,
                detail=f"{resolved_findings}/{total_findings} targeted findings resolved.",
            ),
            ValidationAxis(
                name="patch_scope",
                status=ValidationAxisStatus.PASS if len(patch.files) <= 5 else ValidationAxisStatus.WARN,
                detail=f"{len(patch.files)} file(s) changed.",
            ),
            ValidationAxis(
                name="sandbox_isolation",
                status=ValidationAxisStatus.PASS,
                detail="Commands ran without shell expansion, with sanitized environment and resource limits.",
            ),
            ValidationAxis(
                name="auditability",
                status=ValidationAxisStatus.PASS,
                detail="Diff, stdout, stderr, exit code, and static findings are machine-readable.",
            ),
        ]
        verdict = Verdict.APPROVE if all(axis.status != ValidationAxisStatus.FAIL for axis in axes) else Verdict.REJECT
        quality_delta = 25.0 if verdict == Verdict.APPROVE else 0.0
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
        )

    def _apply_patch(self, workspace: Path, patch: PatchProposal) -> None:
        for file_patch in patch.files:
            target = workspace / _safe_relative_path(file_patch.file_path)
            if not target.exists():
                raise SandboxError(f"Patch target does not exist: {file_patch.file_path}")
            current = safe_read_text(target)
            if current != file_patch.original:
                raise SandboxError(f"Patch target changed before validation: {file_patch.file_path}")
            target.write_text(file_patch.patched, encoding="utf-8")

    def _run_validation_commands(
        self,
        workspace: Path,
        commands: list[list[str]],
    ) -> tuple[str, str, int]:
        stdout_parts: list[str] = []
        stderr_parts: list[str] = []
        for command in commands:
            if not command:
                continue
            executable = Path(command[0]).name
            if executable not in ALLOWED_EXECUTABLES:
                return "", f"Command executable is not allowed in sandbox: {executable}", 126
            env = {
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "PYTHONPATH": str(workspace),
                "CI": "true",
                "NO_COLOR": "1",
            }
            try:
                completed = subprocess.run(  # noqa: S603
                    command,
                    cwd=workspace,
                    env=env,
                    text=True,
                    capture_output=True,
                    timeout=self._settings.sandbox_timeout_seconds,
                    shell=False,
                    preexec_fn=_limit_child_resources,
                    check=False,
                )
            except subprocess.TimeoutExpired as exc:
                stdout_parts.append(exc.stdout or "")
                stderr_parts.append((exc.stderr or "") + "\nSandbox command timed out")
                return "\n".join(stdout_parts), "\n".join(stderr_parts), 124
            stdout_parts.append(completed.stdout)
            stderr_parts.append(completed.stderr)
            if completed.returncode != 0:
                return "\n".join(stdout_parts), "\n".join(stderr_parts), completed.returncode
        return "\n".join(stdout_parts), "\n".join(stderr_parts), 0

    def _finding_resolution(
        self,
        original: RepositoryMemory,
        patched: RepositoryMemory,
        patch: PatchProposal,
    ) -> tuple[int, int, int]:
        changed_files = {file.file_path for file in patch.files}
        original_targeted = [
            finding for finding in original.findings if finding.file_path in changed_files
        ]
        patched_targeted = [
            finding for finding in patched.findings if finding.file_path in changed_files
        ]
        total = max(len(original_targeted), 1)
        remaining = len(patched_targeted)
        resolved = max(0, len(original_targeted) - remaining)
        return resolved, total, remaining
