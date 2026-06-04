"""Local Process Sandbox — macOS / fallback execution backend.

Provides the same interface as ``VMManager`` but executes commands in
a process-isolated subprocess on the host machine. Used when:

- Firecracker is not available (macOS, Windows, non-KVM Linux)
- ``SENTINEL_SANDBOX_ENGINE`` is set to ``"local"``
- Auto-detection does not find the ``firecracker`` binary

Security measures:
- Resource limits via ``resource.setrlimit`` (CPU time, file size, open files)
- Sanitized environment (only PATH, HOME, LANG, PYTHONPATH)
- Ephemeral workspace (``tempfile.mkdtemp``, destroyed after use)
- No shell expansion (``shell=False``)
"""

from __future__ import annotations

import logging
import os
import platform
import shutil

try:
    import resource as _resource
except ImportError:  # Windows has no resource module
    _resource = None
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from .vm_manager import VMConfig

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Resource limits (applied via preexec_fn)
# ---------------------------------------------------------------------------

_RLIMIT_CPU_SECONDS = 20
_RLIMIT_FSIZE_BYTES = 64 * 1024 * 1024  # 64 MB
_RLIMIT_NOFILE = 128


def _apply_resource_limits() -> None:
    """Set resource limits for the child process (Unix only).

    This runs as ``preexec_fn`` in ``subprocess.run`` and applies:
    - CPU time limit: 20 seconds
    - Maximum file size: 64 MB
    - Maximum open file descriptors: 128

    On Windows the ``resource`` module is unavailable; subprocess timeout
    and ephemeral workspaces still enforce isolation.
    """
    if _resource is None:
        return
    try:
        _resource.setrlimit(_resource.RLIMIT_CPU, (_RLIMIT_CPU_SECONDS, _RLIMIT_CPU_SECONDS))
        _resource.setrlimit(_resource.RLIMIT_FSIZE, (_RLIMIT_FSIZE_BYTES, _RLIMIT_FSIZE_BYTES))
        _resource.setrlimit(_resource.RLIMIT_NOFILE, (_RLIMIT_NOFILE, _RLIMIT_NOFILE))
    except (ValueError, OSError) as exc:
        logger.debug("Could not set all resource limits: %s", exc)


def _sanitized_env() -> dict[str, str]:
    """Build a minimal, sanitized environment for subprocess execution."""
    env: dict[str, str] = {}

    # Only pass through safe, essential variables
    for key in ("PATH", "HOME", "LANG", "PYTHONPATH", "VIRTUAL_ENV"):
        value = os.environ.get(key)
        if value:
            env[key] = value

    # Ensure a sensible PATH if not inherited
    if "PATH" not in env:
        env["PATH"] = "/usr/local/bin:/usr/bin:/bin"

    return env


# ---------------------------------------------------------------------------
# Local Sandbox Runner
# ---------------------------------------------------------------------------


class LocalSandboxRunner:
    """Process-isolated sandbox for local development.

    Implements the same interface as ``VMManager`` so it can be used
    as a drop-in replacement by ``SandboxRunner``.
    """

    def __init__(self, config: VMConfig | None = None) -> None:
        self.config = config or VMConfig()
        self._workspace: Path | None = None
        self.boot_time_ms: int = 0
        self.vm_id = f"local-{os.getpid()}-{id(self)}"

    @property
    def workspace_dir(self) -> Path:
        """Path to the ephemeral workspace for this sandbox instance."""
        if self._workspace is None:
            self._workspace = Path(
                tempfile.mkdtemp(prefix="sentinel_sandbox_")
            )
        return self._workspace

    def initialize(self) -> None:
        """Create the ephemeral workspace directory."""
        start = time.monotonic()
        _ = self.workspace_dir  # Trigger creation
        self.boot_time_ms = int((time.monotonic() - start) * 1000)
        logger.debug(
            "Local sandbox initialized: workspace=%s",
            self._workspace,
        )

    def execute_command(
        self,
        command: list[str],
        timeout: int = 120,
    ) -> dict[str, Any]:
        """Execute a command in the local sandbox with resource limits.

        Uses ``subprocess.run`` with:
        - ``shell=False`` (no shell expansion)
        - ``preexec_fn`` for resource limits (CPU, file size, open files)
        - Sanitized environment
        - Ephemeral workspace as ``cwd``

        Returns ``{exit_code, stdout, stderr}`` matching the VMManager
        interface.
        """
        workspace = self.workspace_dir

        # Ensure workspace exists
        workspace.mkdir(parents=True, exist_ok=True)

        # Determine preexec_fn based on platform
        # resource.setrlimit is not available on Windows
        preexec = _apply_resource_limits if platform.system() != "Windows" else None

        try:
            result = subprocess.run(
                command,
                cwd=str(workspace),
                capture_output=True,
                text=True,
                timeout=timeout,
                env=_sanitized_env(),
                preexec_fn=preexec,
            )
            return {
                "exit_code": result.returncode,
                "stdout": result.stdout[-12000:],
                "stderr": result.stderr[-12000:],
            }
        except subprocess.TimeoutExpired:
            return {
                "exit_code": 124,
                "stdout": "",
                "stderr": f"Command timed out after {timeout}s",
            }
        except FileNotFoundError as exc:
            return {
                "exit_code": 127,
                "stdout": "",
                "stderr": f"Command not found: {exc}",
            }
        except OSError as exc:
            return {
                "exit_code": 126,
                "stdout": "",
                "stderr": f"OS error executing command: {exc}",
            }

    def destroy(self) -> None:
        """Remove the ephemeral workspace directory."""
        if self._workspace and self._workspace.exists():
            shutil.rmtree(self._workspace, ignore_errors=True)
            logger.debug("Local sandbox destroyed: %s", self._workspace)
            self._workspace = None


# ---------------------------------------------------------------------------
# Local Pool Manager
# ---------------------------------------------------------------------------


class LocalPoolManager:
    """Pool manager for local process sandboxes.

    Unlike the Firecracker ``PoolManager``, this does not pre-boot VMs.
    Each ``acquire()`` creates a fresh ``LocalSandboxRunner`` on demand
    since there is no VM boot latency to amortize.
    """

    def __init__(self, config: VMConfig | None = None) -> None:
        self.config = config or VMConfig()
        logger.info(
            "Local pool manager initialized (process sandbox, no VM overhead)"
        )

    def acquire(self) -> LocalSandboxRunner:
        """Create and return a new local sandbox runner."""
        runner = LocalSandboxRunner(config=self.config)
        runner.initialize()
        return runner

    def release(self, runner: LocalSandboxRunner) -> None:
        """Destroy the sandbox runner and clean up its workspace."""
        runner.destroy()

    def shutdown(self) -> None:
        """No-op — local sandboxes are ephemeral and self-cleaning."""
        logger.debug("Local pool manager shutdown (no-op)")
