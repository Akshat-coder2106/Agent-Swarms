"""Sandbox service module for Firecracker MicroVM orchestration.

Provides two execution backends:
- **Firecracker MicroVM** (Linux/KVM): Hardware-isolated execution with
  memory snapshotting, AF_VSOCK communication, and Copy-on-Write forking.
- **Local Process Sandbox** (macOS/fallback): Process-isolated subprocess
  execution with resource limits and sanitized environment.
"""

from .pool_manager import PoolManager
from .sandbox_local import LocalPoolManager, LocalSandboxRunner
from .vm_manager import SnapshotFiles, SnapshotManager, VMConfig, VMManager

__all__ = [
    "VMConfig",
    "VMManager",
    "SnapshotFiles",
    "SnapshotManager",
    "PoolManager",
    "LocalSandboxRunner",
    "LocalPoolManager",
]
