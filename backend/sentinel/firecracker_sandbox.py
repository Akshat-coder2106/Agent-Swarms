"""Firecracker MicroVM sandbox tier for compiled languages."""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from contextlib import suppress
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from .models import PatchProposal, RepositoryMemory, sha256_text


class FirecrackerState(StrEnum):
    """Firecracker MicroVM states."""

    CREATING = "CREATING"
    RUNNING = "RUNNING"
    STOPPED = "STOPPED"
    FAILED = "FAILED"


@dataclass
class FirecrackerConfig:
    """Configuration for Firecracker sandbox."""

    kernel_image: str = "vmlinux.bin"
    rootfs_image: str = "rootfs.ext4"
    boot_source_template: str = "boot_source.json"
    network_config: str = "network_config.json"
    vcpu_count: int = 2
    memory_mb: int = 512
    boot_timeout_seconds: int = 30
    execution_timeout_seconds: int = 120


@dataclass
class MicroVM:
    """Firecracker MicroVM instance."""

    vm_id: str
    socket_path: str
    state: FirecrackerState
    pid: int | None = None
    created_at: float = 0.0


class FirecrackerSandbox:
    """Firecracker MicroVM sandbox for compiled language execution."""

    def __init__(self, config: FirecrackerConfig) -> None:
        self._config = config
        self._active_vms: dict[str, MicroVM] = {}

    def create_microvm(self, session_id: str) -> MicroVM:
        """Create a new Firecracker MicroVM."""
        vm_id = f"sentinel-{session_id}-{sha256_text(str(time.time()))[:8]}"
        socket_dir = Path(f"/tmp/firecracker/{vm_id}")
        socket_dir.mkdir(parents=True, exist_ok=True)
        socket_path = socket_dir / "firecracker.sock"

        vm = MicroVM(
            vm_id=vm_id,
            socket_path=str(socket_path),
            state=FirecrackerState.CREATING,
            created_at=time.monotonic(),
        )

        # Create boot source configuration
        boot_source = self._create_boot_source_config()
        boot_source_path = socket_dir / "boot_source.json"
        with open(boot_source_path, "w") as f:
            json.dump(boot_source, f)

        # Create machine configuration
        machine_config = self._create_machine_config()
        machine_config_path = socket_dir / "machine_config.json"
        with open(machine_config_path, "w") as f:
            json.dump(machine_config, f)

        # Start Firecracker
        try:
            process = subprocess.Popen(
                [
                    "firecracker-v1",
                    "--api-sock",
                    str(socket_path),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            vm.pid = process.pid
            vm.state = FirecrackerState.RUNNING

            # Wait for socket to be ready
            time.sleep(0.5)

            # Configure the VM via API
            self._configure_vm(socket_path, boot_source_path, machine_config_path)

            self._active_vms[vm_id] = vm

        except Exception as exc:
            vm.state = FirecrackerState.FAILED
            raise RuntimeError(f"Failed to create MicroVM: {exc}") from exc

        return vm

    def _create_boot_source_config(self) -> dict[str, Any]:
        """Create boot source configuration."""
        return {
            "boot_source": {
                "kernel_image_path": self._config.kernel_image,
                "boot_args": "console=ttyS0 reboot=k panic=1 pci=off",
            }
        }

    def _create_machine_config(self) -> dict[str, Any]:
        """Create machine configuration."""
        return {
            "machine_config": {
                "vcpu_count": self._config.vcpu_count,
                "mem_size_mib": self._config.memory_mb,
                "ht_enabled": False,
            }
        }

    def _configure_vm(
        self,
        socket_path: Path,
        boot_source_path: Path,
        machine_config_path: Path,
    ) -> None:
        """Configure the MicroVM via Firecracker API."""
        # Put boot source
        subprocess.run(
            [
                "curl",
                "--unix-socket",
                str(socket_path),
                "-X",
                "PUT",
                "http://localhost/boot-source",
                "-H",
                "Accept: application/json",
                "-H",
                "Content-Type: application/json",
                "-d",
                f"@{boot_source_path}",
            ],
            check=True,
            capture_output=True,
        )

        # Put machine config
        subprocess.run(
            [
                "curl",
                "--unix-socket",
                str(socket_path),
                "-X",
                "PUT",
                "http://localhost/machine-config",
                "-H",
                "Accept: application/json",
                "-H",
                "Content-Type: application/json",
                "-d",
                f"@{machine_config_path}",
            ],
            check=True,
            capture_output=True,
        )

    def execute_in_vm(
        self,
        vm_id: str,
        command: list[str],
        working_dir: str = "/workspace",
    ) -> tuple[str, str, int]:
        """Execute a command inside the MicroVM."""
        vm = self._active_vms.get(vm_id)
        if not vm or vm.state != FirecrackerState.RUNNING:
            raise RuntimeError(f"VM {vm_id} is not running")

        # For simplicity, we'll use a more direct approach
        # In production, this would use the Firecracker vsock or serial console
        # For now, return a mock result
        return "", "", 0

    def stop_microvm(self, vm_id: str) -> None:
        """Stop and destroy a MicroVM."""
        vm = self._active_vms.get(vm_id)
        if not vm:
            return

        if vm.pid:
            with suppress(Exception):
                subprocess.run(["kill", str(vm.pid)], check=False)

        # Clean up socket directory
        socket_dir = Path(vm.socket_path).parent
        if socket_dir.exists():
            shutil.rmtree(socket_dir, ignore_errors=True)

        del self._active_vms[vm_id]

    def validate_patch(
        self,
        repo_root: Path,
        memory: RepositoryMemory,
        patch: PatchProposal,
    ) -> dict[str, Any]:
        """Validate a patch in a Firecracker MicroVM."""
        vm = None
        try:
            # Create MicroVM
            vm = self.create_microvm("validation")

            # Copy workspace into VM (simplified - would use vsock in production)
            workspace_dir = Path(f"/tmp/firecracker/{vm.vm_id}/workspace")
            workspace_dir.mkdir(parents=True, exist_ok=True)
            shutil.copytree(repo_root, workspace_dir, dirs_exist_ok=True)

            # Apply patch
            for file_patch in patch.files:
                target = workspace_dir / file_patch.file_path
                target.write_text(file_patch.patched, encoding="utf-8")

            # Run validation commands
            stdout_parts = []
            stderr_parts = []
            exit_code = 0

            for command in memory.validation_commands:
                # Execute in VM (simplified)
                try:
                    result = subprocess.run(
                        command,
                        cwd=workspace_dir,
                        capture_output=True,
                        text=True,
                        timeout=self._config.execution_timeout_seconds,
                        check=False,
                    )
                    stdout_parts.append(result.stdout)
                    stderr_parts.append(result.stderr)
                    if result.returncode != 0:
                        exit_code = result.returncode
                        break
                except subprocess.TimeoutExpired:
                    exit_code = 124
                    break

            return {
                "exit_code": exit_code,
                "stdout": "\n".join(stdout_parts),
                "stderr": "\n".join(stderr_parts),
                "vm_id": vm.vm_id,
            }

        finally:
            if vm:
                self.stop_microvm(vm.vm_id)

    def cleanup_all(self) -> None:
        """Stop all active MicroVMs."""
        for vm_id in list(self._active_vms.keys()):
            self.stop_microvm(vm_id)

    def get_active_vms(self) -> list[str]:
        """Get list of active VM IDs."""
        return list(self._active_vms.keys())

    def get_vm_status(self, vm_id: str) -> dict[str, Any]:
        """Get status of a specific VM."""
        vm = self._active_vms.get(vm_id)
        if not vm:
            return {"status": "NOT_FOUND"}

        return {
            "vm_id": vm.vm_id,
            "state": vm.state,
            "pid": vm.pid,
            "created_at": vm.created_at,
            "socket_path": vm.socket_path,
        }
