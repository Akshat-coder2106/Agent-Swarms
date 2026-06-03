"""Firecracker MicroVM Manager with Snapshot-Based Lifecycle.

Manages the full lifecycle of Firecracker MicroVMs including:
- Fresh boot with kernel + rootfs configuration
- Golden image snapshotting for sub-100ms cold starts
- Copy-on-Write fork resumption from snapshots
- AF_VSOCK communication with the guest agent
- Strict resource isolation (vCPU, RAM, no network)
"""

from __future__ import annotations

import json
import logging
import shutil
import socket
import subprocess
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass
class VMConfig:
    """Configuration for a Firecracker MicroVM instance."""

    kernel_image: str = "vmlinux.bin"
    rootfs_image: str = "rootfs.ext4"
    vcpu_count: int = 1
    memory_mb: int = 256
    snapshot_dir: str = "/tmp/sentinel_snapshots"
    guest_cid: int = 3
    boot_timeout_ms: int = 5000
    base_dir: str = "/tmp/firecracker"


@dataclass
class SnapshotFiles:
    """Paths to a Firecracker memory snapshot on disk."""

    mem_file: Path
    snapshot_file: Path
    rootfs_overlay: Path

    @property
    def exists(self) -> bool:
        return self.mem_file.exists() and self.snapshot_file.exists()


# ---------------------------------------------------------------------------
# Snapshot Manager
# ---------------------------------------------------------------------------


class SnapshotManager:
    """Manages golden image snapshots for fast VM forking.

    The workflow is:
    1. Boot a VM with a clean rootfs (``create_golden_snapshot``)
    2. Wait for the guest agent to become responsive
    3. Pause the VM and snapshot memory + disk state
    4. For each validation task, fork from the snapshot (``fork_from_snapshot``)
       using a CoW overlay on the rootfs
    """

    def __init__(self, config: VMConfig) -> None:
        self._config = config
        self._snapshot_dir = Path(config.snapshot_dir)
        self._snapshot_dir.mkdir(parents=True, exist_ok=True)

    @property
    def golden_snapshot(self) -> SnapshotFiles:
        return SnapshotFiles(
            mem_file=self._snapshot_dir / "golden_mem",
            snapshot_file=self._snapshot_dir / "golden_snapshot",
            rootfs_overlay=self._snapshot_dir / "golden_rootfs.ext4",
        )

    def has_golden_snapshot(self) -> bool:
        """Check whether a valid golden snapshot exists on disk."""
        return self.golden_snapshot.exists

    def create_golden_snapshot(self) -> SnapshotFiles:
        """Boot a fresh VM, wait for guest readiness, then snapshot it.

        Returns the ``SnapshotFiles`` containing paths to the memory file
        and snapshot metadata file.
        """
        snapshot = self.golden_snapshot
        if snapshot.exists:
            logger.info("Golden snapshot already exists at %s", self._snapshot_dir)
            return snapshot

        logger.info("Creating golden snapshot...")
        vm = VMManager(vm_id="golden-snapshot", config=self._config)

        try:
            vm.initialize(from_snapshot=False)

            # Wait for guest agent to respond to a health check
            self._wait_for_guest(vm)

            # Pause the VM before snapshotting
            vm._api_request("PATCH", "/vm", {"state": "Paused"})

            # Create the snapshot
            vm._api_request("PUT", "/snapshot/create", {
                "snapshot_type": "Full",
                "snapshot_path": str(snapshot.snapshot_file),
                "mem_file_path": str(snapshot.mem_file),
            })

            # Copy the rootfs as the base overlay
            shutil.copy2(
                Path(self._config.rootfs_image).resolve(),
                snapshot.rootfs_overlay,
            )

            logger.info("Golden snapshot created at %s", self._snapshot_dir)
            return snapshot

        finally:
            vm.destroy()

    def fork_from_snapshot(
        self,
        snapshot: SnapshotFiles,
        fork_id: str,
    ) -> VMManager:
        """Resume a new VM from a golden snapshot with a CoW rootfs overlay.

        Each fork gets its own writable copy of the rootfs so multiple
        concurrent agents can run independently without data leakage.
        """
        if not snapshot.exists:
            raise RuntimeError("Cannot fork: golden snapshot does not exist")

        vm = VMManager(vm_id=f"fork-{fork_id}", config=self._config)
        vm.base_dir.mkdir(parents=True, exist_ok=True)
        vm._workspace_dir.mkdir(parents=True, exist_ok=True)

        # Create CoW overlay of the rootfs
        fork_rootfs = vm.base_dir / "rootfs.ext4"
        try:
            subprocess.run(
                ["cp", "--reflink=auto", str(snapshot.rootfs_overlay), str(fork_rootfs)],
                check=True,
                capture_output=True,
            )
        except (subprocess.CalledProcessError, FileNotFoundError):
            # Fallback: full copy if reflink not supported (e.g. macOS)
            shutil.copy2(snapshot.rootfs_overlay, fork_rootfs)

        # Start Firecracker process
        vm.process = subprocess.Popen(
            ["firecracker", "--api-sock", str(vm.socket_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # Wait for API socket
        timeout_s = self._config.boot_timeout_ms / 1000
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            if vm.socket_path.exists():
                break
            time.sleep(0.05)
        else:
            vm.destroy()
            raise RuntimeError("Firecracker socket did not appear for fork")

        # Load snapshot
        boot_start = time.monotonic()
        vm._api_request("PUT", "/snapshot/load", {
            "snapshot_path": str(snapshot.snapshot_file),
            "mem_backend": {"backend_type": "File", "backend_path": str(snapshot.mem_file)},
            "enable_diff_snapshots": False,
        })

        # Resume the VM
        vm._api_request("PATCH", "/vm", {"state": "Resumed"})
        vm.boot_time_ms = int((time.monotonic() - boot_start) * 1000)

        logger.info(
            "Forked VM %s from snapshot in %dms",
            vm.vm_id,
            vm.boot_time_ms,
        )
        return vm

    def _wait_for_guest(self, vm: VMManager, timeout_s: float = 10.0) -> None:
        """Poll the guest agent until it responds to a health check."""
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            try:
                result = vm.execute_command(
                    ["echo", "health_check"],
                    timeout=2,
                )
                if result.get("exit_code") == 0:
                    logger.info("Guest agent is responsive")
                    return
            except Exception:
                time.sleep(0.2)

        raise RuntimeError("Guest agent did not become responsive")


# ---------------------------------------------------------------------------
# VM Manager
# ---------------------------------------------------------------------------


class VMManager:
    """Manages an isolated Firecracker MicroVM instance.

    Handles the full VM lifecycle: boot → configure → execute → destroy.
    Communication with the guest happens over AF_VSOCK (via Unix domain
    socket mapped by Firecracker).
    """

    def __init__(self, vm_id: str, config: VMConfig) -> None:
        self.vm_id = vm_id
        self.config = config
        self.base_dir = Path(config.base_dir) / self.vm_id
        self.socket_path = self.base_dir / "firecracker.sock"
        self._workspace_dir = self.base_dir / "workspace"
        self.process: subprocess.Popen | None = None
        self.boot_time_ms: int = 0

    @property
    def workspace_dir(self) -> Path:
        """Path to the ephemeral workspace directory for this VM."""
        return self._workspace_dir

    def initialize(self, from_snapshot: bool = False) -> None:
        """Boot the VM.

        If ``from_snapshot`` is False, performs a full cold boot with
        kernel + rootfs configuration. Snapshot-based boots are handled
        by ``SnapshotManager.fork_from_snapshot`` instead.
        """
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self._workspace_dir.mkdir(parents=True, exist_ok=True)

        boot_start = time.monotonic()

        # Start Firecracker process
        self.process = subprocess.Popen(
            ["firecracker", "--api-sock", str(self.socket_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # Wait for API socket to appear
        timeout_s = self.config.boot_timeout_ms / 1000
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            if self.socket_path.exists():
                break
            time.sleep(0.05)
        else:
            self.destroy()
            raise RuntimeError("Firecracker socket did not appear")

        if not from_snapshot:
            self._configure_vm()
            self._start_instance()

        self.boot_time_ms = int((time.monotonic() - boot_start) * 1000)
        logger.info("VM %s booted in %dms", self.vm_id, self.boot_time_ms)

    def _configure_vm(self) -> None:
        """Configure boot source, rootfs drive, vsock, and machine config."""
        # Boot source
        self._api_request("PUT", "/boot-source", {
            "kernel_image_path": str(Path(self.config.kernel_image).resolve()),
            "boot_args": "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda",
        })

        # Root filesystem drive
        self._api_request("PUT", "/drives/rootfs", {
            "drive_id": "rootfs",
            "path_on_host": str(Path(self.config.rootfs_image).resolve()),
            "is_root_device": True,
            "is_read_only": False,
        })

        # Vsock for guest agent communication
        self._api_request("PUT", "/vsock", {
            "guest_cid": self.config.guest_cid,
            "uds_path": str(self.base_dir / "v.sock"),
        })

        # Machine configuration — strict resource limits
        self._api_request("PUT", "/machine-config", {
            "vcpu_count": self.config.vcpu_count,
            "mem_size_mib": self.config.memory_mb,
            "ht_enabled": False,
        })

    def _start_instance(self) -> None:
        """Issue the InstanceStart action to boot the guest."""
        self._api_request("PUT", "/actions", {"action_type": "InstanceStart"})

    def _api_request(self, method: str, path: str, payload: dict) -> None:
        """Send an HTTP request to the Firecracker API via Unix socket."""
        try:
            import httpx
            transport = httpx.HTTPTransport(uds=str(self.socket_path))
            with httpx.Client(transport=transport, timeout=10) as client:
                resp = client.request(
                    method, f"http://localhost{path}", json=payload,
                )
                resp.raise_for_status()
        except ImportError:
            # Fallback: use curl if httpx is not available
            data = json.dumps(payload)
            subprocess.run(
                [
                    "curl", "--unix-socket", str(self.socket_path),
                    "-X", method,
                    f"http://localhost{path}",
                    "-H", "Content-Type: application/json",
                    "-d", data,
                ],
                check=True,
                capture_output=True,
            )

    def execute_command(
        self,
        command: list[str],
        timeout: int = 120,
    ) -> dict[str, Any]:
        """Execute a command in the guest via the vsock agent.

        Connects to the guest agent over the Firecracker-mapped Unix domain
        socket and sends a JSON-encoded command payload. Returns the
        structured result ``{exit_code, stdout, stderr}``.
        """
        uds_path = self.base_dir / "v.sock_5000"

        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(float(timeout))

        # Retry connection for guest boot
        connected = False
        for _ in range(50):
            try:
                client.connect(str(uds_path))
                connected = True
                break
            except (ConnectionRefusedError, FileNotFoundError, OSError):
                time.sleep(0.1)

        if not connected:
            raise RuntimeError(
                f"Could not connect to guest agent via vsock at {uds_path}"
            )

        try:
            payload = {
                "type": "run_test",
                "payload": {
                    "command": command,
                    "working_dir": "/workspace",
                    "timeout": timeout,
                },
                "timeout": timeout,
                "request_id": uuid.uuid4().hex[:12],
            }
            client.sendall((json.dumps(payload) + "\n").encode("utf-8"))

            data = b""
            while True:
                chunk = client.recv(4096)
                if not chunk:
                    break
                data += chunk
                if b"\n" in chunk:
                    break

            result = json.loads(data.decode("utf-8").strip())

            # Normalize response shape
            if "exit_code" not in result and "payload" in result:
                result = result["payload"]

            return {
                "exit_code": result.get("exit_code", 1),
                "stdout": result.get("stdout", ""),
                "stderr": result.get("stderr", ""),
            }
        finally:
            client.close()

    def destroy(self) -> None:
        """Terminate the Firecracker process and clean up all files."""
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=1)
            self.process = None

        if self.base_dir.exists():
            shutil.rmtree(self.base_dir, ignore_errors=True)

        logger.debug("VM %s destroyed", self.vm_id)
