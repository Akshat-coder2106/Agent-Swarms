"""
Firecracker MicroVM Manager.

This module is responsible for managing the lifecycle of Firecracker microVMs.
It starts the VM, connects via vsock, and executes commands inside the guest safely.
"""
import json
import logging
import shutil
import socket
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class VMConfig:
    kernel_image: str = "vmlinux.bin"
    rootfs_image: str = "rootfs.ext4"
    vcpu_count: int = 2
    memory_mb: int = 512


class VMManager:
    """Manages an isolated Firecracker MicroVM."""
    
    def __init__(self, vm_id: str, config: VMConfig):
        self.vm_id = vm_id
        self.config = config
        self.base_dir = Path(tempfile.gettempdir()) / "firecracker" / self.vm_id
        self.socket_path = self.base_dir / "firecracker.sock"
        self.workspace_dir = self.base_dir / "workspace"
        self.process = None

    def initialize(self) -> None:
        """Sets up the VM directories and starts the Firecracker process."""
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.workspace_dir.mkdir(parents=True, exist_ok=True)
        
        # Start Firecracker
        self.process = subprocess.Popen(
            [
                "firecracker",
                "--api-sock",
                str(self.socket_path),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        
        # Wait for socket
        for _ in range(20):
            if self.socket_path.exists():
                break
            time.sleep(0.05)
        else:
            self.destroy()
            raise RuntimeError("Firecracker socket did not appear.")
            
        self._configure_vm()
        self._start_instance()

    def _configure_vm(self) -> None:
        """Configure boot source, drives, and vsock."""
        # Setup boot source
        self._api_request("PUT", "/boot-source", {
            "kernel_image_path": str(Path(self.config.kernel_image).resolve()),
            "boot_args": "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda"
        })
        
        # Setup rootfs
        self._api_request("PUT", "/drives/rootfs", {
            "drive_id": "rootfs",
            "path_on_host": str(Path(self.config.rootfs_image).resolve()),
            "is_root_device": True,
            "is_read_only": False
        })
        
        # Setup vsock for guest agent communication
        self._api_request("PUT", "/vsock", {
            "guest_cid": 3,  # 3 is standard for first guest vsock
            "uds_path": str(self.base_dir / "v.sock")
        })

    def _start_instance(self) -> None:
        """Starts the MicroVM instance."""
        self._api_request("PUT", "/actions", {
            "action_type": "InstanceStart"
        })

    def _api_request(self, method: str, path: str, payload: dict) -> None:
        """Makes an API request to the Firecracker socket."""
        import httpx
        transport = httpx.HTTPTransport(uds=str(self.socket_path))
        with httpx.Client(transport=transport) as client:
            resp = client.request(method, f"http://localhost{path}", json=payload)
            resp.raise_for_status()

    def execute_command(self, command: list[str], timeout: int = 120) -> dict[str, Any]:
        """Executes a command via vsock using the guest agent."""
        uds_path = self.base_dir / "v.sock_5000"  # Firecracker maps port 5000 to this file
        
        # Wait for guest agent to be ready
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        
        # Retries for guest boot
        connected = False
        for _ in range(50):
            try:
                client.connect(str(uds_path))
                connected = True
                break
            except Exception:
                time.sleep(0.1)
                
        if not connected:
            raise RuntimeError("Could not connect to guest agent via vsock.")
            
        try:
            payload = {
                "command": command,
                "working_dir": "/workspace",
                "timeout": timeout
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
            
            return json.loads(data.decode("utf-8").strip())
        finally:
            client.close()

    def destroy(self) -> None:
        """Kills the Firecracker process and cleans up directories."""
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
        
        if self.base_dir.exists():
            shutil.rmtree(self.base_dir, ignore_errors=True)
