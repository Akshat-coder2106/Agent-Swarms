"""Guest Agent running inside a Firecracker MicroVM.

Listens on AF_VSOCK port 5000 for JSON-encoded commands from the host
``VMManager``, executes them locally in the guest, and streams structured
results back through the vsock connection.

Protocol
--------
- Transport: AF_VSOCK, port 5000, newline-delimited JSON
- Request:  ``{"type": "run_test"|"apply_patch"|"health_check", "payload": {...}, "request_id": "..."}``
- Response: ``{"request_id": "...", "exit_code": 0, "stdout": "...", "stderr": "...", ...}``

This file is copied into the guest rootfs by ``image_builder.py`` and
auto-started via ``/sbin/init``.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import signal
import socket
import subprocess
import sys
import tarfile
import time
import traceback
from pathlib import Path
from typing import Any

# Track boot time for health checks
_BOOT_TIME = time.monotonic()

# Vsock port the agent listens on
VSOCK_PORT = 5000


# ---------------------------------------------------------------------------
# Signal handling
# ---------------------------------------------------------------------------


_shutdown_requested = False


def _handle_sigterm(signum: int, frame: Any) -> None:
    global _shutdown_requested
    _shutdown_requested = True
    print("Guest Agent: received SIGTERM, shutting down gracefully...")
    sys.exit(0)


signal.signal(signal.SIGTERM, _handle_sigterm)


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------


def handle_run_test(payload: dict) -> dict:
    """Execute a command list and return structured results."""
    command = payload.get("command", [])
    working_dir = payload.get("working_dir", "/workspace")
    timeout = payload.get("timeout", 120)

    if not command:
        return {
            "exit_code": 1,
            "stdout": "",
            "stderr": "No command provided",
            "cpu_time_ms": 0,
            "memory_peak_kb": 0,
        }

    try:
        Path(working_dir).mkdir(parents=True, exist_ok=True)

        start = time.monotonic()
        process = subprocess.run(
            command,
            cwd=working_dir,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        cpu_time_ms = int((time.monotonic() - start) * 1000)

        # Try to read peak memory from /proc
        memory_peak_kb = _get_memory_peak_kb()

        return {
            "exit_code": process.returncode,
            "stdout": process.stdout[-8192:],  # Cap output size
            "stderr": process.stderr[-8192:],
            "cpu_time_ms": cpu_time_ms,
            "memory_peak_kb": memory_peak_kb,
        }
    except subprocess.TimeoutExpired:
        return {
            "exit_code": 124,
            "stdout": "",
            "stderr": f"Command timed out after {timeout}s",
            "cpu_time_ms": timeout * 1000,
            "memory_peak_kb": 0,
        }
    except FileNotFoundError as exc:
        return {
            "exit_code": 127,
            "stdout": "",
            "stderr": f"Command not found: {exc}",
            "cpu_time_ms": 0,
            "memory_peak_kb": 0,
        }
    except Exception as exc:
        return {
            "exit_code": 1,
            "stdout": "",
            "stderr": str(exc),
            "cpu_time_ms": 0,
            "memory_peak_kb": 0,
        }


def handle_apply_patch(payload: dict) -> dict:
    """Write file content to a path in the workspace."""
    file_path = payload.get("file_path", "")
    content = payload.get("content", "")
    working_dir = payload.get("working_dir", "/workspace")

    if not file_path:
        return {"exit_code": 1, "stdout": "", "stderr": "No file_path provided"}

    try:
        target = Path(working_dir) / file_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return {
            "exit_code": 0,
            "stdout": f"Patched {file_path} ({len(content)} bytes)",
            "stderr": "",
        }
    except Exception as exc:
        return {"exit_code": 1, "stdout": "", "stderr": str(exc)}


def handle_sync_workspace(payload: dict) -> dict:
    """Replace /workspace with a digest-verified archive from the host."""
    working_dir = Path(payload.get("working_dir", "/workspace")).resolve()
    expected_sha256 = str(payload.get("archive_sha256", ""))
    try:
        archive_bytes = base64.b64decode(payload.get("archive_b64", ""), validate=True)
        actual_sha256 = hashlib.sha256(archive_bytes).hexdigest()
        if not expected_sha256 or actual_sha256 != expected_sha256:
            raise ValueError("Workspace archive digest mismatch")

        working_dir.mkdir(parents=True, exist_ok=True)
        for child in working_dir.iterdir():
            if child.is_dir():
                import shutil

                shutil.rmtree(child)
            else:
                child.unlink()

        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as archive:
            members = archive.getmembers()
            for member in members:
                target = (working_dir / member.name).resolve()
                if working_dir not in target.parents and target != working_dir:
                    raise ValueError(f"Unsafe archive member: {member.name}")
                if member.issym() or member.islnk():
                    raise ValueError(f"Archive links are not allowed: {member.name}")
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                if not member.isfile():
                    raise ValueError(f"Unsupported archive member: {member.name}")
                source = archive.extractfile(member)
                if source is None:
                    raise ValueError(f"Could not read archive member: {member.name}")
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open("wb") as destination:
                    destination.write(source.read())

        return {
            "exit_code": 0,
            "stdout": f"Workspace synchronized ({len(archive_bytes)} bytes)",
            "stderr": "",
            "workspace_sha256": actual_sha256,
        }
    except Exception as exc:
        return {
            "exit_code": 1,
            "stdout": "",
            "stderr": str(exc),
            "workspace_sha256": "",
        }


def handle_health_check(_payload: dict) -> dict:
    """Return agent health information."""
    uptime_ms = int((time.monotonic() - _BOOT_TIME) * 1000)
    return {
        "exit_code": 0,
        "stdout": json.dumps({
            "status": "ok",
            "uptime_ms": uptime_ms,
            "python_version": sys.version,
            "pid": os.getpid(),
        }),
        "stderr": "",
    }


# Dispatch table
HANDLERS = {
    "run_test": handle_run_test,
    "apply_patch": handle_apply_patch,
    "sync_workspace": handle_sync_workspace,
    "health_check": handle_health_check,
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_memory_peak_kb() -> int:
    """Read VmPeak from /proc/self/status (Linux only)."""
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("VmPeak:"):
                    return int(line.split()[1])
    except (FileNotFoundError, ValueError, IndexError):
        pass
    return 0


# ---------------------------------------------------------------------------
# Connection handler
# ---------------------------------------------------------------------------


def handle_connection(conn: socket.socket) -> None:
    """Process a single client connection from the host VMManager."""
    try:
        data = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
            if b"\n" in chunk:
                break

        if not data:
            return

        request = json.loads(data.decode("utf-8").strip())

        # Support both new protocol (with "type") and legacy (flat command)
        cmd_type = request.get("type", "run_test")
        payload = request.get("payload", request)
        request_id = request.get("request_id", "unknown")

        # Legacy support: if "command" is at top level, treat as run_test
        if "command" in request and "type" not in request:
            payload = request
            cmd_type = "run_test"

        handler = HANDLERS.get(cmd_type, handle_run_test)
        result = handler(payload)

        response = {
            "request_id": request_id,
            **result,
        }

        conn.sendall((json.dumps(response) + "\n").encode("utf-8"))

    except Exception:
        error_resp = json.dumps({
            "request_id": "error",
            "exit_code": -1,
            "stdout": "",
            "stderr": traceback.format_exc(),
        }) + "\n"
        try:
            conn.sendall(error_resp.encode("utf-8"))
        except Exception:
            pass
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    """Start the guest agent listener on AF_VSOCK."""
    try:
        # AF_VSOCK = 40 on Linux
        server = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        server.bind((socket.VMADDR_CID_ANY, VSOCK_PORT))
        server.listen(4)
        print(f"Guest Agent listening on vsock port {VSOCK_PORT}...")

        while not _shutdown_requested:
            server.settimeout(1.0)
            try:
                conn, addr = server.accept()
                handle_connection(conn)
            except TimeoutError:
                continue

    except AttributeError:
        # AF_VSOCK not available (e.g. macOS) — fall back to TCP for testing
        print("AF_VSOCK not available, falling back to TCP on 127.0.0.1:5000")
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", VSOCK_PORT))
        server.listen(4)

        while not _shutdown_requested:
            server.settimeout(1.0)
            try:
                conn, addr = server.accept()
                handle_connection(conn)
            except TimeoutError:
                continue

    except Exception as exc:
        print(f"Guest Agent failed to start: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
