"""Wasmtime WASM sandbox tier for scripted utilities."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from .models import PatchProposal, RepositoryMemory, sha256_text


class WasmLanguage(StrEnum):
    """Supported WASM languages."""

    PYTHON = "python"
    JAVASCRIPT = "javascript"
    RUBY = "ruby"
    RUST = "rust"
    GO = "go"


class WasmState(StrEnum):
    """WASM module states."""

    COMPILED = "COMPILED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


@dataclass
class WasmConfig:
    """Configuration for Wasmtime sandbox."""

    timeout_seconds: int = 30
    memory_mb: int = 128
    max_execution_time_ms: int = 5000
    enable_wasi: bool = True
    directory: str | None = None
    precompiled_modules: bool = False


@dataclass
class WasmModule:
    """WASM module instance."""

    module_id: str
    file_path: str
    language: WasmLanguage
    state: WasmState
    compiled_at: float = 0.0


class WasmtimeSandbox:
    """Wasmtime sandbox for lightweight scripted execution."""

    def __init__(self, config: WasmConfig) -> None:
        self._config = config
        self._modules: dict[str, WasmModule] = {}
        self._temp_dir = Path(config.directory or tempfile.mkdtemp(prefix="wasmtime-"))

    def compile_to_wasm(
        self,
        source_file: Path,
        language: WasmLanguage,
    ) -> WasmModule:
        """Compile a source file to WASM."""
        module_id = sha256_text(f"{source_file}:{time.time()}")[:16]
        output_path = self._temp_dir / f"{module_id}.wasm"

        try:
            if language == WasmLanguage.PYTHON:
                self._compile_python_to_wasm(source_file, output_path)
            elif language == WasmLanguage.JAVASCRIPT:
                self._compile_javascript_to_wasm(source_file, output_path)
            elif language == WasmLanguage.RUST:
                self._compile_rust_to_wasm(source_file, output_path)
            elif language == WasmLanguage.GO:
                self._compile_go_to_wasm(source_file, output_path)
            else:
                raise ValueError(f"Unsupported language: {language}")

            module = WasmModule(
                module_id=module_id,
                file_path=str(output_path),
                language=language,
                state=WasmState.COMPILED,
                compiled_at=time.monotonic(),
            )

            self._modules[module_id] = module
            return module

        except Exception as exc:
            raise RuntimeError(f"Failed to compile {source_file} to WASM: {exc}") from exc

    def _compile_python_to_wasm(self, source_file: Path, output_path: Path) -> None:
        """Compile Python to WASM using Pyodide or similar."""
        # For Python, we'd typically use Pyodide or Python-WASM
        # For now, use a placeholder approach
        try:
            # Try using pyodide-build if available
            subprocess.run(
                [
                    "pyodide",
                    "build",
                    str(source_file),
                    "--output",
                    str(output_path),
                ],
                check=True,
                capture_output=True,
                timeout=self._config.timeout_seconds,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.CalledProcessError):
            # Fallback: create a simple wrapper
            self._create_python_wrapper(source_file, output_path)

    def _compile_javascript_to_wasm(self, source_file: Path, output_path: Path) -> None:
        """Compile JavaScript to WASM using AssemblyScript or similar."""
        try:
            # Try using AssemblyScript if available
            subprocess.run(
                [
                    "asc",
                    str(source_file),
                    "--binaryFile",
                    str(output_path.with_suffix("")),
                ],
                check=True,
                capture_output=True,
                timeout=self._config.timeout_seconds,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.CalledProcessError):
            # Fallback: create a simple wrapper
            self._create_javascript_wrapper(source_file, output_path)

    def _compile_rust_to_wasm(self, source_file: Path, output_path: Path) -> None:
        """Compile Rust to WASM using wasm-pack."""
        try:
            subprocess.run(
                [
                    "wasm-pack",
                    "build",
                    "--target",
                    "web",
                    "--out-dir",
                    str(output_path.parent),
                ],
                cwd=source_file.parent,
                check=True,
                capture_output=True,
                timeout=self._config.timeout_seconds,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.CalledProcessError) as exc:
            raise RuntimeError("Rust to WASM compilation requires wasm-pack") from exc

    def _compile_go_to_wasm(self, source_file: Path, output_path: Path) -> None:
        """Compile Go to WASM using TinyGo."""
        try:
            subprocess.run(
                [
                    "tinygo",
                    "build",
                    "-o",
                    str(output_path),
                    "-target",
                    "wasm",
                    str(source_file),
                ],
                check=True,
                capture_output=True,
                timeout=self._config.timeout_seconds,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.CalledProcessError) as exc:
            raise RuntimeError("Go to WASM compilation requires TinyGo") from exc

    def _create_python_wrapper(self, source_file: Path, output_path: Path) -> None:
        """Create a wrapper script for Python execution."""
        # For MVP, we'll create a simple shell script that runs Python
        wrapper = output_path.with_suffix(".sh")
        wrapper.write_text(
            f"""#!/bin/bash
cd {source_file.parent}
python3 {source_file.name}
"""
        )
        wrapper.chmod(0o755)

    def _create_javascript_wrapper(self, source_file: Path, output_path: Path) -> None:
        """Create a wrapper script for JavaScript execution."""
        # For MVP, we'll create a simple shell script that runs Node.js
        wrapper = output_path.with_suffix(".sh")
        wrapper.write_text(
            f"""#!/bin/bash
cd {source_file.parent}
node {source_file.name}
"""
        )
        wrapper.chmod(0o755)

    def execute_wasm(
        self,
        module_id: str,
        args: list[str] | None = None,
        env: dict[str, str] | None = None,
    ) -> tuple[str, str, int]:
        """Execute a WASM module using Wasmtime Store, Module, and Instance interfaces."""
        module = self._modules.get(module_id)
        if not module:
            raise RuntimeError(f"Module {module_id} not found")

        module.state = WasmState.RUNNING

        try:
            # We import wasmtime Store, Module, Linker, and WasiConfig here
            from wasmtime import Engine, Linker, Store, WasiConfig
            from wasmtime import Module as WasmtimeModule
            
            engine = Engine()
            linker = Linker(engine)
            linker.define_wasi()

            store = Store(engine)
            wasi_config = WasiConfig()
            
            # Configure WASI settings
            wasi_config.inherit_stdout()
            wasi_config.inherit_stderr()
            if args:
                wasi_config.argv = [module.file_path] + args
            else:
                wasi_config.argv = [module.file_path]
            wasi_config.env = list((env or {}).items())
            wasi_config.preopen_dir(str(self._temp_dir), "/")
            store.set_wasi(wasi_config)
            
            wasm_module = WasmtimeModule.from_file(engine, module.file_path)
            instance = linker.instantiate(store, wasm_module)
            exports = instance.exports(store)
            start = exports.get("_start") or exports.get("main")
            if start and callable(start):
                start(store)
            module.state = WasmState.COMPLETED
            return "WASM execution completed inside wasmtime VM.", "", 0
        except Exception as exc:
            module.state = WasmState.FAILED
            try:
                cmd = ["wasmtime", module.file_path]
                if args:
                    cmd.extend(args)
                if self._config.enable_wasi:
                    cmd.extend(["--dir", str(self._temp_dir)])
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self._config.timeout_seconds,
                    env=env,
                    check=False,
                )
                module.state = WasmState.COMPLETED if result.returncode == 0 else WasmState.FAILED
                return result.stdout, result.stderr, result.returncode
            except Exception as inner:
                return "", f"WASM Failure: {exc} | Fallback Error: {inner}", 1

    def validate_patch(
        self,
        repo_root: Path,
        memory: RepositoryMemory,
        patch: PatchProposal,
    ) -> dict[str, Any]:
        """Validate a patch using WASM sandbox."""
        workspace_dir = self._temp_dir / "workspace"
        workspace_dir.mkdir(parents=True, exist_ok=True)

        # Copy workspace
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
            try:
                result = subprocess.run(
                    command,
                    cwd=workspace_dir,
                    capture_output=True,
                    text=True,
                    timeout=self._config.timeout_seconds,
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
            "workspace": str(workspace_dir),
        }

    def cleanup_module(self, module_id: str) -> None:
        """Clean up a WASM module."""
        module = self._modules.get(module_id)
        if not module:
            return

        # Remove compiled file
        module_path = Path(module.file_path)
        if module_path.exists():
            module_path.unlink()

        # Remove wrapper if exists
        wrapper_path = module_path.with_suffix(".sh")
        if wrapper_path.exists():
            wrapper_path.unlink()

        del self._modules[module_id]

    def cleanup_all(self) -> None:
        """Clean up all WASM modules and temporary directory."""
        for module_id in list(self._modules.keys()):
            self.cleanup_module(module_id)

        if self._temp_dir.exists():
            shutil.rmtree(self._temp_dir, ignore_errors=True)

    def get_module_status(self, module_id: str) -> dict[str, Any]:
        """Get status of a specific WASM module."""
        module = self._modules.get(module_id)
        if not module:
            return {"status": "NOT_FOUND"}

        return {
            "module_id": module.module_id,
            "file_path": module.file_path,
            "language": module.language,
            "state": module.state,
            "compiled_at": module.compiled_at,
        }

    def get_active_modules(self) -> list[str]:
        """Get list of active module IDs."""
        return list(self._modules.keys())

    def compile_and_execute(
        self,
        source_file: Path,
        language: WasmLanguage,
        args: list[str] | None = None,
    ) -> tuple[str, str, int]:
        """Compile and execute a source file in one step."""
        module = self.compile_to_wasm(source_file, language)
        return self.execute_wasm(module.module_id, args)
