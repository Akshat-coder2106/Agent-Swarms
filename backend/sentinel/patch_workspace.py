"""Immutable patch workspace management."""

from __future__ import annotations

import hashlib
import json
import logging
import shutil
from pathlib import Path
from typing import Any
from uuid import uuid4

from .models import PatchProposal

logger = logging.getLogger(__name__)


class PatchWorkspace:
    """Manages staged patches."""
    
    def __init__(self, base_dir: str | Path = "/tmp"):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(exist_ok=True, parents=True)
    
    def stage_patch(self, session_id: str, patch: PatchProposal) -> Path:
        """Stage patch (NOT applied yet)."""
        workspace_id = f"patch_{session_id}_{uuid4().hex[:8]}"
        workspace_path = self.base_dir / workspace_id
        workspace_path.mkdir(exist_ok=True, parents=True)
        
        metadata = {
            "version": "1.0",
            "patch_id": patch.patch_id,
            "task_id": patch.task_id,
            "session_id": session_id,
            "unified_diff": patch.unified_diff,
            "rationale": patch.rationale,
            "engineer_confidence": patch.engineer_confidence,
            "risk": patch.risk.value,
            "files": [
                {
                    "file_path": f.file_path,
                    "original_sha256": f.original_sha256,
                    "patched_sha256": f.patched_sha256,
                }
                for f in patch.files
            ],
        }
        
        (workspace_path / "metadata.json").write_text(
            json.dumps(metadata, indent=2)
        )
        
        files_dir = workspace_path / "files"
        files_dir.mkdir(exist_ok=True)
        
        for file_patch in patch.files:
            safe_name = file_patch.file_path.replace("/", "_")
            patch_file = files_dir / safe_name
            patch_file.write_text(file_patch.patched, encoding="utf-8")
            patch_file.chmod(0o444)
        
        (workspace_path / ".immutable").touch()
        logger.info(f"Patch staged: {workspace_path}")
        return workspace_path
    
    def apply_patch(self, workspace_path: Path, target_repo: Path) -> None:
        """Apply patch to repo."""
        metadata_file = workspace_path / "metadata.json"
        metadata = json.loads(metadata_file.read_text())
        files_dir = workspace_path / "files"
        
        for file_patch in metadata["files"]:
            file_path = file_patch["file_path"]
            target_file = target_repo / file_path
            
            if not target_file.exists():
                raise ValueError(f"Target does not exist: {file_path}")
            
            from .memory import safe_read_text
            current = safe_read_text(target_file)
            current_hash = hashlib.sha256(current.encode("utf-8")).hexdigest()
            
            if current_hash != file_patch["original_sha256"]:
                raise ValueError(f"File {file_path} changed since validation")
            
            safe_name = file_path.replace("/", "_")
            patched = (files_dir / safe_name).read_text(encoding="utf-8")
            target_file.write_text(patched, encoding="utf-8")
            
            logger.info(f"Applied patch: {file_path}")
    
    def cleanup(self, workspace_path: Path) -> None:
        """Delete workspace."""
        if workspace_path.exists():
            shutil.rmtree(workspace_path, ignore_errors=True)
            logger.info(f"Cleaned: {workspace_path}")
