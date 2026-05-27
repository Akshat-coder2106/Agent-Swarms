"""
Audit Logger for enterprise-grade tracking.

Logs important events in a structured format (JSON) for compliance.
"""
import json
import logging
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Optional


class AuditAction(str, Enum):
    LOGIN = "LOGIN"
    LOGOUT = "LOGOUT"
    APPROVAL = "APPROVAL"
    ROLLBACK = "ROLLBACK"
    REPO_INGESTION = "REPO_INGESTION"
    PATCH_APPLICATION = "PATCH_APPLICATION"
    WEBHOOK_TRIGGER = "WEBHOOK_TRIGGER"
    PERMISSION_DENIED = "PERMISSION_DENIED"


class AuditLogger:
    def __init__(self, log_dir: str = "/tmp/sentinel_logs/audit"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = self.log_dir / "audit.jsonl"

    def log_event(
        self,
        action: AuditAction,
        actor: str,
        resource: Optional[str] = None,
        details: Optional[dict[str, Any]] = None,
        success: bool = True,
    ) -> None:
        """Write a structured audit log entry."""
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "action": action.value,
            "actor": actor,
            "resource": resource or "SYSTEM",
            "details": details or {},
            "success": success,
        }
        
        with open(self.log_file, "a") as f:
            f.write(json.dumps(entry) + "\n")
            
        # Also mirror to standard logging for immediate visibility
        if success:
            logging.info(f"AUDIT [{action.value}] by {actor} on {resource}")
        else:
            logging.warning(f"AUDIT DENIED [{action.value}] by {actor} on {resource}")
