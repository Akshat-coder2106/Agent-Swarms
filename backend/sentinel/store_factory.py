from __future__ import annotations

import os
from pathlib import Path

from .config import Settings
from .orchestrator import SessionStore
from .session_store import SQLiteSessionStore


def build_session_store(settings: Settings) -> SessionStore | SQLiteSessionStore:
    db_path = os.getenv("SENTINEL_SESSION_DB", "").strip()
    if db_path:
        return SQLiteSessionStore(Path(db_path).expanduser().resolve())
    if settings.environment == "production":
        default = Path.cwd() / "data" / "sentinel_sessions.db"
        return SQLiteSessionStore(default)
    return SessionStore()
