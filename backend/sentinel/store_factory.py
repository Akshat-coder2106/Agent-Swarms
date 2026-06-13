from __future__ import annotations

import os
from pathlib import Path

from .config import Settings
from .orchestrator import SessionStore
from .session_store import SQLiteSessionStore

from .postgres_store import PostgresSessionStore

def build_session_store(settings: Settings) -> SessionStore | SQLiteSessionStore | PostgresSessionStore:
    if hasattr(settings, "postgres_dsn") and settings.postgres_dsn:
        return PostgresSessionStore(settings.postgres_dsn)
    postgres_dsn = os.getenv("POSTGRES_DSN", "").strip()
    if postgres_dsn:
        return PostgresSessionStore(postgres_dsn)

    if settings.session_store_backend == "memory":
        return SessionStore()
    db_path = os.getenv("SENTINEL_SESSION_DB", settings.session_db).strip()
    if db_path:
        return SQLiteSessionStore(Path(db_path).expanduser().resolve())
    if settings.sentinel_environment == "production":
        default = Path.cwd() / "data" / "sentinel_sessions.db"
        return SQLiteSessionStore(default)
    return SessionStore()
