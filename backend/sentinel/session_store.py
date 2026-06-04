"""Persistent session storage (SQLite) for Microsoft hackathon / production demos."""

from __future__ import annotations

import asyncio
import json
import sqlite3
from pathlib import Path

from .models import AuditSession, SessionNotFoundError


class SQLiteSessionStore:
    def __init__(self, db_path: Path | str) -> None:
        raw = str(db_path)
        if raw == ":memory:":
            self._db_path = "file:sentinel_mem?mode=memory&cache=shared"
            uri = True
        else:
            self._db_path = raw
            path = Path(raw)
            path.parent.mkdir(parents=True, exist_ok=True)
            uri = False
        self._conn = sqlite3.connect(self._db_path, uri=uri, check_same_thread=False)
        self._lock = asyncio.Lock()
        self._init_db()

    def _init_db(self) -> None:
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_sessions (
                session_id TEXT PRIMARY KEY,
                payload TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def _upsert_sync(self, session: AuditSession) -> None:
        payload = session.model_dump(mode="json")
        self._conn.execute(
            """
            INSERT INTO audit_sessions (session_id, payload, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(session_id) DO UPDATE SET
                payload = excluded.payload,
                updated_at = excluded.updated_at
            """,
            (session.session_id, json.dumps(payload), session.updated_at.isoformat()),
        )
        self._conn.commit()

    def _get_sync(self, session_id: str) -> AuditSession:
        row = self._conn.execute(
            "SELECT payload FROM audit_sessions WHERE session_id = ?",
            (session_id,),
        ).fetchone()
        if row is None:
            raise SessionNotFoundError(session_id)
        return AuditSession.model_validate(json.loads(row[0]))

    def _list_sync(self) -> list[AuditSession]:
        rows = self._conn.execute(
            "SELECT payload FROM audit_sessions ORDER BY updated_at DESC"
        ).fetchall()
        return [AuditSession.model_validate(json.loads(row[0])) for row in rows]

    async def create(self, session: AuditSession) -> AuditSession:
        async with self._lock:
            await asyncio.to_thread(self._upsert_sync, session)
        return session

    async def get(self, session_id: str) -> AuditSession:
        async with self._lock:
            return await asyncio.to_thread(self._get_sync, session_id)

    async def save(self, session: AuditSession) -> None:
        async with self._lock:
            await asyncio.to_thread(self._upsert_sync, session)

    async def list(self) -> list[AuditSession]:
        async with self._lock:
            return await asyncio.to_thread(self._list_sync)

    def close(self) -> None:
        self._conn.close()
