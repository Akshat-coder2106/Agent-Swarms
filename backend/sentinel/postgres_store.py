"""Persistent session storage (PostgreSQL) for enterprise deployments."""

from __future__ import annotations

import json
import logging
from typing import Any

from .models import AuditSession, SessionNotFoundError

logger = logging.getLogger(__name__)

try:
    import asyncpg
except ImportError:
    asyncpg = None  # type: ignore


class PostgresSessionStore:
    """Enterprise-grade persistent session storage using PostgreSQL."""

    def __init__(self, dsn: str) -> None:
        if asyncpg is None:
            raise RuntimeError("asyncpg is not installed. Please install it to use PostgresSessionStore.")
        self._dsn = dsn
        self._pool: asyncpg.Pool | None = None

    async def connect(self) -> None:
        if self._pool is None:
            self._pool = await asyncpg.create_pool(dsn=self._dsn)
            async with self._pool.acquire() as conn:
                await conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS audit_sessions (
                        session_id TEXT PRIMARY KEY,
                        payload JSONB NOT NULL,
                        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                    )
                    """
                )
            logger.info("Connected to PostgreSQL session store.")

    async def create(self, session: AuditSession) -> AuditSession:
        await self.save(session)
        return session

    async def get(self, session_id: str) -> AuditSession:
        if self._pool is None:
            await self.connect()
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT payload FROM audit_sessions WHERE session_id = $1",
                session_id,
            )
            if not row:
                raise SessionNotFoundError(session_id)
            return AuditSession.model_validate(json.loads(row["payload"]))

    async def save(self, session: AuditSession) -> None:
        if self._pool is None:
            await self.connect()
        async with self._pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO audit_sessions (session_id, payload, updated_at)
                VALUES ($1, $2, CURRENT_TIMESTAMP)
                ON CONFLICT (session_id) DO UPDATE SET
                    payload = EXCLUDED.payload,
                    updated_at = CURRENT_TIMESTAMP
                """,
                session.session_id,
                session.model_dump_json(),
            )

    async def list(self) -> list[AuditSession]:
        if self._pool is None:
            await self.connect()
        async with self._pool.acquire() as conn:
            rows = await conn.fetch("SELECT payload FROM audit_sessions ORDER BY updated_at DESC LIMIT 100")
            return [AuditSession.model_validate(json.loads(row["payload"])) for row in rows]
