"""Neo4j property graph integration for structural code relationships."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from neo4j import AsyncGraphDatabase

from .models import CodeGraphEdge, CodeSymbol, RepositoryMemory


@dataclass
class Neo4jConfig:
    """Configuration for Neo4j integration."""

    uri: str = "bolt://localhost:7687"
    username: str = "neo4j"
    password: str = "password"
    database: str = "neo4j"


class Neo4jGraphIndex:
    """Neo4j-based property graph for code structure."""

    def __init__(self, config: Neo4jConfig) -> None:
        self._config = config
        self._driver = AsyncGraphDatabase.driver(
            config.uri,
            auth=(config.username, config.password),
        )

    async def close(self) -> None:
        """Close the driver connection."""
        await self._driver.close()

    async def index_memory(self, session_id: str, memory: RepositoryMemory) -> None:
        """Index repository memory into Neo4j graph."""
        async with self._driver.session(database=self._config.database) as session:
            # Create session node
            await session.run(
                """
                MERGE (s:Session {session_id: $session_id})
                SET s.root_path = $root_path,
                    s.files_indexed = $files_indexed,
                    s.indexed_at = datetime()
                """,
                session_id=session_id,
                root_path=memory.root_path,
                files_indexed=memory.files_indexed,
            )

            # Index symbols as nodes
            for symbol in memory.symbols:
                await self._index_symbol(session, session_id, symbol)

            # Index edges as relationships
            for edge in memory.edges:
                await self._index_edge(session, session_id, edge)

            # Index file nodes
            files = {chunk.file_path for chunk in memory.chunks}
            for file_path in files:
                await self._index_file(session, session_id, file_path)

    async def _index_symbol(
        self,
        session,
        session_id: str,
        symbol: CodeSymbol,
    ) -> None:
        """Index a code symbol as a node."""
        await session.run(
            """
            MERGE (s:Symbol {symbol_id: $symbol_id})
            SET s.name = $name,
                s.kind = $kind,
                s.file_path = $file_path,
                s.start_line = $start_line,
                s.end_line = $end_line,
                s.session_id = $session_id
            """,
            symbol_id=symbol.symbol_id,
            name=symbol.name,
            kind=symbol.kind,
            file_path=symbol.file_path,
            start_line=symbol.start_line,
            end_line=symbol.end_line,
            session_id=session_id,
        )

    async def _index_edge(
        self,
        session,
        session_id: str,
        edge: CodeGraphEdge,
    ) -> None:
        """Index a code relationship."""
        await session.run(
            """
            MATCH (source:Symbol {symbol_id: $source_id})
            MATCH (target:Symbol {symbol_id: $target_id})
            MERGE (source)-[r:RELATES {session_id: $session_id}]->(target)
            SET r.relationship = $relationship
            """,
            source_id=edge.source_id,
            target_id=edge.target_id,
            relationship=edge.relationship,
            session_id=session_id,
        )

    async def _index_file(
        self,
        session,
        session_id: str,
        file_path: str,
    ) -> None:
        """Index a file node."""
        await session.run(
            """
            MERGE (f:File {file_path: $file_path, session_id: $session_id})
            """,
            file_path=file_path,
            session_id=session_id,
        )

    async def query_symbols_for_file(
        self,
        session_id: str,
        file_path: str,
    ) -> list[dict[str, Any]]:
        """Query all symbols in a file."""
        async with self._driver.session(database=self._config.database) as session:
            result = await session.run(
                """
                MATCH (s:Symbol {session_id: $session_id, file_path: $file_path})
                RETURN s
                ORDER BY s.start_line
                """,
                session_id=session_id,
                file_path=file_path,
            )
            return [record.data()["s"] async for record in result]

    async def query_call_graph(
        self,
        session_id: str,
        symbol_name: str,
        max_depth: int = 3,
    ) -> list[dict[str, Any]]:
        """Query the call graph for a symbol."""
        async with self._driver.session(database=self._config.database) as session:
            result = await session.run(
                """
                MATCH path = (s:Symbol {session_id: $session_id, name: $name})-[:RELATES*1..$max_depth]->(t:Symbol)
                RETURN path, t
                """,
                session_id=session_id,
                name=symbol_name,
                max_depth=max_depth,
            )
            return [record.data() async for record in result]

    async def query_vulnerability_impact(
        self,
        session_id: str,
        symbol_id: str,
    ) -> list[dict[str, Any]]:
        """Query which services/functions are affected by a vulnerable symbol."""
        async with self._driver.session(database=self._config.database) as session:
            result = await session.run(
                """
                MATCH (vuln:Symbol {symbol_id: $symbol_id, session_id: $session_id})
                MATCH (caller:Symbol)-[:RELATES]->(vuln)
                RETURN caller
                """,
                symbol_id=symbol_id,
                session_id=session_id,
            )
            return [record.data()["caller"] async for record in result]

    async def query_circular_dependencies(
        self,
        session_id: str,
    ) -> list[dict[str, Any]]:
        """Detect circular dependencies in the codebase."""
        async with self._driver.session(database=self._config.database) as session:
            result = await session.run(
                """
                MATCH path = (s:Symbol {session_id: $session_id})-[:RELATES*]->(s)
                WHERE length(path) > 1
                RETURN path
                LIMIT 100
                """,
                session_id=session_id,
            )
            return [record.data() async for record in result]

    async def delete_session(self, session_id: str) -> None:
        """Delete all nodes and relationships for a session."""
        async with self._driver.session(database=self._config.database) as session:
            await session.run(
                """
                MATCH (n {session_id: $session_id})
                DETACH DELETE n
                """,
                session_id=session_id,
            )

    async def get_stats(self) -> dict[str, Any]:
        """Get graph statistics."""
        async with self._driver.session(database=self._config.database) as session:
            result = await session.run(
                """
                MATCH (n)
                RETURN count(n) as node_count,
                       count((n)-[:RELATES]->()) as relationship_count
                """
            )
            record = await result.single()
            return {
                "node_count": record["node_count"],
                "relationship_count": record["relationship_count"],
            }
