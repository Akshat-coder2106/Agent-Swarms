"""Qdrant vector database integration for semantic memory."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from qdrant_client import QdrantClient
from qdrant_client.models import (
    Distance,
    FieldCondition,
    Filter,
    FilterSelector,
    MatchValue,
    PointStruct,
    VectorParams,
)
from sentence_transformers import SentenceTransformer

from .models import CodeChunk, RepositoryMemory, sha256_text


@dataclass
class QdrantConfig:
    """Configuration for Qdrant integration."""

    host: str = "localhost"
    port: int = 6333
    collection_name: str = "sentinel-code-chunks"
    embedding_model: str = "sentence-transformers/all-mpnet-base-v2"
    vector_size: int = 768
    recreate_collection: bool = False


class QdrantMemoryIndex:
    """Qdrant-based semantic memory index for code chunks."""

    def __init__(self, config: QdrantConfig) -> None:
        self._config = config
        self._client = QdrantClient(host=config.host, port=config.port)
        self._encoder = SentenceTransformer(config.embedding_model)
        self._ensure_collection()

    def _ensure_collection(self) -> None:
        """Ensure the collection exists."""
        collections = self._client.get_collections().collections
        collection_names = [c.name for c in collections]

        if self._config.collection_name in collection_names:
            if self._config.recreate_collection:
                self._client.delete_collection(self._config.collection_name)
            else:
                return

        self._client.create_collection(
            collection_name=self._config.collection_name,
            vectors_config=VectorParams(
                size=self._config.vector_size,
                distance=Distance.COSINE,
            ),
        )

    def index_chunks(self, session_id: str, memory: RepositoryMemory) -> None:
        """Index code chunks from repository memory."""
        points = []
        for chunk in memory.chunks:
            # Generate embedding
            embedding = self._encoder.encode(chunk.text, convert_to_numpy=True).tolist()

            # Create point
            point = PointStruct(
                id=self._point_id(session_id, chunk.chunk_id),
                vector=embedding,
                payload={
                    "session_id": session_id,
                    "chunk_id": chunk.chunk_id,
                    "file_path": chunk.file_path,
                    "start_line": chunk.start_line,
                    "end_line": chunk.end_line,
                    "text": chunk.text,
                    "token_fingerprint": chunk.token_fingerprint,
                },
            )
            points.append(point)

        # Batch upsert
        if points:
            self._client.upsert(
                collection_name=self._config.collection_name,
                points=points,
            )

    def search(
        self,
        session_id: str,
        query: str,
        limit: int = 5,
        score_threshold: float = 0.5,
    ) -> list[tuple[CodeChunk, float]]:
        """Search for similar chunks."""
        # Generate query embedding
        query_embedding = self._encoder.encode(query, convert_to_numpy=True).tolist()

        # Search with session filter
        search_result = self._client.search(
            collection_name=self._config.collection_name,
            query_vector=query_embedding,
            query_filter=Filter(
                must=[
                    FieldCondition(
                        key="session_id",
                        match=MatchValue(value=session_id),
                    )
                ]
            ),
            limit=limit,
            score_threshold=score_threshold,
        )

        # Convert to CodeChunk objects
        results = []
        for hit in search_result:
            payload = hit.payload
            chunk = CodeChunk(
                chunk_id=payload["chunk_id"],
                file_path=payload["file_path"],
                start_line=payload["start_line"],
                end_line=payload["end_line"],
                text=payload["text"],
                token_fingerprint=payload["token_fingerprint"],
            )
            results.append((chunk, hit.score))

        return results

    def delete_session(self, session_id: str) -> None:
        """Delete all chunks for a session."""
        self._client.delete(
            collection_name=self._config.collection_name,
            points_selector=FilterSelector(
                filter=Filter(
                    must=[
                        FieldCondition(
                            key="session_id",
                            match=MatchValue(value=session_id),
                        )
                    ]
                )
            ),
        )

    def _point_id(self, session_id: str, chunk_id: str) -> str:
        """Generate unique point ID."""
        return sha256_text(f"{session_id}:{chunk_id}")

    def get_stats(self) -> dict[str, Any]:
        """Get collection statistics."""
        info = self._client.get_collection(self._config.collection_name)
        return {
            "points_count": info.points_count,
            "vectors_count": info.vectors_count,
            "indexed_vectors_count": info.indexed_vectors_count,
        }
