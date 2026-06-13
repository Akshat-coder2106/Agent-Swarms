"""Azure AI Foundry embeddings for semantic code search.

Replaces the token-overlap search in RepositoryIngestor.search()
with real vector similarity using Azure AI Foundry's embedding models.
Falls back to token-overlap if Azure credentials are not configured.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .models import CodeChunk, RepositoryMemory

logger = logging.getLogger(__name__)


# ── Azure AI Inference SDK (graceful degradation) ───────────────────────────
try:
    from azure.ai.inference import EmbeddingsClient
    from azure.core.credentials import AzureKeyCredential
    AZURE_INFERENCE_AVAILABLE = True
except ImportError:
    AZURE_INFERENCE_AVAILABLE = False
    logger.warning(
        "azure-ai-inference not installed. "
        "Falling back to token-overlap search. "
        "Run: pip install azure-ai-inference"
    )


@dataclass
class EmbeddingSearchResult:
    chunk: "CodeChunk"
    score: float
    method: str  # "azure_foundry" | "token_overlap"


class AzureFoundryEmbedder:
    """Semantic search using Azure AI Foundry embeddings.

    Uses the text-embedding-3-small model via Azure AI Services endpoint.
    Falls back to token-overlap Jaccard similarity when unavailable.
    """

    EMBEDDING_MODEL = "text-embedding-3-small"

    def __init__(self) -> None:
        self._client = None
        self._endpoint = os.getenv("AZURE_AI_ENDPOINT", "")
        self._key = os.getenv("AZURE_AI_KEY", "")
        self._cache: dict[str, list[float]] = {}

        if AZURE_INFERENCE_AVAILABLE and self._endpoint and self._key:
            try:
                self._client = EmbeddingsClient(
                    endpoint=self._endpoint,
                    credential=AzureKeyCredential(self._key),
                )
                logger.info("AzureFoundryEmbedder: connected to %s", self._endpoint)
            except Exception as exc:
                logger.warning("AzureFoundryEmbedder: failed to connect — %s", exc)

    @property
    def is_available(self) -> bool:
        return self._client is not None

    def embed(self, text: str) -> list[float] | None:
        """Get embedding vector for a text string. Results are cached."""
        if not self._client:
            return None
        cache_key = text[:200]  # key on first 200 chars
        if cache_key in self._cache:
            return self._cache[cache_key]
        try:
            response = self._client.embed(
                input=[text[:8000]],  # respect token limit
                model=self.EMBEDDING_MODEL,
            )
            vector = response.data[0].embedding
            self._cache[cache_key] = vector
            return vector
        except Exception as exc:
            logger.warning("Embedding call failed: %s", exc)
            return None

    @staticmethod
    def cosine_similarity(a: list[float], b: list[float]) -> float:
        """Dot-product cosine similarity (vectors are pre-normalised by Azure)."""
        if len(a) != len(b):
            return 0.0
        return sum(x * y for x, y in zip(a, b))

    def search(
        self,
        memory: "RepositoryMemory",
        query: str,
        *,
        limit: int = 5,
    ) -> list[EmbeddingSearchResult]:
        """Semantic search over code chunks using Azure AI Foundry embeddings.

        Falls back to token-overlap Jaccard if embeddings unavailable.
        """
        query_vec = self.embed(query) if self._client else None

        if query_vec:
            # ── Azure Foundry path ──────────────────────────────────────────
            scored: list[EmbeddingSearchResult] = []
            for chunk in memory.chunks:
                chunk_text = f"{chunk.file_path} {chunk.text}"
                chunk_vec = self.embed(chunk_text)
                if chunk_vec:
                    score = self.cosine_similarity(query_vec, chunk_vec)
                    scored.append(EmbeddingSearchResult(
                        chunk=chunk, score=score, method="azure_foundry"
                    ))
            return sorted(scored, key=lambda r: r.score, reverse=True)[:limit]

        else:
            # ── Token-overlap fallback ──────────────────────────────────────
            def tokenize(text: str) -> set[str]:
                return set(text.lower().split())

            query_tokens = tokenize(query)
            scored = []
            for chunk in memory.chunks:
                chunk_tokens = tokenize(chunk.text)
                overlap = len(query_tokens & chunk_tokens)
                if overlap == 0:
                    continue
                denom = len(query_tokens | chunk_tokens) or 1
                scored.append(EmbeddingSearchResult(
                    chunk=chunk,
                    score=overlap / denom,
                    method="token_overlap",
                ))
            return sorted(scored, key=lambda r: r.score, reverse=True)[:limit]


# Singleton for use across the application
_embedder: AzureFoundryEmbedder | None = None


def get_embedder() -> AzureFoundryEmbedder:
    global _embedder
    if _embedder is None:
        _embedder = AzureFoundryEmbedder()
    return _embedder
