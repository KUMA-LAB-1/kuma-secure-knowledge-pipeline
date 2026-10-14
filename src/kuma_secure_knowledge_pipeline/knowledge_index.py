"""Bounded, immutable resource policy for local knowledge indexing."""

import json
from dataclasses import dataclass

from kuma_secure_knowledge_pipeline.knowledge_budget import (
    MAX_CHUNK_AMPLIFICATION,
    project_chunk_allocation,
    within_amplification_budget,
)
from kuma_secure_knowledge_pipeline.knowledge_chunks import (
    ChunkPolicy,
    KnowledgeChunk,
    chunk_csv_record,
)
from kuma_secure_knowledge_pipeline.knowledge_contracts import SourceLocator
from kuma_secure_knowledge_pipeline.knowledge_csv import resolve_csv_record
from kuma_secure_knowledge_pipeline.knowledge_evidence import VerifiedSourceSnapshot

_MAX_CHUNKS = 1024
_MAX_TOTAL_CHARS = 4 * 1024 * 1024
_MAX_SOURCE_BYTES = 16 * 1024 * 1024
_MAX_INDEX_AMPLIFICATION = MAX_CHUNK_AMPLIFICATION


@dataclass(frozen=True, slots=True, kw_only=True)
class IndexPolicy:
    """Explicit aggregate resource budgets for a knowledge index."""

    max_chunks: int
    max_total_chars: int
    max_source_bytes: int

    def __post_init__(self) -> None:
        if type(self.max_chunks) is not int or not 1 <= self.max_chunks <= _MAX_CHUNKS:
            raise ValueError("Invalid index chunk budget.")

        if (
            type(self.max_total_chars) is not int
            or not 1 <= self.max_total_chars <= _MAX_TOTAL_CHARS
        ):
            raise ValueError("Invalid index character budget.")

        if (
            type(self.max_source_bytes) is not int
            or not 1 <= self.max_source_bytes <= _MAX_SOURCE_BYTES
        ):
            raise ValueError("Invalid index source byte budget.")


class IndexingError(ValueError):
    """Reject construction when source, corpus, or budget verification fails."""


@dataclass(frozen=True, slots=True, kw_only=True)
class KnowledgeIndex:
    """Derived CSV chunks; direct construction is not proof of verification."""

    source_sha256: str
    locator: SourceLocator
    chunks: tuple[KnowledgeChunk, ...]
    policy: IndexPolicy
    total_chars: int


def build_csv_index(
    snapshot: VerifiedSourceSnapshot,
    chunks: tuple[KnowledgeChunk, ...],
    *,
    policy: IndexPolicy,
) -> KnowledgeIndex:
    """Reverify one CSV record before constructing a bounded index."""
    if type(snapshot) is not VerifiedSourceSnapshot:
        raise IndexingError("Invalid source snapshot.")

    if type(policy) is not IndexPolicy:
        raise IndexingError("Invalid index policy.")

    if type(chunks) is not tuple or not chunks:
        raise IndexingError("Invalid index corpus.")

    try:
        checked_policy = IndexPolicy(
            max_chunks=policy.max_chunks,
            max_total_chars=policy.max_total_chars,
            max_source_bytes=policy.max_source_bytes,
        )

        if len(chunks) > checked_policy.max_chunks:
            raise IndexingError("Index chunk count exceeds budget.")

        if (
            type(snapshot.content) is not bytes
            or not 1 <= len(snapshot.content) <= checked_policy.max_source_bytes
        ):
            raise IndexingError("Index source exceeds byte budget.")

        if any(type(chunk) is not KnowledgeChunk for chunk in chunks):
            raise IndexingError("Invalid index chunk type.")

        total_chars = sum(len(chunk.text) for chunk in chunks)

        if total_chars > checked_policy.max_total_chars:
            raise IndexingError("Index corpus exceeds character budget.")

        locator = snapshot.locator

        if type(locator) is not SourceLocator:
            raise IndexingError("Invalid source locator.")

        checked_locator = SourceLocator(
            artifact_id=locator.artifact_id,
            source_sha256=locator.source_sha256,
            kind=locator.kind,
            page=locator.page,
            region=locator.region,
            record_index=locator.record_index,
            record_id=locator.record_id,
        )

        if checked_locator.kind != "csv_row":
            raise IndexingError("Only CSV records are indexable.")

        checked_snapshot = VerifiedSourceSnapshot(
            artifact=snapshot.artifact,
            locator=checked_locator,
            content=snapshot.content,
        )

        chunk_policy = chunks[0].policy

        if type(chunk_policy) is not ChunkPolicy:
            raise IndexingError("Invalid chunking policy.")

        checked_chunk_policy = ChunkPolicy(
            max_chars=chunk_policy.max_chars,
            overlap_chars=chunk_policy.overlap_chars,
            max_chunks=chunk_policy.max_chunks,
        )

        expected_chunks = chunk_csv_record(
            checked_snapshot,
            policy=checked_chunk_policy,
        )

        if expected_chunks != chunks:
            raise IndexingError("Index corpus does not match verified source.")

        if sum(len(chunk.text) for chunk in expected_chunks) != total_chars:
            raise IndexingError("Index corpus length mismatch.")

        canonical_chars = expected_chunks[-1].end

        if canonical_chars < 1 or not within_amplification_budget(
            canonical_chars=canonical_chars,
            projected_chars=total_chars,
        ):
            raise IndexingError("Index corpus amplification exceeds limit.")

        return KnowledgeIndex(
            source_sha256=checked_snapshot.artifact.sha256,
            locator=checked_locator,
            chunks=expected_chunks,
            policy=checked_policy,
            total_chars=total_chars,
        )

    except IndexingError:
        raise
    except (AttributeError, TypeError, ValueError, OverflowError):
        raise IndexingError("Unable to verify index corpus.") from None


def build_verified_csv_index(
    snapshot: VerifiedSourceSnapshot,
    *,
    chunk_policy: ChunkPolicy,
    policy: IndexPolicy,
) -> KnowledgeIndex:
    """Project budgets before constructing verified CSV chunks."""
    if type(snapshot) is not VerifiedSourceSnapshot:
        raise IndexingError("Invalid source snapshot.")

    if type(chunk_policy) is not ChunkPolicy:
        raise IndexingError("Invalid chunking policy.")

    if type(policy) is not IndexPolicy:
        raise IndexingError("Invalid index policy.")

    try:
        checked_policy = IndexPolicy(
            max_chunks=policy.max_chunks,
            max_total_chars=policy.max_total_chars,
            max_source_bytes=policy.max_source_bytes,
        )

        checked_chunk_policy = ChunkPolicy(
            max_chars=chunk_policy.max_chars,
            overlap_chars=chunk_policy.overlap_chars,
            max_chunks=chunk_policy.max_chunks,
        )

        if (
            type(snapshot.content) is not bytes
            or not 1 <= len(snapshot.content) <= checked_policy.max_source_bytes
        ):
            raise IndexingError("Index source exceeds byte budget.")

        locator = snapshot.locator

        if type(locator) is not SourceLocator:
            raise IndexingError("Invalid source locator.")

        checked_locator = SourceLocator(
            artifact_id=locator.artifact_id,
            source_sha256=locator.source_sha256,
            kind=locator.kind,
            page=locator.page,
            region=locator.region,
            record_index=locator.record_index,
            record_id=locator.record_id,
        )

        if checked_locator.kind != "csv_row":
            raise IndexingError("Only CSV records are indexable.")

        checked_snapshot = VerifiedSourceSnapshot(
            artifact=snapshot.artifact,
            locator=checked_locator,
            content=snapshot.content,
        )

        record = resolve_csv_record(checked_snapshot)

        canonical = json.dumps(
            [[name, value] for name, value in record.fields],
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        )

        canonical_chars = len(canonical)

        if not 1 <= canonical_chars <= checked_policy.max_total_chars:
            raise IndexingError("Canonical record exceeds index budget.")

        required_chunks, projected_chars = project_chunk_allocation(
            canonical_chars=canonical_chars,
            max_chars=checked_chunk_policy.max_chars,
            overlap_chars=checked_chunk_policy.overlap_chars,
        )

        if (
            required_chunks > checked_chunk_policy.max_chunks
            or required_chunks > checked_policy.max_chunks
        ):
            raise IndexingError("Projected chunk count exceeds budget.")

        if projected_chars > checked_policy.max_total_chars:
            raise IndexingError("Projected index characters exceed budget.")

        if not within_amplification_budget(
            canonical_chars=canonical_chars,
            projected_chars=projected_chars,
        ):
            raise IndexingError("Projected index amplification exceeds limit.")

        chunks = chunk_csv_record(
            checked_snapshot,
            policy=checked_chunk_policy,
        )

        return build_csv_index(
            checked_snapshot,
            chunks,
            policy=checked_policy,
        )

    except IndexingError:
        raise
    except (AttributeError, TypeError, ValueError, OverflowError):
        raise IndexingError("Unable to build verified CSV index.") from None
