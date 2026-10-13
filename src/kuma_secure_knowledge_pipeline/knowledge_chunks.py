"""Deterministic knowledge chunks bound to verified CSV evidence."""

import hashlib
import json
from dataclasses import dataclass

from kuma_secure_knowledge_pipeline.knowledge_contracts import SourceLocator
from kuma_secure_knowledge_pipeline.knowledge_csv import resolve_csv_record
from kuma_secure_knowledge_pipeline.knowledge_evidence import VerifiedSourceSnapshot

_MAX_CHARS = 4096
_MAX_CHUNKS = 1024
_MAX_CANONICAL_CHARS = 4 * 1024 * 1024
_ID_VERSION = "kuma-knowledge-chunk-v1"


class ChunkingError(ValueError):
    """The chunking input or resource policy cannot be satisfied."""


@dataclass(frozen=True, slots=True, kw_only=True)
class ChunkPolicy:
    """Bounded deterministic character-based segmentation policy."""

    max_chars: int
    overlap_chars: int
    max_chunks: int

    def __post_init__(self) -> None:
        if type(self.max_chars) is not int or not 1 <= self.max_chars <= _MAX_CHARS:
            raise ValueError("Invalid maximum chunk length.")

        if type(self.overlap_chars) is not int or not 0 <= self.overlap_chars < self.max_chars:
            raise ValueError("Invalid chunk overlap.")

        if type(self.max_chunks) is not int or not 1 <= self.max_chunks <= _MAX_CHUNKS:
            raise ValueError("Invalid maximum chunk count.")


def _chunk_digest(
    *,
    locator: SourceLocator,
    policy: ChunkPolicy,
    ordinal: int,
    start: int,
    end: int,
    text: str,
) -> str:
    """Hash versioned, unambiguous fields in a fixed order."""
    payload = [
        _ID_VERSION,
        locator.artifact_id,
        locator.source_sha256,
        locator.kind,
        locator.page,
        locator.region,
        locator.record_index,
        locator.record_id,
        policy.max_chars,
        policy.overlap_chars,
        policy.max_chunks,
        ordinal,
        start,
        end,
        text,
    ]

    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")

    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True, kw_only=True)
class KnowledgeChunk:
    """Immutable, locally self-checking chunk identity and source locator.

    A valid identifier does not independently prove external source
    authenticity or that generated text is factually correct.
    """

    chunk_id: str
    artifact_id: str
    source_sha256: str
    locator: SourceLocator
    policy: ChunkPolicy
    ordinal: int
    start: int
    end: int
    text: str

    def __post_init__(self) -> None:
        if type(self.locator) is not SourceLocator:
            raise ChunkingError("Invalid source locator.")

        if type(self.policy) is not ChunkPolicy:
            raise ChunkingError("Invalid chunk policy.")

        if (
            type(self.artifact_id) is not str
            or type(self.source_sha256) is not str
            or self.artifact_id != self.locator.artifact_id
            or self.source_sha256 != self.locator.source_sha256
        ):
            raise ChunkingError("Chunk source identity mismatch.")

        if type(self.ordinal) is not int or not 0 <= self.ordinal < self.policy.max_chunks:
            raise ChunkingError("Invalid chunk ordinal.")

        if (
            type(self.start) is not int
            or type(self.end) is not int
            or not 0 <= self.start < self.end
        ):
            raise ChunkingError("Invalid chunk offsets.")

        if (
            type(self.text) is not str
            or not self.text
            or len(self.text) != self.end - self.start
            or len(self.text) > self.policy.max_chars
        ):
            raise ChunkingError("Invalid chunk content or length.")

        try:
            self.text.encode("utf-8")
        except UnicodeEncodeError:
            raise ChunkingError("Invalid Unicode in chunk text.") from None

        expected_id = _chunk_digest(
            locator=self.locator,
            policy=self.policy,
            ordinal=self.ordinal,
            start=self.start,
            end=self.end,
            text=self.text,
        )

        if type(self.chunk_id) is not str or self.chunk_id != expected_id:
            raise ChunkingError("Chunk identifier mismatch.")


def chunk_csv_record(
    snapshot: VerifiedSourceSnapshot,
    *,
    policy: ChunkPolicy,
) -> tuple[KnowledgeChunk, ...]:
    """Chunk one verified CSV record without changing source text.

    Offsets refer to Python Unicode code points in the canonical JSON
    projection, not byte positions in the original CSV file.
    """
    if not isinstance(snapshot, VerifiedSourceSnapshot):
        raise ChunkingError("Invalid verified source snapshot.")

    if type(policy) is not ChunkPolicy:
        raise ChunkingError("Invalid chunk policy.")

    record = resolve_csv_record(snapshot)

    canonical = json.dumps(
        [[name, value] for name, value in record.fields],
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    )

    total = len(canonical)

    if not 1 <= total <= _MAX_CANONICAL_CHARS:
        raise ChunkingError("Canonical record exceeds character limit.")

    stride = policy.max_chars - policy.overlap_chars

    if total <= policy.max_chars:
        required = 1
    else:
        remaining = total - policy.max_chars
        required = 1 + (remaining + stride - 1) // stride

    if required > policy.max_chunks:
        raise ChunkingError("Required chunk count exceeds policy.")

    chunks = []

    for ordinal in range(required):
        start = ordinal * stride
        end = min(start + policy.max_chars, total)
        text = canonical[start:end]

        chunk = KnowledgeChunk(
            chunk_id=_chunk_digest(
                locator=snapshot.locator,
                policy=policy,
                ordinal=ordinal,
                start=start,
                end=end,
                text=text,
            ),
            artifact_id=record.artifact_id,
            source_sha256=record.source_sha256,
            locator=snapshot.locator,
            policy=policy,
            ordinal=ordinal,
            start=start,
            end=end,
            text=text,
        )

        chunks.append(chunk)

    return tuple(chunks)
