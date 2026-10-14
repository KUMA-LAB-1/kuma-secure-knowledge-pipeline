"""Bounded lexical retrieval from independently reverified CSV chunks."""

import json
import unicodedata
from dataclasses import dataclass

from kuma_secure_knowledge_pipeline.knowledge_budget import (
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
from kuma_secure_knowledge_pipeline.knowledge_evidence import (
    VerifiedSourceSnapshot,
)

_MAX_QUERY_CHARS = 256
_MAX_CANDIDATES = 1024
_MAX_RESULTS = 1024
_MAX_RESULT_CHARS = 4 * 1024 * 1024
_MAX_SOURCE_BYTES = 16 * 1024 * 1024


class RetrievalError(ValueError):
    """Retrieval cannot safely validate or satisfy the supplied corpus."""


@dataclass(frozen=True, slots=True, kw_only=True)
class RetrievalQuery:
    """Literal Unicode query with an explicit input budget."""

    text: str

    def __post_init__(self) -> None:
        if (
            type(self.text) is not str
            or not 1 <= len(self.text) <= _MAX_QUERY_CHARS
            or self.text != self.text.strip()
        ):
            raise ValueError("Invalid retrieval query.")

        if any(unicodedata.category(character) in {"Cc", "Cs", "Cf"} for character in self.text):
            raise ValueError("Retrieval query contains unsupported controls.")


@dataclass(frozen=True, slots=True, kw_only=True)
class RetrievalPolicy:
    """Bounded candidate validation and ranked-result budgets."""

    max_candidates: int
    max_results: int
    max_total_chars: int

    def __post_init__(self) -> None:
        if type(self.max_candidates) is not int or not 1 <= self.max_candidates <= _MAX_CANDIDATES:
            raise ValueError("Invalid candidate budget.")

        if (
            type(self.max_results) is not int
            or not 1 <= self.max_results <= _MAX_RESULTS
            or self.max_results > self.max_candidates
        ):
            raise ValueError("Invalid result budget.")

        if (
            type(self.max_total_chars) is not int
            or not 1 <= self.max_total_chars <= _MAX_RESULT_CHARS
        ):
            raise ValueError("Invalid result character budget.")


@dataclass(frozen=True, slots=True, kw_only=True)
class RetrievalHit:
    """One positively scored, source-bound knowledge chunk."""

    chunk: KnowledgeChunk
    score: int

    def __post_init__(self) -> None:
        if type(self.chunk) is not KnowledgeChunk:
            raise RetrievalError("Invalid retrieval hit chunk.")

        if type(self.score) is not int or self.score < 1:
            raise RetrievalError("Invalid retrieval score.")


@dataclass(frozen=True, slots=True, kw_only=True)
class RetrievalResult:
    """Immutable ranked hits with explicit completeness metadata."""

    query: RetrievalQuery
    hits: tuple[RetrievalHit, ...]
    total_matches: int
    truncated: bool

    def __post_init__(self) -> None:
        if type(self.query) is not RetrievalQuery:
            raise RetrievalError("Invalid result query.")

        if type(self.hits) is not tuple or any(type(hit) is not RetrievalHit for hit in self.hits):
            raise RetrievalError("Invalid result hits.")

        if type(self.total_matches) is not int or self.total_matches < len(self.hits):
            raise RetrievalError("Invalid match count.")

        if type(self.truncated) is not bool or self.truncated != (
            self.total_matches > len(self.hits)
        ):
            raise RetrievalError("Inconsistent truncation status.")

        ordering = tuple((-hit.score, hit.chunk.ordinal) for hit in self.hits)

        if ordering != tuple(sorted(ordering)):
            raise RetrievalError("Retrieval hits are not deterministically ranked.")


def _verify_corpus(
    snapshot: VerifiedSourceSnapshot,
    chunks: tuple[KnowledgeChunk, ...],
    *,
    policy: RetrievalPolicy,
) -> tuple[KnowledgeChunk, ...]:
    """Reconstruct and compare every chunk using verified source bytes."""
    if type(snapshot) is not VerifiedSourceSnapshot:
        raise RetrievalError("Invalid source snapshot.")

    if type(chunks) is not tuple or not chunks or len(chunks) > policy.max_candidates:
        raise RetrievalError("Invalid or oversized retrieval corpus.")

    if any(type(chunk) is not KnowledgeChunk for chunk in chunks):
        raise RetrievalError("Unsupported chunk type.")

    if (
        type(snapshot.content) is not bytes
        or not 1 <= len(snapshot.content) <= _MAX_SOURCE_BYTES
        or type(snapshot.locator) is not SourceLocator
        or snapshot.locator.kind != "csv_row"
    ):
        raise RetrievalError("Unsupported verified source.")

    try:
        original_policy = chunks[0].policy

        if type(original_policy) is not ChunkPolicy:
            raise RetrievalError("Invalid chunking policy.")

        checked_policy = ChunkPolicy(
            max_chars=original_policy.max_chars,
            overlap_chars=original_policy.overlap_chars,
            max_chunks=original_policy.max_chunks,
        )

        checked_locator = SourceLocator(
            artifact_id=snapshot.locator.artifact_id,
            source_sha256=snapshot.locator.source_sha256,
            kind=snapshot.locator.kind,
            page=snapshot.locator.page,
            region=snapshot.locator.region,
            record_index=snapshot.locator.record_index,
            record_id=snapshot.locator.record_id,
        )

        checked_snapshot = VerifiedSourceSnapshot(
            artifact=snapshot.artifact,
            locator=checked_locator,
            content=snapshot.content,
        )

        # Bound the verified canonical projection before chunk allocation.
        record = resolve_csv_record(checked_snapshot)
        canonical_chars = len(
            json.dumps(
                [[name, value] for name, value in record.fields],
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
            )
        )

        required_chunks, projected_chars = project_chunk_allocation(
            canonical_chars=canonical_chars,
            max_chars=checked_policy.max_chars,
            overlap_chars=checked_policy.overlap_chars,
        )

        if required_chunks > policy.max_candidates:
            raise RetrievalError("Projected retrieval corpus exceeds candidate budget.")

        if not within_amplification_budget(
            canonical_chars=canonical_chars,
            projected_chars=projected_chars,
        ):
            raise RetrievalError("Retrieval corpus amplification exceeds limit.")

        expected = chunk_csv_record(
            checked_snapshot,
            policy=checked_policy,
        )

        if len(expected) != len(chunks):
            raise RetrievalError("Retrieval corpus does not match source.")

        if len(expected) > policy.max_candidates:
            raise RetrievalError("Source exceeds retrieval candidate budget.")

        for supplied, verified in zip(chunks, expected, strict=True):
            if supplied != verified:
                raise RetrievalError("Retrieval chunk failed source verification.")

        return expected

    except Exception:
        raise RetrievalError("Unable to verify retrieval corpus.") from None


def retrieve_csv_chunks(
    snapshot: VerifiedSourceSnapshot,
    chunks: tuple[KnowledgeChunk, ...],
    *,
    query: RetrievalQuery,
    policy: RetrievalPolicy,
) -> RetrievalResult:
    """Search validated chunks by literal casefolded substring.

    A score counts nonoverlapping occurrences within one chunk. Overlap
    between chunks may repeat content; scores are not document-wide counts.
    Only a ranked prefix is returned when the output budget is exhausted.
    """
    if type(query) is not RetrievalQuery:
        raise RetrievalError("Invalid query contract.")

    if type(policy) is not RetrievalPolicy:
        raise RetrievalError("Invalid retrieval policy contract.")

    try:
        checked_query = RetrievalQuery(text=query.text)

        checked_policy = RetrievalPolicy(
            max_candidates=policy.max_candidates,
            max_results=policy.max_results,
            max_total_chars=policy.max_total_chars,
        )
    except Exception:
        raise RetrievalError("Invalid retrieval parameters.") from None

    verified_chunks = _verify_corpus(
        snapshot,
        chunks,
        policy=checked_policy,
    )

    needle = checked_query.text.casefold()
    ranked = []

    for chunk in verified_chunks:
        score = chunk.text.casefold().count(needle)

        if score:
            ranked.append(RetrievalHit(chunk=chunk, score=score))

    ranked.sort(key=lambda hit: (-hit.score, hit.chunk.ordinal))

    selected = []
    used_chars = 0

    for hit in ranked:
        candidate_size = len(hit.chunk.text)

        if (
            len(selected) >= checked_policy.max_results
            or used_chars + candidate_size > checked_policy.max_total_chars
        ):
            break

        selected.append(hit)
        used_chars += candidate_size

    return RetrievalResult(
        query=checked_query,
        hits=tuple(selected),
        total_matches=len(ranked),
        truncated=len(selected) < len(ranked),
    )
