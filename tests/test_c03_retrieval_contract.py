"""RED-first contract for evidence-bound lexical knowledge retrieval."""

import importlib

from kuma_secure_knowledge_pipeline.artifacts import build_source_artifact
from kuma_secure_knowledge_pipeline.knowledge_chunks import (
    ChunkPolicy,
    KnowledgeChunk,
    chunk_csv_record,
)
from kuma_secure_knowledge_pipeline.knowledge_contracts import SourceLocator
from kuma_secure_knowledge_pipeline.knowledge_evidence import (
    load_verified_source_snapshot,
)


def test_retrieval_returns_verified_hits_deterministically(tmp_path):
    """Matches must retain original chunks and verified CSV provenance."""
    retrieval = importlib.import_module("kuma_secure_knowledge_pipeline.knowledge_retrieval")

    path = tmp_path / "retrieval.csv"
    path.write_bytes(b"record_id,value\nDOC-0001,Alpha alpha ALPHA beta\n")

    artifact = build_source_artifact(path)

    locator = SourceLocator(
        artifact_id=artifact.artifact_id,
        source_sha256=artifact.sha256,
        kind="csv_row",
        record_index=1,
        record_id="DOC-0001",
    )

    snapshot = load_verified_source_snapshot(
        source_path=path,
        artifact=artifact,
        locator=locator,
    )

    chunks = chunk_csv_record(
        snapshot,
        policy=ChunkPolicy(
            max_chars=24,
            overlap_chars=4,
            max_chunks=64,
        ),
    )

    query = retrieval.RetrievalQuery(text="alpha")
    policy = retrieval.RetrievalPolicy(
        max_candidates=64,
        max_results=8,
        max_total_chars=4096,
    )

    first = retrieval.retrieve_csv_chunks(
        snapshot,
        chunks,
        query=query,
        policy=policy,
    )

    second = retrieval.retrieve_csv_chunks(
        snapshot,
        chunks,
        query=query,
        policy=policy,
    )

    assert first == second
    assert first.query == query
    assert first.hits
    assert isinstance(first.hits, tuple)
    assert first.total_matches >= len(first.hits)
    assert first.truncated is False

    expected_chunks = set(chunks)

    for hit in first.hits:
        assert isinstance(hit.chunk, KnowledgeChunk)
        assert hit.chunk in expected_chunks
        assert hit.chunk.source_sha256 == snapshot.artifact.sha256
        assert hit.chunk.locator == snapshot.locator
        assert hit.score > 0
        assert query.text.casefold() in hit.chunk.text.casefold()

    ordering = [(-hit.score, hit.chunk.ordinal) for hit in first.hits]

    assert ordering == sorted(ordering)
