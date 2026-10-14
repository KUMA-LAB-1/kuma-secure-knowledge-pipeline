"""Adversarial contract for proportional retrieval corpus budgets."""

import json

import pytest

from kuma_secure_knowledge_pipeline.artifacts import build_source_artifact
from kuma_secure_knowledge_pipeline.knowledge_chunks import (
    ChunkPolicy,
    chunk_csv_record,
)
from kuma_secure_knowledge_pipeline.knowledge_contracts import SourceLocator
from kuma_secure_knowledge_pipeline.knowledge_evidence import (
    load_verified_source_snapshot,
)
from kuma_secure_knowledge_pipeline.knowledge_index import (
    IndexingError,
    IndexPolicy,
    build_csv_index,
)
from kuma_secure_knowledge_pipeline.knowledge_retrieval import (
    RetrievalError,
    RetrievalPolicy,
    RetrievalQuery,
    retrieve_csv_chunks,
)


def _case(tmp_path, *, overlap_chars):
    path = tmp_path / "retrieval-amplification.csv"
    path.write_bytes(b"record_id,value\nDOC-0001," + b"A" * 600 + b"\n")

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
            max_chars=128,
            overlap_chars=overlap_chars,
            max_chunks=128,
        ),
    )

    canonical = json.dumps(
        [["record_id", "DOC-0001"], ["value", "A" * 600]],
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    )

    ratio = sum(len(chunk.text) for chunk in chunks) / len(canonical)

    index_policy = IndexPolicy(
        max_chunks=128,
        max_total_chars=8192,
        max_source_bytes=4096,
    )

    retrieval_policy = RetrievalPolicy(
        max_candidates=128,
        max_results=4,
        max_total_chars=512,
    )

    return snapshot, chunks, ratio, index_policy, retrieval_policy


def test_retrieval_accepts_corpus_below_amplification_limit(tmp_path):
    snapshot, chunks, ratio, index_policy, retrieval_policy = _case(
        tmp_path,
        overlap_chars=114,
    )

    assert len(chunks) == 38
    assert 7 < ratio < 8

    index = build_csv_index(snapshot, chunks, policy=index_policy)
    assert index.chunks == chunks

    result = retrieve_csv_chunks(
        snapshot,
        chunks,
        query=RetrievalQuery(text="AAAA"),
        policy=retrieval_policy,
    )

    assert result.hits
    assert len(result.hits) <= 4


def test_retrieval_rejects_corpus_above_amplification_limit(tmp_path):
    snapshot, chunks, ratio, index_policy, retrieval_policy = _case(
        tmp_path,
        overlap_chars=115,
    )

    assert len(chunks) == 41
    assert 8 < ratio < 9

    with pytest.raises(IndexingError):
        build_csv_index(snapshot, chunks, policy=index_policy)

    with pytest.raises(RetrievalError):
        retrieve_csv_chunks(
            snapshot,
            chunks,
            query=RetrievalQuery(text="AAAA"),
            policy=retrieval_policy,
        )
