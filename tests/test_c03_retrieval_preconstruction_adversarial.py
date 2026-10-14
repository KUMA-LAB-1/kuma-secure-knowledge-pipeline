"""Ensure retrieval amplification is rejected before chunk reconstruction."""

import json
from unittest.mock import patch

import pytest

import kuma_secure_knowledge_pipeline.knowledge_retrieval as retrieval
from kuma_secure_knowledge_pipeline.artifacts import build_source_artifact
from kuma_secure_knowledge_pipeline.knowledge_chunks import (
    ChunkPolicy,
    chunk_csv_record,
)
from kuma_secure_knowledge_pipeline.knowledge_contracts import SourceLocator
from kuma_secure_knowledge_pipeline.knowledge_evidence import (
    load_verified_source_snapshot,
)


def _case(
    tmp_path,
    *,
    value_size,
    max_chars,
    overlap,
    max_chunks,
):
    path = tmp_path / "preconstruction.csv"
    path.write_bytes(b"record_id,value\nDOC-0001," + b"A" * value_size + b"\n")

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
            max_chars=max_chars,
            overlap_chars=overlap,
            max_chunks=max_chunks,
        ),
    )

    canonical = json.dumps(
        [
            ["record_id", "DOC-0001"],
            ["value", "A" * value_size],
        ],
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    )

    canonical_chars = len(canonical)
    aggregate_chars = sum(len(chunk.text) for chunk in chunks)

    policy = retrieval.RetrievalPolicy(
        max_candidates=max_chunks,
        max_results=4,
        max_total_chars=512,
    )

    query = retrieval.RetrievalQuery(text="AAAA")

    return (
        snapshot,
        chunks,
        canonical_chars,
        aggregate_chars,
        query,
        policy,
    )


def test_legitimate_corpus_reconstructs_exactly_once(tmp_path):
    (
        snapshot,
        chunks,
        canonical_chars,
        aggregate_chars,
        query,
        policy,
    ) = _case(
        tmp_path,
        value_size=600,
        max_chars=128,
        overlap=114,
        max_chunks=128,
    )

    assert canonical_chars == 639
    assert len(chunks) == 38
    assert aggregate_chars == 4857
    assert aggregate_chars <= 8 * canonical_chars

    with patch.object(
        retrieval,
        "chunk_csv_record",
        wraps=retrieval.chunk_csv_record,
    ) as materializer:
        result = retrieval.retrieve_csv_chunks(
            snapshot,
            chunks,
            query=query,
            policy=policy,
        )

        assert result.hits
        materializer.assert_called_once()


@pytest.mark.parametrize(
    (
        "value_size",
        "max_chars",
        "overlap",
        "max_chunks",
        "expected_chunks",
        "expected_canonical",
        "expected_aggregate",
    ),
    [
        (600, 128, 115, 128, 41, 639, 5239),
        (5080, 4096, 4095, 1024, 1024, 5119, 4194304),
    ],
    ids=["amplification-8x", "amplification-819x"],
)
def test_unsafe_corpus_rejected_without_reconstruction(
    tmp_path,
    value_size,
    max_chars,
    overlap,
    max_chunks,
    expected_chunks,
    expected_canonical,
    expected_aggregate,
):
    (
        snapshot,
        chunks,
        canonical_chars,
        aggregate_chars,
        query,
        policy,
    ) = _case(
        tmp_path,
        value_size=value_size,
        max_chars=max_chars,
        overlap=overlap,
        max_chunks=max_chunks,
    )

    assert len(chunks) == expected_chunks
    assert canonical_chars == expected_canonical
    assert aggregate_chars == expected_aggregate
    assert aggregate_chars > 8 * canonical_chars

    with patch.object(
        retrieval,
        "chunk_csv_record",
        side_effect=AssertionError("Premature retrieval reconstruction."),
    ) as materializer:
        with pytest.raises(retrieval.RetrievalError):
            retrieval.retrieve_csv_chunks(
                snapshot,
                chunks,
                query=query,
                policy=policy,
            )

        materializer.assert_not_called()
