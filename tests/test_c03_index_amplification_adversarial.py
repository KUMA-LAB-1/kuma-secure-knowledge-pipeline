"""Adversarial amplification tests for evidence-bound CSV indexing."""

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


def _case(tmp_path, *, size, max_chars, overlap_chars, max_chunks):
    value = "A" * size
    path = tmp_path / "amplification.csv"
    path.write_bytes(f"record_id,value\nDOC-0001,{value}\n".encode())

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
            overlap_chars=overlap_chars,
            max_chunks=max_chunks,
        ),
    )
    canonical = json.dumps(
        [["record_id", "DOC-0001"], ["value", value]],
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    )
    return snapshot, chunks, len(canonical)


def _policy():
    return IndexPolicy(
        max_chunks=1024,
        max_total_chars=4 * 1024 * 1024,
        max_source_bytes=16 * 1024 * 1024,
    )


def test_reasonable_overlap_remains_accepted(tmp_path):
    snapshot, chunks, canonical_chars = _case(
        tmp_path,
        size=600,
        max_chars=128,
        overlap_chars=32,
        max_chunks=32,
    )
    total = sum(len(chunk.text) for chunk in chunks)
    ratio = total / canonical_chars

    assert 1 < ratio < 2

    index = build_csv_index(snapshot, chunks, policy=_policy())

    assert index.chunks == chunks
    assert index.total_chars == total


def test_pathological_overlap_is_rejected_despite_absolute_budgets(tmp_path):
    snapshot, chunks, canonical_chars = _case(
        tmp_path,
        size=5080,
        max_chars=4096,
        overlap_chars=4095,
        max_chunks=1024,
    )
    total = sum(len(chunk.text) for chunk in chunks)

    assert canonical_chars == 5119
    assert len(chunks) == 1024
    assert total == 4 * 1024 * 1024
    assert total / canonical_chars > 800

    with pytest.raises(IndexingError):
        build_csv_index(snapshot, chunks, policy=_policy())


def test_amplification_below_eightfold_remains_accepted(tmp_path):
    snapshot, chunks, canonical_chars = _case(
        tmp_path,
        size=600,
        max_chars=128,
        overlap_chars=114,
        max_chunks=128,
    )
    total = sum(len(chunk.text) for chunk in chunks)

    assert 7 < total / canonical_chars < 8

    index = build_csv_index(snapshot, chunks, policy=_policy())

    assert index.total_chars == total
    assert index.chunks == chunks


def test_amplification_above_eightfold_is_rejected(tmp_path):
    snapshot, chunks, canonical_chars = _case(
        tmp_path,
        size=600,
        max_chars=128,
        overlap_chars=115,
        max_chunks=128,
    )
    total = sum(len(chunk.text) for chunk in chunks)

    assert 8 < total / canonical_chars < 9

    with pytest.raises(IndexingError):
        build_csv_index(snapshot, chunks, policy=_policy())
