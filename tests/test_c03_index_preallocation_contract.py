"""RED-first contracts for bounded CSV indexing before chunk allocation."""

import importlib

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


def _module():
    return importlib.import_module("kuma_secure_knowledge_pipeline.knowledge_index")


def _snapshot(tmp_path, *, value):
    path = tmp_path / "preallocation.csv"
    path.write_bytes(f"record_id,value\nDOC-0001,{value}\n".encode())

    artifact = build_source_artifact(path)
    locator = SourceLocator(
        artifact_id=artifact.artifact_id,
        source_sha256=artifact.sha256,
        kind="csv_row",
        record_index=1,
        record_id="DOC-0001",
    )
    return load_verified_source_snapshot(
        source_path=path,
        artifact=artifact,
        locator=locator,
    )


def test_safe_preallocation_path_builds_verified_index(tmp_path):
    module = _module()
    snapshot = _snapshot(tmp_path, value="alpha beta " * 12)

    chunk_policy = ChunkPolicy(
        max_chars=32,
        overlap_chars=4,
        max_chunks=256,
    )
    policy = module.IndexPolicy(
        max_chunks=256,
        max_total_chars=4096,
        max_source_bytes=4096,
    )

    expected = chunk_csv_record(snapshot, policy=chunk_policy)

    index = module.build_verified_csv_index(
        snapshot,
        chunk_policy=chunk_policy,
        policy=policy,
    )

    assert index.chunks == expected
    assert index.total_chars == sum(len(chunk.text) for chunk in expected)
    assert index.locator == snapshot.locator
    assert index.policy == policy


def test_extreme_amplification_rejected_before_chunk_creation(tmp_path, monkeypatch):
    module = _module()
    snapshot = _snapshot(tmp_path, value="A" * 5080)

    chunk_policy = ChunkPolicy(
        max_chars=4096,
        overlap_chars=4095,
        max_chunks=1024,
    )
    policy = module.IndexPolicy(
        max_chunks=1024,
        max_total_chars=4 * 1024 * 1024,
        max_source_bytes=16 * 1024 * 1024,
    )

    calls = []

    def forbidden_chunking(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("Chunk materialization occurred before rejection.")

    monkeypatch.setattr(module, "chunk_csv_record", forbidden_chunking)

    with pytest.raises(module.IndexingError):
        module.build_verified_csv_index(
            snapshot,
            chunk_policy=chunk_policy,
            policy=policy,
        )

    assert calls == []


def test_index_count_budget_rejected_before_chunk_creation(tmp_path, monkeypatch):
    module = _module()
    snapshot = _snapshot(tmp_path, value="A" * 300)

    chunk_policy = ChunkPolicy(
        max_chars=32,
        overlap_chars=4,
        max_chunks=256,
    )
    policy = module.IndexPolicy(
        max_chunks=1,
        max_total_chars=4096,
        max_source_bytes=4096,
    )

    calls = []

    def forbidden_chunking(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("Chunk materialization occurred before rejection.")

    monkeypatch.setattr(module, "chunk_csv_record", forbidden_chunking)

    with pytest.raises(module.IndexingError):
        module.build_verified_csv_index(
            snapshot,
            chunk_policy=chunk_policy,
            policy=policy,
        )

    assert calls == []
