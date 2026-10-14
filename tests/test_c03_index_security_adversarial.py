"""Permanent adversarial tests for preallocation CSV indexing."""

from unittest.mock import patch

import pytest

import kuma_secure_knowledge_pipeline.knowledge_index as module
from kuma_secure_knowledge_pipeline.artifacts import build_source_artifact
from kuma_secure_knowledge_pipeline.knowledge_chunks import ChunkPolicy
from kuma_secure_knowledge_pipeline.knowledge_contracts import SourceLocator
from kuma_secure_knowledge_pipeline.knowledge_evidence import (
    load_verified_source_snapshot,
)


def _snapshot(tmp_path, value):
    path = tmp_path / "security-case.csv"
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


def _chunk_policy(max_chars=32, overlap=4, count=256):
    return ChunkPolicy(
        max_chars=max_chars,
        overlap_chars=overlap,
        max_chunks=count,
    )


def _index_policy(count=256, chars=4096, source_bytes=4096):
    return module.IndexPolicy(
        max_chunks=count,
        max_total_chars=chars,
        max_source_bytes=source_bytes,
    )


def test_legitimate_source_is_accepted(tmp_path):
    source = _snapshot(tmp_path, "alpha beta " * 12)

    index = module.build_verified_csv_index(
        source,
        chunk_policy=_chunk_policy(),
        policy=_index_policy(),
    )

    assert index.locator == source.locator
    assert index.chunks
    assert index.total_chars == sum(len(chunk.text) for chunk in index.chunks)


def test_unicode_source_preserves_character_accounting(tmp_path):
    source = _snapshot(tmp_path, "é" * 150)

    assert len(source.content) > len(source.content.decode())

    index = module.build_verified_csv_index(
        source,
        chunk_policy=_chunk_policy(),
        policy=_index_policy(),
    )

    assert index.chunks
    assert index.total_chars == sum(len(chunk.text) for chunk in index.chunks)


@pytest.mark.parametrize(
    "scenario",
    [
        "tampered_source_bytes",
        "tampered_record_locator",
        "tampered_media_type",
        "tampered_index_policy",
        "tampered_chunk_policy",
        "insufficient_source_bytes",
        "projected_character_overflow",
        "pathological_amplification",
    ],
)
def test_unsafe_input_rejected_before_chunk_materialization(tmp_path, scenario):
    value = "alpha beta " * 12

    if scenario == "projected_character_overflow":
        value = "A" * 600
    elif scenario == "pathological_amplification":
        value = "A" * 5080

    source = _snapshot(tmp_path, value)
    chunk_policy = _chunk_policy()
    index_policy = _index_policy()

    if scenario == "tampered_source_bytes":
        altered = source.content.replace(b"alpha", b"gamma")
        assert altered != source.content
        object.__setattr__(source, "content", altered)

    elif scenario == "tampered_record_locator":
        object.__setattr__(
            source.locator,
            "record_id",
            "DOC-9999",
        )

    elif scenario == "tampered_media_type":
        object.__setattr__(
            source.artifact,
            "media_type",
            "application/octet-stream",
        )

    elif scenario == "tampered_index_policy":
        object.__setattr__(index_policy, "max_chunks", True)

    elif scenario == "tampered_chunk_policy":
        object.__setattr__(
            chunk_policy,
            "overlap_chars",
            chunk_policy.max_chars,
        )

    elif scenario == "insufficient_source_bytes":
        index_policy = _index_policy(
            source_bytes=len(source.content) - 1,
        )

    elif scenario == "projected_character_overflow":
        chunk_policy = _chunk_policy(
            max_chars=128,
            overlap=114,
            count=128,
        )
        index_policy = _index_policy(
            count=128,
            chars=4096,
            source_bytes=4096,
        )

    elif scenario == "pathological_amplification":
        chunk_policy = _chunk_policy(
            max_chars=4096,
            overlap=4095,
            count=1024,
        )
        index_policy = _index_policy(
            count=1024,
            chars=4 * 1024 * 1024,
            source_bytes=16 * 1024 * 1024,
        )

    with patch.object(
        module,
        "chunk_csv_record",
        side_effect=AssertionError("Chunk materialization occurred before rejection."),
    ) as materializer:
        with pytest.raises(module.IndexingError):
            module.build_verified_csv_index(
                source,
                chunk_policy=chunk_policy,
                policy=index_policy,
            )

        materializer.assert_not_called()
