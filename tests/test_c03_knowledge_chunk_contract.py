"""Contract-first tests for deterministic, provenance-bound CSV chunks."""

import json
import re
from dataclasses import FrozenInstanceError

import pytest

from kuma_secure_knowledge_pipeline.artifacts import build_source_artifact
from kuma_secure_knowledge_pipeline.knowledge_chunks import (
    ChunkingError,
    ChunkPolicy,
    KnowledgeChunk,
    chunk_csv_record,
)
from kuma_secure_knowledge_pipeline.knowledge_contracts import SourceLocator
from kuma_secure_knowledge_pipeline.knowledge_evidence import (
    load_verified_source_snapshot,
)


def _snapshot(tmp_path, value="Ol\u00e1 \U0001f30d", *, content=None):
    if content is None:
        content = f"record_id,value\nDOC-0001,{value}\n".encode()

    path = tmp_path / "synthetic.csv"
    path.write_bytes(content)

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


def _canonical(value="Ol\u00e1 \U0001f30d"):
    fields = [
        ["record_id", "DOC-0001"],
        ["value", value],
    ]
    return json.dumps(
        fields,
        ensure_ascii=False,
        separators=(",", ":"),
    )


def test_policy_is_immutable():
    policy = ChunkPolicy(
        max_chars=32,
        overlap_chars=4,
        max_chunks=16,
    )

    assert policy.max_chars == 32
    assert policy.overlap_chars == 4
    assert policy.max_chunks == 16

    with pytest.raises(FrozenInstanceError):
        policy.max_chars = 64


@pytest.mark.parametrize(
    "values",
    [
        {"max_chars": True, "overlap_chars": 0, "max_chunks": 4},
        {"max_chars": 0, "overlap_chars": 0, "max_chunks": 4},
        {"max_chars": 4097, "overlap_chars": 0, "max_chunks": 4},
        {"max_chars": 32, "overlap_chars": -1, "max_chunks": 4},
        {"max_chars": 32, "overlap_chars": 32, "max_chunks": 4},
        {"max_chars": 32, "overlap_chars": 1.0, "max_chunks": 4},
        {"max_chars": 32, "overlap_chars": 0, "max_chunks": False},
        {"max_chars": 32, "overlap_chars": 0, "max_chunks": 0},
        {"max_chars": 32, "overlap_chars": 0, "max_chunks": 1025},
    ],
)
def test_rejects_invalid_chunk_policy(values):
    with pytest.raises((ValueError, TypeError)):
        ChunkPolicy(**values)


def test_csv_chunks_bind_to_verified_locator(tmp_path):
    snapshot = _snapshot(tmp_path)

    chunks = chunk_csv_record(
        snapshot,
        policy=ChunkPolicy(
            max_chars=16,
            overlap_chars=4,
            max_chunks=16,
        ),
    )

    assert chunks
    assert isinstance(chunks, tuple)

    for index, chunk in enumerate(chunks):
        assert isinstance(chunk, KnowledgeChunk)
        assert chunk.locator == snapshot.locator
        assert chunk.artifact_id == snapshot.artifact.artifact_id
        assert chunk.source_sha256 == snapshot.artifact.sha256
        assert chunk.ordinal == index
        assert re.fullmatch(r"[0-9a-f]{64}", chunk.chunk_id)


def test_chunks_have_exact_offsets_and_full_coverage(tmp_path):
    snapshot = _snapshot(tmp_path)
    expected = _canonical()

    chunks = chunk_csv_record(
        snapshot,
        policy=ChunkPolicy(
            max_chars=12,
            overlap_chars=3,
            max_chunks=32,
        ),
    )

    assert chunks[0].start == 0
    assert chunks[-1].end == len(expected)

    for chunk in chunks:
        assert 0 <= chunk.start < chunk.end <= len(expected)
        assert chunk.text == expected[chunk.start : chunk.end]
        assert len(chunk.text) <= 12

    for left, right in zip(chunks, chunks[1:], strict=False):
        assert right.start == left.end - 3

    reconstructed = chunks[0].text + "".join(chunk.text[3:] for chunk in chunks[1:])
    assert reconstructed == expected


def test_chunk_generation_is_deterministic(tmp_path):
    snapshot = _snapshot(tmp_path)
    policy = ChunkPolicy(
        max_chars=16,
        overlap_chars=4,
        max_chunks=32,
    )

    first = chunk_csv_record(snapshot, policy=policy)
    second = chunk_csv_record(snapshot, policy=policy)

    assert first == second


def test_source_content_change_changes_chunk_identity(tmp_path):
    first = _snapshot(tmp_path, value="Alpha")
    second = _snapshot(tmp_path, value="Bravo")

    policy = ChunkPolicy(
        max_chars=64,
        overlap_chars=0,
        max_chunks=8,
    )

    first_chunks = chunk_csv_record(first, policy=policy)
    second_chunks = chunk_csv_record(second, policy=policy)

    assert first_chunks[0].chunk_id != second_chunks[0].chunk_id
    assert first_chunks[0].source_sha256 != second_chunks[0].source_sha256


def test_policy_change_changes_chunk_identity(tmp_path):
    snapshot = _snapshot(tmp_path)

    first = chunk_csv_record(
        snapshot,
        policy=ChunkPolicy(
            max_chars=64,
            overlap_chars=0,
            max_chunks=8,
        ),
    )
    second = chunk_csv_record(
        snapshot,
        policy=ChunkPolicy(
            max_chars=65,
            overlap_chars=0,
            max_chunks=8,
        ),
    )

    assert first[0].text == second[0].text
    assert first[0].chunk_id != second[0].chunk_id


def test_rejects_chunk_count_over_budget(tmp_path):
    snapshot = _snapshot(tmp_path, value="A" * 200)

    with pytest.raises(ChunkingError):
        chunk_csv_record(
            snapshot,
            policy=ChunkPolicy(
                max_chars=16,
                overlap_chars=4,
                max_chunks=2,
            ),
        )


def test_rejects_invalid_csv_even_after_target_record(tmp_path):
    snapshot = _snapshot(
        tmp_path,
        content=(b"record_id,value\nDOC-0001,valid\nDOC-0001,duplicate\n"),
    )

    with pytest.raises(ValueError):
        chunk_csv_record(
            snapshot,
            policy=ChunkPolicy(
                max_chars=32,
                overlap_chars=0,
                max_chunks=8,
            ),
        )


def test_preserves_unicode_without_normalization(tmp_path):
    value = "Cafe\u0301 \U0001f30d"
    snapshot = _snapshot(tmp_path, value=value)

    chunks = chunk_csv_record(
        snapshot,
        policy=ChunkPolicy(
            max_chars=14,
            overlap_chars=2,
            max_chunks=32,
        ),
    )

    reconstructed = chunks[0].text + "".join(chunk.text[2:] for chunk in chunks[1:])

    assert reconstructed == _canonical(value)
    assert "e\u0301" in reconstructed


def test_chunk_is_immutable(tmp_path):
    snapshot = _snapshot(tmp_path)

    chunk = chunk_csv_record(
        snapshot,
        policy=ChunkPolicy(
            max_chars=64,
            overlap_chars=0,
            max_chunks=8,
        ),
    )[0]

    with pytest.raises(FrozenInstanceError):
        chunk.text = "tampered"


def test_rejects_non_snapshot():
    with pytest.raises((ChunkingError, ValueError, TypeError)):
        chunk_csv_record(
            object(),
            policy=ChunkPolicy(
                max_chars=32,
                overlap_chars=0,
                max_chunks=8,
            ),
        )
