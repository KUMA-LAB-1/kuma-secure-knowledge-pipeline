"""Evidence-bound, aggregate-budget index construction tests."""

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


def _index_module():
    return importlib.import_module("kuma_secure_knowledge_pipeline.knowledge_index")


def _corpus(
    tmp_path,
    *,
    filename="index.csv",
    value=None,
    max_chars=32,
    overlap_chars=4,
):
    if value is None:
        value = "alpha beta " * 12

    path = tmp_path / filename
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
            max_chunks=256,
        ),
    )

    return snapshot, chunks


def _policy(module, snapshot, chunks, **overrides):
    values = {
        "max_chunks": len(chunks),
        "max_total_chars": sum(len(chunk.text) for chunk in chunks),
        "max_source_bytes": len(snapshot.content),
    }
    values.update(overrides)
    return module.IndexPolicy(**values)


def test_build_index_is_deterministic_and_source_bound(tmp_path):
    module = _index_module()
    snapshot, chunks = _corpus(tmp_path)
    policy = _policy(module, snapshot, chunks)

    first = module.build_csv_index(snapshot, chunks, policy=policy)
    second = module.build_csv_index(snapshot, chunks, policy=policy)

    assert first == second
    assert first.chunks == chunks
    assert first.policy == policy
    assert first.source_sha256 == snapshot.artifact.sha256
    assert first.locator == snapshot.locator
    assert first.total_chars == sum(len(chunk.text) for chunk in chunks)


def test_index_rejects_aggregate_overlap_amplification(tmp_path):
    module = _index_module()

    snapshot, chunks = _corpus(
        tmp_path,
        value="alpha beta " * 8,
        max_chars=32,
        overlap_chars=31,
    )

    total_chars = sum(len(chunk.text) for chunk in chunks)

    assert len(chunks) > 5
    assert total_chars > len(snapshot.content)

    policy = _policy(
        module,
        snapshot,
        chunks,
        max_total_chars=total_chars - 1,
    )

    with pytest.raises(module.IndexingError):
        module.build_csv_index(snapshot, chunks, policy=policy)


def test_index_rejects_chunk_count_over_budget(tmp_path):
    module = _index_module()
    snapshot, chunks = _corpus(tmp_path)

    assert len(chunks) > 1

    policy = _policy(
        module,
        snapshot,
        chunks,
        max_chunks=len(chunks) - 1,
    )

    with pytest.raises(module.IndexingError):
        module.build_csv_index(snapshot, chunks, policy=policy)


def test_index_rejects_source_byte_budget(tmp_path):
    module = _index_module()
    snapshot, chunks = _corpus(tmp_path)

    policy = _policy(
        module,
        snapshot,
        chunks,
        max_source_bytes=len(snapshot.content) - 1,
    )

    with pytest.raises(module.IndexingError):
        module.build_csv_index(snapshot, chunks, policy=policy)


def test_index_rejects_chunks_from_another_source(tmp_path):
    module = _index_module()

    snapshot, chunks = _corpus(tmp_path, filename="original.csv")
    _, foreign_chunks = _corpus(
        tmp_path,
        filename="foreign.csv",
        value="other content beta gamma",
    )

    policy = _policy(module, snapshot, chunks)

    with pytest.raises(module.IndexingError):
        module.build_csv_index(snapshot, foreign_chunks, policy=policy)


@pytest.mark.parametrize("alteration", ["duplicate", "missing", "reordered"])
def test_index_rejects_noncanonical_corpus(tmp_path, alteration):
    module = _index_module()
    snapshot, chunks = _corpus(tmp_path)

    assert len(chunks) > 1

    if alteration == "duplicate":
        supplied = chunks + (chunks[0],)
    elif alteration == "missing":
        supplied = chunks[:-1]
    else:
        supplied = tuple(reversed(chunks))

    canonical_total = sum(len(chunk.text) for chunk in chunks)
    supplied_total = sum(len(chunk.text) for chunk in supplied)

    policy = _policy(
        module,
        snapshot,
        chunks,
        max_chunks=256,
        max_total_chars=max(canonical_total, supplied_total),
    )

    # Verify rejection reaches source comparison rather than budget limits.
    assert len(supplied) <= policy.max_chunks
    assert supplied_total <= policy.max_total_chars

    with pytest.raises(
        module.IndexingError,
        match=r"^Index corpus does not match verified source[.]$",
    ):
        module.build_csv_index(snapshot, supplied, policy=policy)


def test_index_rejects_tampered_frozen_chunk(tmp_path):
    module = _index_module()
    snapshot, chunks = _corpus(tmp_path)
    policy = _policy(module, snapshot, chunks)

    original = chunks[0].text
    replacement = ("X" if original[0] != "X" else "Y") + original[1:]

    object.__setattr__(chunks[0], "text", replacement)

    with pytest.raises(module.IndexingError):
        module.build_csv_index(snapshot, chunks, policy=policy)


def test_index_rejects_tampered_source_snapshot(tmp_path):
    module = _index_module()
    snapshot, chunks = _corpus(tmp_path)

    policy = module.IndexPolicy(
        max_chunks=256,
        max_total_chars=4096,
        max_source_bytes=4096,
    )

    object.__setattr__(
        snapshot,
        "content",
        b"record_id,value\nDOC-0001,forged\n",
    )

    with pytest.raises(module.IndexingError):
        module.build_csv_index(snapshot, chunks, policy=policy)


def test_index_revalidates_mutated_policy(tmp_path):
    module = _index_module()
    snapshot, chunks = _corpus(tmp_path)
    policy = _policy(module, snapshot, chunks)

    object.__setattr__(policy, "max_total_chars", 4 * 1024 * 1024 + 1)

    with pytest.raises(module.IndexingError):
        module.build_csv_index(snapshot, chunks, policy=policy)


@pytest.mark.parametrize("invalid_chunks", [(), [], None])
def test_index_rejects_invalid_corpus_container(tmp_path, invalid_chunks):
    module = _index_module()
    snapshot, chunks = _corpus(tmp_path)
    policy = _policy(module, snapshot, chunks)

    with pytest.raises(module.IndexingError):
        module.build_csv_index(snapshot, invalid_chunks, policy=policy)
