"""Verified source snapshots: real bytes and fail-closed boundaries."""

from dataclasses import FrozenInstanceError, replace

import pytest

from kuma_secure_knowledge_pipeline.artifacts import build_source_artifact
from kuma_secure_knowledge_pipeline.knowledge_contracts import SourceLocator
from kuma_secure_knowledge_pipeline.knowledge_evidence import (
    load_verified_source_snapshot,
)


def _source(
    tmp_path,
    *,
    filename="vendas.csv",
    content=b"opportunity_id,value\nOPP-0001,100\n",
):
    path = tmp_path / filename
    path.write_bytes(content)

    artifact = build_source_artifact(path)

    locator = SourceLocator(
        artifact_id=artifact.artifact_id,
        source_sha256=artifact.sha256,
        kind="csv_row",
        record_index=1,
        record_id="OPP-0001",
    )

    return path, artifact, locator, content


def test_snapshot_binds_verified_real_bytes(tmp_path):
    path, artifact, locator, expected = _source(tmp_path)

    snapshot = load_verified_source_snapshot(
        source_path=path,
        artifact=artifact,
        locator=locator,
    )

    assert snapshot.content == expected
    assert snapshot.artifact == artifact
    assert snapshot.locator == locator


def test_rejects_same_size_tampering(tmp_path):
    path, artifact, locator, original = _source(tmp_path)

    changed = original.replace(b"100", b"900")

    assert len(changed) == len(original)
    assert changed != original

    path.write_bytes(changed)

    with pytest.raises(ValueError):
        load_verified_source_snapshot(
            source_path=path,
            artifact=artifact,
            locator=locator,
        )


def test_rejects_foreign_source_locator(tmp_path):
    path, artifact, _, _ = _source(tmp_path)

    _, _, foreign_locator, _ = _source(
        tmp_path,
        filename="outro.csv",
        content=b"opportunity_id,value\nOPP-0001,999\n",
    )

    with pytest.raises(ValueError):
        load_verified_source_snapshot(
            source_path=path,
            artifact=artifact,
            locator=foreign_locator,
        )


def test_rejects_forged_artifact_metadata(tmp_path):
    path, artifact, locator, _ = _source(tmp_path)

    forged = replace(
        artifact,
        artifact_id="sha256-" + "b" * 64,
    )

    with pytest.raises(ValueError):
        load_verified_source_snapshot(
            source_path=path,
            artifact=forged,
            locator=locator,
        )


def test_rejects_missing_source(tmp_path):
    path, artifact, locator, _ = _source(tmp_path)

    path.unlink()

    with pytest.raises(ValueError):
        load_verified_source_snapshot(
            source_path=path,
            artifact=artifact,
            locator=locator,
        )


def test_rejects_oversized_source(tmp_path):
    path, artifact, locator, content = _source(tmp_path)

    with pytest.raises(ValueError):
        load_verified_source_snapshot(
            source_path=path,
            artifact=artifact,
            locator=locator,
            max_bytes=len(content) - 1,
        )


@pytest.mark.parametrize(
    "bad_limit",
    [None, True, 0, -1, 1.0, "1024"],
)
def test_rejects_invalid_byte_limit(tmp_path, bad_limit):
    path, artifact, locator, _ = _source(tmp_path)

    with pytest.raises(ValueError):
        load_verified_source_snapshot(
            source_path=path,
            artifact=artifact,
            locator=locator,
            max_bytes=bad_limit,
        )


def test_snapshot_is_immutable(tmp_path):
    path, artifact, locator, _ = _source(tmp_path)

    snapshot = load_verified_source_snapshot(
        source_path=path,
        artifact=artifact,
        locator=locator,
    )

    with pytest.raises(FrozenInstanceError):
        snapshot.content = b"modified"
