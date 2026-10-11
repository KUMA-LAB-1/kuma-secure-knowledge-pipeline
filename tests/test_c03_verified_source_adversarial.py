"""Adversarial tests for verified, immutable source snapshots."""

from dataclasses import replace

import pytest

from kuma_secure_knowledge_pipeline.artifacts import build_source_artifact
from kuma_secure_knowledge_pipeline.knowledge_contracts import SourceLocator
from kuma_secure_knowledge_pipeline.knowledge_evidence import (
    VerifiedSourceSnapshot,
    load_verified_source_snapshot,
)


def _fixture(tmp_path):
    path = tmp_path / "vendas.csv"
    content = b"opportunity_id,value\nOPP-0001,100\n"
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


def test_snapshot_preserves_bytes_after_source_rewrite(tmp_path):
    path, artifact, locator, original = _fixture(tmp_path)

    snapshot = load_verified_source_snapshot(
        source_path=path,
        artifact=artifact,
        locator=locator,
    )

    path.write_bytes(original.replace(b"100", b"900"))

    assert snapshot.content == original


def test_snapshot_preserves_bytes_after_source_deletion(tmp_path):
    path, artifact, locator, original = _fixture(tmp_path)

    snapshot = load_verified_source_snapshot(
        source_path=path,
        artifact=artifact,
        locator=locator,
    )

    path.unlink()

    assert snapshot.content == original


def test_rejects_direct_snapshot_with_forged_bytes(tmp_path):
    _, artifact, locator, original = _fixture(tmp_path)

    forged = original.replace(b"100", b"900")

    with pytest.raises(ValueError):
        VerifiedSourceSnapshot(
            artifact=artifact,
            locator=locator,
            content=forged,
        )


@pytest.mark.parametrize(
    "changes",
    [
        {"filename": "outro.csv"},
        {"media_type": ""},
        {"artifact_id": "sha256-" + "b" * 64},
    ],
)
def test_rejects_invalid_artifact_metadata(tmp_path, changes):
    path, artifact, locator, _ = _fixture(tmp_path)

    modified = replace(artifact, **changes)

    with pytest.raises(ValueError):
        load_verified_source_snapshot(
            source_path=path,
            artifact=modified,
            locator=locator,
        )


@pytest.mark.parametrize(
    ("field_name", "invalid_value"),
    [
        ("source_path", "vendas.csv"),
        ("artifact", None),
        ("locator", None),
    ],
)
def test_rejects_invalid_loader_argument_types(
    tmp_path,
    field_name,
    invalid_value,
):
    path, artifact, locator, _ = _fixture(tmp_path)

    arguments = {
        "source_path": path,
        "artifact": artifact,
        "locator": locator,
    }

    arguments[field_name] = invalid_value

    with pytest.raises(ValueError):
        load_verified_source_snapshot(**arguments)


def test_accepts_exact_max_byte_limit(tmp_path):
    path, artifact, locator, original = _fixture(tmp_path)

    snapshot = load_verified_source_snapshot(
        source_path=path,
        artifact=artifact,
        locator=locator,
        max_bytes=len(original),
    )

    assert snapshot.content == original


def test_rejects_source_truncated_to_empty(tmp_path):
    path, artifact, locator, _ = _fixture(tmp_path)

    path.write_bytes(b"")

    with pytest.raises(ValueError):
        load_verified_source_snapshot(
            source_path=path,
            artifact=artifact,
            locator=locator,
        )


def test_rejects_directory_substituted_for_file(tmp_path):
    path, artifact, locator, _ = _fixture(tmp_path)

    path.unlink()
    path.mkdir()

    with pytest.raises(ValueError):
        load_verified_source_snapshot(
            source_path=path,
            artifact=artifact,
            locator=locator,
        )


def test_rejects_source_file_symlink(tmp_path):
    path, artifact, locator, _ = _fixture(tmp_path)
    link = tmp_path / "atalho.csv"

    try:
        link.symlink_to(path)
    except (OSError, NotImplementedError):
        pytest.skip("File symlink creation unavailable on this host.")

    linked_artifact = replace(artifact, filename=link.name)

    with pytest.raises(ValueError, match="Redirected"):
        load_verified_source_snapshot(
            source_path=link,
            artifact=linked_artifact,
            locator=locator,
        )


def test_rejects_symlinked_parent_directory(tmp_path):
    path, artifact, locator, _ = _fixture(tmp_path)
    alias = tmp_path / "alias"

    try:
        alias.symlink_to(tmp_path, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Directory symlink creation unavailable on this host.")

    with pytest.raises(ValueError, match="Redirected"):
        load_verified_source_snapshot(
            source_path=alias / path.name,
            artifact=artifact,
            locator=locator,
        )
