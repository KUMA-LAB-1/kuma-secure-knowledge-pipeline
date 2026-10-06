import hashlib
from pathlib import Path

import pytest

from kuma_secure_knowledge_pipeline.artifacts import (
    build_source_artifact,
    verify_artifact_integrity,
)


def test_build_source_artifact_generates_sha256_identity(tmp_path: Path) -> None:
    content = b"synthetic-security-evidence"
    source = tmp_path / "security-report.png"
    source.write_bytes(content)

    artifact = build_source_artifact(source)

    expected_sha256 = hashlib.sha256(content).hexdigest()

    assert artifact.filename == "security-report.png"
    assert artifact.media_type == "image/png"
    assert artifact.sha256 == expected_sha256
    assert artifact.artifact_id == f"sha256-{expected_sha256}"


def test_verify_artifact_integrity_rejects_modified_source(tmp_path: Path) -> None:
    source = tmp_path / "security-report.png"
    source.write_bytes(b"original")

    artifact = build_source_artifact(source)

    source.write_bytes(b"tampered")

    with pytest.raises(ValueError):
        verify_artifact_integrity(source, artifact)


def test_build_source_artifact_rejects_empty_file(tmp_path: Path) -> None:
    source = tmp_path / "empty.png"
    source.write_bytes(b"")

    with pytest.raises(ValueError, match="empty"):
        build_source_artifact(source)


def test_build_source_artifact_rejects_missing_file(tmp_path: Path) -> None:
    source = tmp_path / "missing.png"

    with pytest.raises(ValueError, match="does not exist"):
        build_source_artifact(source)
