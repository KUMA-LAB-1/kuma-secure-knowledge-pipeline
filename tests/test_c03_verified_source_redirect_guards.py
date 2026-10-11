"""Deterministic tests for source-path redirection guards."""

from pathlib import Path

import pytest

from kuma_secure_knowledge_pipeline.artifacts import build_source_artifact
from kuma_secure_knowledge_pipeline.knowledge_contracts import SourceLocator
from kuma_secure_knowledge_pipeline.knowledge_evidence import (
    load_verified_source_snapshot,
)


@pytest.mark.parametrize(
    ("redirect_method", "target_level"),
    [
        ("is_symlink", "file"),
        ("is_symlink", "parent"),
        ("is_junction", "file"),
        ("is_junction", "parent"),
    ],
)
def test_rejects_reported_redirect_before_read(
    tmp_path,
    monkeypatch,
    redirect_method,
    target_level,
):
    source_path = tmp_path / "vendas.csv"
    source_path.write_bytes(b"opportunity_id,value\nOPP-0001,100\n")

    artifact = build_source_artifact(source_path)

    locator = SourceLocator(
        artifact_id=artifact.artifact_id,
        source_sha256=artifact.sha256,
        kind="csv_row",
        record_index=1,
        record_id="OPP-0001",
    )

    target = source_path if target_level == "file" else tmp_path

    original_check = getattr(Path, redirect_method)
    original_open = Path.open

    def reported_redirect(self):
        if self == target:
            return True

        return original_check(self)

    def guarded_open(self, *args, **kwargs):
        if self == source_path:
            raise AssertionError("Source opened before redirect guard rejected it.")

        return original_open(self, *args, **kwargs)

    monkeypatch.setattr(
        Path,
        redirect_method,
        reported_redirect,
    )

    monkeypatch.setattr(
        Path,
        "open",
        guarded_open,
    )

    with pytest.raises(ValueError, match="Redirected"):
        load_verified_source_snapshot(
            source_path=source_path,
            artifact=artifact,
            locator=locator,
        )
