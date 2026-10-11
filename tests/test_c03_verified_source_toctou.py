"""Regression tests for the source snapshot's TOCTOU byte boundary."""

import os
from pathlib import Path

import pytest

from kuma_secure_knowledge_pipeline.artifacts import (
    ArtifactIntegrityError,
    build_source_artifact,
)
from kuma_secure_knowledge_pipeline.knowledge_contracts import SourceLocator
from kuma_secure_knowledge_pipeline.knowledge_evidence import (
    load_verified_source_snapshot,
)

ORIGINAL = b"opportunity_id,value\nOPP-0001,100\n"
TAMPERED = b"opportunity_id,value\nOPP-0001,900\n"


@pytest.mark.parametrize(
    ("replacement", "expected_valid"),
    [
        pytest.param(TAMPERED, False, id="altered-bytes-rejected"),
        pytest.param(ORIGINAL, True, id="identical-bytes-accepted"),
    ],
)
def test_substitution_immediately_before_open(
    tmp_path,
    monkeypatch,
    replacement,
    expected_valid,
):
    source = tmp_path / "vendas.csv"
    alternate = tmp_path / "replacement.csv"

    source.write_bytes(ORIGINAL)
    alternate.write_bytes(replacement)

    artifact = build_source_artifact(source)

    locator = SourceLocator(
        artifact_id=artifact.artifact_id,
        source_sha256=artifact.sha256,
        kind="csv_row",
        record_index=1,
        record_id="OPP-0001",
    )

    original_open = Path.open
    swapped = False

    def swapped_open(self, *args, **kwargs):
        nonlocal swapped

        if self == source and not swapped:
            os.replace(alternate, source)
            swapped = True

        return original_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", swapped_open)

    if expected_valid:
        snapshot = load_verified_source_snapshot(
            source_path=source,
            artifact=artifact,
            locator=locator,
        )
        assert snapshot.content == ORIGINAL
    else:
        with pytest.raises(ArtifactIntegrityError, match="SHA-256"):
            load_verified_source_snapshot(
                source_path=source,
                artifact=artifact,
                locator=locator,
            )

    assert swapped, "The controlled substitution did not occur."
