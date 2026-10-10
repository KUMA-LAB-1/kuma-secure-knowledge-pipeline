import os
import subprocess
from pathlib import Path
from typing import Any

import pytest

from kuma_secure_knowledge_pipeline.contracts import (
    EvidenceReference,
    ExtractionProvenance,
    ExtractionResult,
    SourceArtifact,
)
from kuma_secure_knowledge_pipeline.evidence import write_extraction_evidence
from kuma_secure_knowledge_pipeline.orchestration import (
    AnalysisInputIntegrityError,
    load_analysis_input,
)

_TEXT_LIMIT = 16 * 1024 * 1024


def _valid_bundle(tmp_path: Path) -> Path:
    artifact = SourceArtifact(
        artifact_id="art-filesystem-001",
        filename="synthetic.png",
        media_type="image/png",
        sha256="a" * 64,
    )

    provenance = ExtractionProvenance(
        run_id="run-filesystem-001",
        provider="amazon-textract",
        operation="DetectDocumentText",
        region="us-east-1",
        started_at_utc="2026-10-09T12:00:00Z",
    )

    result = ExtractionResult(
        artifact_id=artifact.artifact_id,
        provider=provenance.provider,
        operation=provenance.operation,
        text="INCIDENT ID: INC-001",
        average_confidence=99.0,
        evidence_refs=(
            EvidenceReference(
                artifact_id=artifact.artifact_id,
                block_id="line-001",
                page=1,
                confidence=99.0,
            ),
        ),
    )

    raw_response = {
        "Blocks": [
            {
                "BlockType": "LINE",
                "Id": "line-001",
                "Page": 1,
                "Confidence": 99.0,
                "Text": result.text,
            }
        ]
    }

    return write_extraction_evidence(
        output_root=tmp_path / "origin",
        artifact=artifact,
        raw_response=raw_response,
        result=result,
        provenance=provenance,
    )


class _ReadBudgetGuard:
    """Detect reads without an explicit and acceptable byte budget."""

    def __init__(self, stream: Any) -> None:
        self._stream = stream

    def __enter__(self) -> "_ReadBudgetGuard":
        self._stream.__enter__()
        return self

    def __exit__(
        self,
        exc_type: Any,
        exc: Any,
        traceback: Any,
    ) -> Any:
        return self._stream.__exit__(exc_type, exc, traceback)

    def read(self, size: int = -1) -> Any:
        if size < 0 or size > _TEXT_LIMIT + 1:
            raise AssertionError("Unbounded extracted.txt read detected.")

        return self._stream.read(size)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._stream, name)


def _guard_extracted_reads(
    monkeypatch: pytest.MonkeyPatch,
    extracted: Path,
) -> None:
    original_open = Path.open

    def guarded_open(
        path: Path,
        mode: str = "r",
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        stream = original_open(path, mode, *args, **kwargs)

        if path == extracted and "r" in mode:
            return _ReadBudgetGuard(stream)

        return stream

    monkeypatch.setattr(Path, "open", guarded_open)


def test_rejects_oversized_extracted_without_unbounded_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = _valid_bundle(tmp_path)
    extracted = bundle / "extracted.txt"

    with extracted.open("r+b") as stream:
        stream.truncate(_TEXT_LIMIT + 1)

    assert extracted.stat().st_size > _TEXT_LIMIT

    _guard_extracted_reads(monkeypatch, extracted)

    with pytest.raises(AnalysisInputIntegrityError):
        load_analysis_input(bundle)


def test_valid_extracted_uses_bounded_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = _valid_bundle(tmp_path)
    extracted = bundle / "extracted.txt"

    _guard_extracted_reads(monkeypatch, extracted)

    context = load_analysis_input(bundle)

    assert context.text == "INCIDENT ID: INC-001"


def _create_directory_redirect(
    link: Path,
    target: Path,
) -> None:
    if os.name == "nt":
        result = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(target)],
            capture_output=True,
            text=True,
            check=False,
        )

        if result.returncode != 0:
            pytest.fail(
                "Cannot establish Windows junction fixture: " + result.stderr + result.stdout
            )
    else:
        link.symlink_to(target, target_is_directory=True)


def test_rejects_redirected_ancestor_directory(
    tmp_path: Path,
) -> None:
    bundle = _valid_bundle(tmp_path)

    original_artifact_root = bundle.parent.parent

    alias_root = tmp_path / "untrusted-alias"
    alias_root.mkdir()

    redirected_artifact_root = alias_root / original_artifact_root.name

    _create_directory_redirect(
        redirected_artifact_root,
        original_artifact_root,
    )

    redirected_bundle = redirected_artifact_root / bundle.parent.name / bundle.name

    assert redirected_bundle.is_dir()
    assert redirected_bundle.name == bundle.name
    assert redirected_bundle.parent.name == bundle.parent.name
    assert redirected_bundle.parent.parent.name == original_artifact_root.name

    with pytest.raises(AnalysisInputIntegrityError):
        load_analysis_input(redirected_bundle)


def test_valid_bundle_without_redirect_is_accepted(
    tmp_path: Path,
) -> None:
    bundle = _valid_bundle(tmp_path)

    context = load_analysis_input(bundle)

    assert context.artifact_id == "art-filesystem-001"
    assert context.extraction_run_id == "run-filesystem-001"
    assert context.evidence_block_ids == ("line-001",)
