import json
from pathlib import Path

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


def _valid_bundle(tmp_path: Path) -> Path:
    artifact = SourceArtifact(
        artifact_id="art-boundary-001",
        filename="synthetic.png",
        media_type="image/png",
        sha256="a" * 64,
    )

    provenance = ExtractionProvenance(
        run_id="run-boundary-001",
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
        output_root=tmp_path,
        artifact=artifact,
        raw_response=raw_response,
        result=result,
        provenance=provenance,
    )


def _prepend_duplicate_key(
    path: Path,
    *,
    key: str,
    decoy: str,
) -> None:
    original = path.read_text(encoding="utf-8")

    assert original.startswith("{")
    assert f'"{key}"' in original

    duplicate_prefix = json.dumps({key: decoy})[1:-1]

    path.write_text(
        "{" + duplicate_prefix + "," + original[1:],
        encoding="utf-8",
    )


def test_rejects_artifact_directory_identity_drift(
    tmp_path: Path,
) -> None:
    bundle = _valid_bundle(tmp_path)

    artifact_root = bundle.parent.parent
    moved_root = artifact_root.rename(artifact_root.with_name("art-forged"))
    moved_bundle = moved_root / bundle.parent.name / bundle.name

    with pytest.raises(AnalysisInputIntegrityError):
        load_analysis_input(moved_bundle)


def test_rejects_operation_directory_identity_drift(
    tmp_path: Path,
) -> None:
    bundle = _valid_bundle(tmp_path)

    operation_root = bundle.parent
    moved_root = operation_root.rename(operation_root.with_name("OtherOperation"))
    moved_bundle = moved_root / bundle.name

    with pytest.raises(AnalysisInputIntegrityError):
        load_analysis_input(moved_bundle)


def test_rejects_run_directory_identity_drift(
    tmp_path: Path,
) -> None:
    bundle = _valid_bundle(tmp_path)

    moved_bundle = bundle.rename(bundle.with_name("run-forged"))

    with pytest.raises(AnalysisInputIntegrityError):
        load_analysis_input(moved_bundle)


def test_rejects_duplicate_manifest_json_key(
    tmp_path: Path,
) -> None:
    bundle = _valid_bundle(tmp_path)

    _prepend_duplicate_key(
        bundle / "manifest.json",
        key="status",
        decoy="normalization_failed",
    )

    with pytest.raises(AnalysisInputIntegrityError):
        load_analysis_input(bundle)


def test_rejects_duplicate_normalized_json_key(
    tmp_path: Path,
) -> None:
    bundle = _valid_bundle(tmp_path)

    _prepend_duplicate_key(
        bundle / "normalized.json",
        key="artifact_id",
        decoy="art-forged",
    )

    with pytest.raises(AnalysisInputIntegrityError):
        load_analysis_input(bundle)


def test_valid_bundle_preserves_identity(
    tmp_path: Path,
) -> None:
    bundle = _valid_bundle(tmp_path)

    context = load_analysis_input(bundle)

    assert bundle.name == context.extraction_run_id
    assert bundle.parent.name == context.operation
    assert bundle.parent.parent.name == context.artifact_id
    assert context.evidence_block_ids == ("line-001",)
