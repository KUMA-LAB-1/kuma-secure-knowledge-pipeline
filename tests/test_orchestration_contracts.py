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


def _synthetic_bundle(tmp_path: Path) -> Path:
    artifact = SourceArtifact(
        artifact_id="art-test-001",
        filename="fixture.png",
        media_type="image/png",
        sha256="a" * 64,
    )

    provenance = ExtractionProvenance(
        run_id="run-test-001",
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


def test_valid_bundle_builds_analysis_input(tmp_path: Path) -> None:
    bundle = _synthetic_bundle(tmp_path)

    context = load_analysis_input(bundle)

    assert context.artifact_id == "art-test-001"
    assert context.extraction_run_id == "run-test-001"
    assert context.source_sha256 == "a" * 64
    assert context.text == "INCIDENT ID: INC-001"
    assert context.evidence_block_ids == ("line-001",)


def test_rejects_mismatched_artifact_id(tmp_path: Path) -> None:
    bundle = _synthetic_bundle(tmp_path)
    normalized_path = bundle / "normalized.json"

    normalized = json.loads(normalized_path.read_text(encoding="utf-8"))
    normalized["artifact_id"] = "art-other"

    normalized_path.write_text(
        json.dumps(normalized),
        encoding="utf-8",
    )

    with pytest.raises(
        AnalysisInputIntegrityError,
        match="artifact",
    ):
        load_analysis_input(bundle)


def test_rejects_mismatched_extracted_text(tmp_path: Path) -> None:
    bundle = _synthetic_bundle(tmp_path)

    (bundle / "extracted.txt").write_text(
        "TAMPERED TEXT",
        encoding="utf-8",
    )

    with pytest.raises(
        AnalysisInputIntegrityError,
        match="text",
    ):
        load_analysis_input(bundle)
