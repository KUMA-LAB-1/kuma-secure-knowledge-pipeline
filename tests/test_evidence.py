import json
from pathlib import Path

import pytest

from kuma_secure_knowledge_pipeline.contracts import (
    EvidenceReference,
    ExtractionResult,
    SourceArtifact,
)
from kuma_secure_knowledge_pipeline.evidence import write_extraction_evidence


def _reference(artifact_id: str) -> EvidenceReference:
    return EvidenceReference(
        artifact_id=artifact_id,
        block_id="line-001",
        page=1,
        confidence=99.5,
    )


def _artifact() -> SourceArtifact:
    return SourceArtifact(
        artifact_id="art-001",
        filename="security-report.png",
        media_type="image/png",
        sha256="abc123",
    )


def _result(
    artifact_id: str = "art-001",
) -> ExtractionResult:
    return ExtractionResult(
        artifact_id=artifact_id,
        provider="amazon-textract",
        operation="DetectDocumentText",
        text="INCIDENT ID: INC-001",
        average_confidence=99.5,
        evidence_refs=(_reference(artifact_id),),
    )


def test_write_extraction_evidence_preserves_raw_and_normalized_data(
    tmp_path: Path,
) -> None:
    artifact = _artifact()
    result = _result()

    raw_response = {
        "Blocks": [
            {
                "BlockType": "LINE",
                "Id": "line-001",
                "Page": 1,
                "Confidence": 99.5,
                "Text": "INCIDENT ID: INC-001",
            }
        ]
    }

    evidence_dir = write_extraction_evidence(
        output_root=tmp_path,
        artifact=artifact,
        raw_response=raw_response,
        result=result,
    )

    raw = json.loads(
        (evidence_dir / "raw-response.json").read_text(
            encoding="utf-8",
        )
    )

    normalized = json.loads(
        (evidence_dir / "normalized.json").read_text(
            encoding="utf-8",
        )
    )

    manifest = json.loads(
        (evidence_dir / "manifest.json").read_text(
            encoding="utf-8",
        )
    )

    extracted_text = (evidence_dir / "extracted.txt").read_text(encoding="utf-8")

    assert raw["Blocks"][0]["Id"] == "line-001"
    assert normalized["artifact_id"] == "art-001"
    assert normalized["evidence_refs"][0]["block_id"] == "line-001"
    assert manifest["source"]["sha256"] == "abc123"
    assert manifest["extraction"]["provider"] == "amazon-textract"
    assert manifest["extraction"]["evidence_count"] == 1
    assert extracted_text == "INCIDENT ID: INC-001"


def test_write_extraction_evidence_rejects_artifact_mismatch(
    tmp_path: Path,
) -> None:
    artifact = _artifact()
    result = _result("art-002")

    with pytest.raises(ValueError, match="does not belong"):
        write_extraction_evidence(
            output_root=tmp_path,
            artifact=artifact,
            raw_response={"Blocks": []},
            result=result,
        )


def test_write_extraction_evidence_fails_closed_on_non_json_data(
    tmp_path: Path,
) -> None:
    artifact = _artifact()
    result = _result()

    raw_response = {
        "Blocks": [],
        "unexpected_object": object(),
    }

    evidence_dir = tmp_path / artifact.artifact_id

    with pytest.raises(TypeError):
        write_extraction_evidence(
            output_root=tmp_path,
            artifact=artifact,
            raw_response=raw_response,
            result=result,
        )

    assert not evidence_dir.exists()
