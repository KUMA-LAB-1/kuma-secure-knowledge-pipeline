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
        artifact_id="art-type-security-001",
        filename="synthetic.png",
        media_type="image/png",
        sha256="a" * 64,
    )

    provenance = ExtractionProvenance(
        run_id="run-type-security-001",
        provider="amazon-textract",
        operation="DetectDocumentText",
        region="us-east-1",
        started_at_utc="2026-10-09T12:00:00Z",
    )

    result = ExtractionResult(
        artifact_id=artifact.artifact_id,
        provider=provenance.provider,
        operation=provenance.operation,
        text="INCIDENT ID: INC-SEC-001",
        average_confidence=1.0,
        evidence_refs=(
            EvidenceReference(
                artifact_id=artifact.artifact_id,
                block_id="line-001",
                page=1,
                confidence=1.0,
            ),
        ),
    )

    raw_response = {
        "Blocks": [
            {
                "BlockType": "LINE",
                "Id": "line-001",
                "Page": 1,
                "Confidence": 1.0,
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


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: dict) -> None:
    path.write_text(
        json.dumps(payload, sort_keys=True),
        encoding="utf-8",
    )


@pytest.mark.parametrize(
    "field",
    ["page", "confidence", "average_confidence"],
)
def test_rejects_boolean_in_numeric_evidence_field(
    tmp_path: Path,
    field: str,
) -> None:
    bundle = _valid_bundle(tmp_path)
    path = bundle / "normalized.json"
    payload = _read_json(path)

    if field == "average_confidence":
        payload[field] = True
    else:
        payload["evidence_refs"][0][field] = True

    _write_json(path, payload)

    with pytest.raises(AnalysisInputIntegrityError):
        load_analysis_input(bundle)


def test_rejects_invalid_provenance_timestamp(
    tmp_path: Path,
) -> None:
    bundle = _valid_bundle(tmp_path)
    path = bundle / "manifest.json"
    payload = _read_json(path)

    payload["run"]["started_at_utc"] = "not-a-timestamp"

    _write_json(path, payload)

    with pytest.raises(AnalysisInputIntegrityError):
        load_analysis_input(bundle)


def test_rejects_manifest_average_confidence_drift(
    tmp_path: Path,
) -> None:
    bundle = _valid_bundle(tmp_path)
    path = bundle / "manifest.json"
    payload = _read_json(path)

    payload["extraction"]["average_confidence"] = 80.0

    _write_json(path, payload)

    with pytest.raises(AnalysisInputIntegrityError):
        load_analysis_input(bundle)


def test_valid_bundle_retains_numeric_types(
    tmp_path: Path,
) -> None:
    bundle = _valid_bundle(tmp_path)

    context = load_analysis_input(bundle)

    assert context.artifact_id == "art-type-security-001"
    assert context.extraction_run_id == "run-type-security-001"
    assert context.text == "INCIDENT ID: INC-SEC-001"
    assert context.evidence_block_ids == ("line-001",)
