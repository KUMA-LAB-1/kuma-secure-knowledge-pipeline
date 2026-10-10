"""Residual exception disclosure regression tests for C02.

Synthetic inputs only. No network or AWS.
"""

import json
import traceback
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
    _read_extracted_text_bounded,
    _read_json_text_bounded,
    load_analysis_input,
)
from kuma_secure_knowledge_pipeline.provenance import (
    validate_extraction_provenance,
)

PATH_CANARY = "KUMA_SYNTHETIC_PRIVATE_PATH_038"
INVALID_TIMESTAMP = "2099-99-99T99:99:99Z"


def _assert_sanitized(error: BaseException, marker: str) -> None:
    assert error.__cause__ is None
    assert error.__context__ is None
    assert marker not in str(error)
    assert marker not in "".join(traceback.format_exception(error))


def _provenance(timestamp: str) -> ExtractionProvenance:
    return ExtractionProvenance(
        run_id="run-residual-038",
        provider="amazon-textract",
        operation="DetectDocumentText",
        region="us-east-1",
        started_at_utc=timestamp,
    )


def test_missing_evidence_path_does_not_leak_via_exception(
    tmp_path: Path,
) -> None:
    path = tmp_path / PATH_CANARY / "raw-response.json"

    assert not path.exists()

    with pytest.raises(AnalysisInputIntegrityError) as caught:
        _read_json_text_bounded(path)

    _assert_sanitized(caught.value, PATH_CANARY)


def test_invalid_provenance_timestamp_does_not_chain_value() -> None:
    with pytest.raises(ValueError) as caught:
        validate_extraction_provenance(_provenance(INVALID_TIMESTAMP))

    _assert_sanitized(caught.value, INVALID_TIMESTAMP)


def test_orchestration_provenance_does_not_chain_timestamp(
    tmp_path: Path,
) -> None:
    artifact = SourceArtifact(
        artifact_id="art-residual-038",
        filename="synthetic.png",
        media_type="image/png",
        sha256="a" * 64,
    )

    valid = _provenance("2026-10-10T12:00:00Z")

    result = ExtractionResult(
        artifact_id=artifact.artifact_id,
        provider=valid.provider,
        operation=valid.operation,
        text="SYNTHETIC INCIDENT",
        average_confidence=95.0,
        evidence_refs=(
            EvidenceReference(
                artifact_id=artifact.artifact_id,
                block_id="line-001",
                page=1,
                confidence=95.0,
            ),
        ),
    )

    raw_response = {
        "Blocks": [
            {
                "BlockType": "LINE",
                "Id": "line-001",
                "Page": 1,
                "Confidence": 95.0,
                "Text": result.text,
            }
        ]
    }

    bundle = write_extraction_evidence(
        output_root=tmp_path,
        artifact=artifact,
        raw_response=raw_response,
        result=result,
        provenance=valid,
    )

    manifest_path = bundle / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["run"]["started_at_utc"] = INVALID_TIMESTAMP

    manifest_path.write_text(
        json.dumps(manifest),
        encoding="utf-8",
    )

    with pytest.raises(AnalysisInputIntegrityError) as caught:
        load_analysis_input(bundle)

    _assert_sanitized(caught.value, INVALID_TIMESTAMP)


def test_missing_extracted_text_path_does_not_leak(
    tmp_path: Path,
) -> None:
    path = tmp_path / PATH_CANARY / "extracted.txt"
    assert not path.exists()

    with pytest.raises(AnalysisInputIntegrityError) as caught:
        _read_extracted_text_bounded(path)

    _assert_sanitized(caught.value, PATH_CANARY)
