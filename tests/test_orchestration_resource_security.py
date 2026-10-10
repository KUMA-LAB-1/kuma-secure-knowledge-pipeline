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


@pytest.fixture
def bundle(tmp_path: Path) -> Path:
    artifact = SourceArtifact(
        artifact_id="art-resource-001",
        filename="synthetic.png",
        media_type="image/png",
        sha256="a" * 64,
    )

    provenance = ExtractionProvenance(
        run_id="run-resource-001",
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


@pytest.mark.parametrize("value", ["nan", "inf"])
def test_rejects_nonfinite_raw_json(
    bundle: Path,
    value: str,
) -> None:
    path = bundle / "raw-response.json"
    payload = json.loads(path.read_text(encoding="utf-8"))

    payload["ignored_untrusted_metric"] = float(value)

    path.write_text(
        json.dumps(payload),
        encoding="utf-8",
    )

    with pytest.raises(AnalysisInputIntegrityError):
        load_analysis_input(bundle)


def test_rejects_numeric_overflow_in_raw_json(
    bundle: Path,
) -> None:
    path = bundle / "raw-response.json"
    payload = json.loads(path.read_text(encoding="utf-8"))

    serialized = json.dumps(payload)

    assert serialized.endswith("}")

    path.write_text(
        serialized[:-1] + ',"ignored_overflow":1e9999}',
        encoding="utf-8",
    )

    with pytest.raises(AnalysisInputIntegrityError):
        load_analysis_input(bundle)


def test_rejects_excessive_json_depth(
    bundle: Path,
) -> None:
    path = bundle / "raw-response.json"
    payload = json.loads(path.read_text(encoding="utf-8"))

    nested = {"leaf": "synthetic"}

    for _ in range(70):
        nested = {"nested": nested}

    payload["ignored_nested_metadata"] = nested

    path.write_text(
        json.dumps(payload),
        encoding="utf-8",
    )

    with pytest.raises(AnalysisInputIntegrityError):
        load_analysis_input(bundle)


def test_rejects_oversized_manifest(
    bundle: Path,
) -> None:
    path = bundle / "manifest.json"
    payload = json.loads(path.read_text(encoding="utf-8"))

    payload["untrusted_padding"] = "x" * 70_000

    path.write_text(
        json.dumps(payload),
        encoding="utf-8",
    )

    assert path.stat().st_size > 64 * 1024

    with pytest.raises(AnalysisInputIntegrityError):
        load_analysis_input(bundle)


def test_valid_small_bundle_is_accepted(
    bundle: Path,
) -> None:
    context = load_analysis_input(bundle)

    assert context.artifact_id == "art-resource-001"
    assert context.extraction_run_id == "run-resource-001"
    assert context.text == "INCIDENT ID: INC-001"
    assert context.evidence_block_ids == ("line-001",)
