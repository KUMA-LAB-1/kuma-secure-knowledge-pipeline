import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from kuma_secure_knowledge_pipeline.artifacts import (
    build_source_artifact,
)
from kuma_secure_knowledge_pipeline.contracts import (
    EvidenceReference,
    ExtractionProvenance,
    ExtractionResult,
    SourceArtifact,
)
from kuma_secure_knowledge_pipeline.evidence import (
    EvidenceIntegrityError,
    write_extraction_evidence,
)
from kuma_secure_knowledge_pipeline.extraction.textract import (
    TextractResponseError,
)
from kuma_secure_knowledge_pipeline.provenance import (
    create_extraction_provenance,
)
from kuma_secure_knowledge_pipeline.runner import (
    run_local_pipeline,
)

PROVIDER = "amazon-textract"
OPERATION = "DetectDocumentText"
REGION = "us-east-1"


def _artifact() -> SourceArtifact:
    return SourceArtifact(
        artifact_id="art-001",
        filename="security-report.png",
        media_type="image/png",
        sha256="abc123",
    )


def _result() -> ExtractionResult:
    return ExtractionResult(
        artifact_id="art-001",
        provider=PROVIDER,
        operation=OPERATION,
        text="INCIDENT ID: INC-001",
        average_confidence=99.5,
        evidence_refs=(
            EvidenceReference(
                artifact_id="art-001",
                block_id="line-001",
                page=1,
                confidence=99.5,
            ),
        ),
    )


def _provenance(
    run_id: str = "run-test-001",
) -> ExtractionProvenance:
    return ExtractionProvenance(
        run_id=run_id,
        provider=PROVIDER,
        operation=OPERATION,
        region=REGION,
        started_at_utc="2026-10-07T15:00:00Z",
    )


def test_create_extraction_provenance_normalizes_timestamp_to_utc() -> None:
    provenance = create_extraction_provenance(
        provider=PROVIDER,
        operation=OPERATION,
        region=REGION,
        run_id="run-fixed-001",
        now=datetime(
            2026,
            10,
            7,
            12,
            30,
            45,
            tzinfo=timezone(timedelta(hours=-3)),
        ),
    )

    assert provenance.run_id == "run-fixed-001"
    assert provenance.provider == PROVIDER
    assert provenance.operation == OPERATION
    assert provenance.region == REGION
    assert provenance.started_at_utc == "2026-10-07T15:30:45Z"


def test_create_extraction_provenance_rejects_naive_datetime() -> None:
    with pytest.raises(
        ValueError,
        match="timezone-aware",
    ):
        create_extraction_provenance(
            provider=PROVIDER,
            operation=OPERATION,
            region=REGION,
            run_id="run-fixed-001",
            now=datetime(
                2026,
                10,
                7,
                12,
                30,
                45,
            ),
        )


def test_success_bundle_contains_run_provenance(
    tmp_path: Path,
) -> None:
    artifact = _artifact()
    result = _result()
    provenance = _provenance()

    evidence_dir = write_extraction_evidence(
        output_root=tmp_path,
        artifact=artifact,
        raw_response={
            "Blocks": [
                {
                    "BlockType": "LINE",
                    "Id": "line-001",
                    "Page": 1,
                    "Confidence": 99.5,
                    "Text": "INCIDENT ID: INC-001",
                }
            ]
        },
        result=result,
        provenance=provenance,
    )

    assert evidence_dir == (tmp_path / artifact.artifact_id / OPERATION / provenance.run_id)

    manifest = json.loads((evidence_dir / "manifest.json").read_text(encoding="utf-8"))

    assert manifest["status"] == "success"

    assert manifest["run"] == {
        "run_id": "run-test-001",
        "provider": PROVIDER,
        "operation": OPERATION,
        "region": REGION,
        "started_at_utc": "2026-10-07T15:00:00Z",
    }


def test_same_artifact_operation_supports_distinct_runs(
    tmp_path: Path,
) -> None:
    artifact = _artifact()
    result = _result()

    first = write_extraction_evidence(
        output_root=tmp_path,
        artifact=artifact,
        raw_response={"Blocks": []},
        result=result,
        provenance=_provenance("run-test-001"),
    )

    second = write_extraction_evidence(
        output_root=tmp_path,
        artifact=artifact,
        raw_response={"Blocks": []},
        result=result,
        provenance=_provenance("run-test-002"),
    )

    assert first != second
    assert first.is_dir()
    assert second.is_dir()


def test_evidence_rejects_unsafe_run_id(
    tmp_path: Path,
) -> None:
    artifact = _artifact()

    with pytest.raises(
        EvidenceIntegrityError,
        match="run_id",
    ):
        write_extraction_evidence(
            output_root=tmp_path,
            artifact=artifact,
            raw_response={"Blocks": []},
            result=_result(),
            provenance=_provenance("../escape"),
        )

    assert not any(tmp_path.iterdir())


class MalformedTextractClient:
    def __init__(self) -> None:
        self.calls = 0

    def detect_document_text(
        self,
        **kwargs,
    ):
        self.calls += 1

        return {
            "DocumentMetadata": {
                "Pages": 1,
            },
            "Blocks": [
                {
                    "BlockType": "LINE",
                    "Id": "line-malformed",
                    "Page": 1,
                    "Confidence": 99.0,
                    "Text": 123,
                }
            ],
            "SyntheticCanary": "RAW_RESPONSE_MUST_SURVIVE",
        }


def test_normalization_failure_preserves_raw_response(
    tmp_path: Path,
) -> None:
    source = (
        Path(__file__).parent
        / "fixtures"
        / "ocr"
        / "textract"
        / "v2"
        / "KUMA_TEXTRACT_FIXTURE_INCIDENT_v2.png"
    )

    artifact = build_source_artifact(source)

    provenance = _provenance("run-normalization-failure-001")

    client = MalformedTextractClient()

    output_root = tmp_path / "evidence"

    with pytest.raises(
        TextractResponseError,
        match="Text",
    ):
        run_local_pipeline(
            source_path=source,
            output_root=output_root,
            client=client,
            provenance=provenance,
        )

    assert client.calls == 1

    failure_dir = output_root / artifact.artifact_id / OPERATION / provenance.run_id

    assert failure_dir.is_dir()

    assert {path.name for path in failure_dir.iterdir()} == {
        "raw-response.json",
        "manifest.json",
    }

    raw = json.loads((failure_dir / "raw-response.json").read_text(encoding="utf-8"))

    manifest = json.loads((failure_dir / "manifest.json").read_text(encoding="utf-8"))

    assert raw["SyntheticCanary"] == "RAW_RESPONSE_MUST_SURVIVE"

    assert raw["Blocks"][0]["Text"] == 123

    assert manifest["status"] == "normalization_failed"

    assert manifest["failure"]["stage"] == "normalization"

    assert manifest["failure"]["error_type"] == "TextractResponseError"

    assert manifest["run"] == {
        "run_id": "run-normalization-failure-001",
        "provider": PROVIDER,
        "operation": OPERATION,
        "region": REGION,
        "started_at_utc": "2026-10-07T15:00:00Z",
    }

    assert not (failure_dir / "normalized.json").exists()

    assert not (failure_dir / "extracted.txt").exists()

    assert not list(output_root.rglob("*.reservation"))


def test_runner_rejects_provenance_operation_mismatch_before_provider(
    tmp_path: Path,
) -> None:
    source = (
        Path(__file__).parent
        / "fixtures"
        / "ocr"
        / "textract"
        / "v2"
        / "KUMA_TEXTRACT_FIXTURE_INCIDENT_v2.png"
    )

    client = MalformedTextractClient()

    invalid_provenance = ExtractionProvenance(
        run_id="run-invalid-operation",
        provider=PROVIDER,
        operation="AnalyzeDocument",
        region=REGION,
        started_at_utc="2026-10-07T15:00:00Z",
    )

    with pytest.raises(
        ValueError,
        match="operation",
    ):
        run_local_pipeline(
            source_path=source,
            output_root=tmp_path,
            client=client,
            provenance=invalid_provenance,
        )

    assert client.calls == 0
