from pathlib import Path

import pytest

import kuma_secure_knowledge_pipeline.evidence as evidence_module
from kuma_secure_knowledge_pipeline.contracts import (
    EvidenceReference,
    ExtractionResult,
    SourceArtifact,
)
from kuma_secure_knowledge_pipeline.evidence import (
    EvidenceAlreadyExistsError,
    EvidenceIntegrityError,
    EvidenceSerializationError,
    write_extraction_evidence,
)


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
    *,
    reference_artifact_id: str | None = None,
    operation: str = "DetectDocumentText",
) -> ExtractionResult:
    return ExtractionResult(
        artifact_id=artifact_id,
        provider="amazon-textract",
        operation=operation,
        text="INCIDENT ID: INC-001",
        average_confidence=99.5,
        evidence_refs=(
            _reference(reference_artifact_id if reference_artifact_id is not None else artifact_id),
        ),
    )


def test_evidence_bundle_refuses_overwrite(
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

    write_extraction_evidence(
        output_root=tmp_path,
        artifact=artifact,
        raw_response=raw_response,
        result=result,
    )

    with pytest.raises(
        EvidenceAlreadyExistsError,
        match="already exists",
    ):
        write_extraction_evidence(
            output_root=tmp_path,
            artifact=artifact,
            raw_response=raw_response,
            result=result,
        )


def test_non_json_evidence_raises_specific_error(
    tmp_path: Path,
) -> None:
    artifact = _artifact()
    result = _result()

    with pytest.raises(EvidenceSerializationError):
        write_extraction_evidence(
            output_root=tmp_path,
            artifact=artifact,
            raw_response={
                "Blocks": [],
                "unexpected_object": object(),
            },
            result=result,
        )


def test_evidence_rejects_reference_from_different_artifact(
    tmp_path: Path,
) -> None:
    artifact = _artifact()

    result = _result(
        reference_artifact_id="art-other",
    )

    with pytest.raises(
        EvidenceIntegrityError,
        match="different artifact",
    ):
        write_extraction_evidence(
            output_root=tmp_path,
            artifact=artifact,
            raw_response={"Blocks": []},
            result=result,
        )

    assert not any(tmp_path.iterdir())


@pytest.mark.parametrize(
    ("artifact_id", "operation"),
    [
        ("../escape", "DetectDocumentText"),
        ("art-001", "../escape"),
        ("art/escape", "DetectDocumentText"),
        ("art-001", r"Detect\DocumentText"),
    ],
)
def test_evidence_rejects_unsafe_path_components(
    tmp_path: Path,
    artifact_id: str,
    operation: str,
) -> None:
    artifact = SourceArtifact(
        artifact_id=artifact_id,
        filename="security-report.png",
        media_type="image/png",
        sha256="abc123",
    )

    result = _result(
        artifact_id=artifact_id,
        operation=operation,
    )

    with pytest.raises(
        EvidenceIntegrityError,
        match="unsafe for an evidence path",
    ):
        write_extraction_evidence(
            output_root=tmp_path,
            artifact=artifact,
            raw_response={"Blocks": []},
            result=result,
        )

    assert not any(tmp_path.iterdir())


def test_evidence_removes_partial_temp_bundle_on_write_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = _artifact()
    result = _result()

    original_write = evidence_module._write_text
    call_count = 0

    def fail_during_bundle_write(
        destination: Path,
        content: str,
    ) -> None:
        nonlocal call_count

        call_count += 1

        if call_count == 3:
            raise OSError("synthetic evidence write failure")

        original_write(
            destination,
            content,
        )

    monkeypatch.setattr(
        evidence_module,
        "_write_text",
        fail_during_bundle_write,
    )

    with pytest.raises(
        OSError,
        match="synthetic evidence write failure",
    ):
        write_extraction_evidence(
            output_root=tmp_path,
            artifact=artifact,
            raw_response={"Blocks": []},
            result=result,
        )

    artifact_root = tmp_path / artifact.artifact_id

    final_bundle = artifact_root / result.operation

    assert not final_bundle.exists()
    assert not artifact_root.exists()
