import hashlib
from pathlib import Path

import pytest

from kuma_secure_knowledge_pipeline.contracts import (
    EvidenceReference,
    ExtractionProvenance,
    ExtractionResult,
    SourceArtifact,
)
from kuma_secure_knowledge_pipeline.evidence import write_extraction_evidence
from kuma_secure_knowledge_pipeline.extraction.tesseract import (
    TSV_COLUMNS,
    normalize_tesseract_tsv,
)
from kuma_secure_knowledge_pipeline.orchestration import (
    AnalysisInputIntegrityError,
    load_analysis_input,
)


def _textract_bundle(
    tmp_path: Path,
    *,
    raw_block_id: str = "line-001",
    raw_text: str = "INCIDENT ID: INC-001",
) -> Path:
    artifact = SourceArtifact(
        artifact_id="art-textract-001",
        filename="synthetic.png",
        media_type="image/png",
        sha256="a" * 64,
    )

    provenance = ExtractionProvenance(
        run_id="run-textract-001",
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
                "Id": raw_block_id,
                "Page": 1,
                "Confidence": 99.0,
                "Text": raw_text,
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


def _tesseract_bundle(
    tmp_path: Path,
    *,
    corrupt_hash: bool = False,
) -> Path:
    artifact = SourceArtifact(
        artifact_id="art-tesseract-001",
        filename="synthetic.png",
        media_type="image/png",
        sha256="b" * 64,
    )

    provenance = ExtractionProvenance(
        run_id="run-tesseract-001",
        provider="tesseract",
        operation="TesseractTSV",
        region="local",
        started_at_utc="2026-10-09T12:00:00Z",
    )

    word_row = (
        "5",
        "1",
        "1",
        "1",
        "1",
        "1",
        "0",
        "0",
        "40",
        "20",
        "95.0",
        "MITRE",
    )

    tsv_text = "\t".join(TSV_COLUMNS) + "\n" + "\t".join(word_row) + "\n"

    result = normalize_tesseract_tsv(
        artifact_id=artifact.artifact_id,
        tsv_text=tsv_text,
    )

    actual_hash = hashlib.sha256(tsv_text.encode("utf-8")).hexdigest()

    raw_response = {
        "tsv_text": tsv_text,
        "tsv_sha256": "0" * 64 if corrupt_hash else actual_hash,
    }

    return write_extraction_evidence(
        output_root=tmp_path,
        artifact=artifact,
        raw_response=raw_response,
        result=result,
        provenance=provenance,
    )


def test_rejects_unresolved_textract_raw_block(
    tmp_path: Path,
) -> None:
    bundle = _textract_bundle(
        tmp_path,
        raw_block_id="line-unrelated",
    )

    with pytest.raises(
        AnalysisInputIntegrityError,
        match="raw",
    ):
        load_analysis_input(bundle)


def test_rejects_textract_raw_text_drift(
    tmp_path: Path,
) -> None:
    bundle = _textract_bundle(
        tmp_path,
        raw_text="UNRELATED RECORD",
    )

    with pytest.raises(
        AnalysisInputIntegrityError,
        match="raw",
    ):
        load_analysis_input(bundle)


def test_rejects_tesseract_raw_checksum_drift(
    tmp_path: Path,
) -> None:
    bundle = _tesseract_bundle(
        tmp_path,
        corrupt_hash=True,
    )

    with pytest.raises(
        AnalysisInputIntegrityError,
        match="tsv",
    ):
        load_analysis_input(bundle)


def test_valid_tesseract_bundle_remains_supported(
    tmp_path: Path,
) -> None:
    bundle = _tesseract_bundle(tmp_path)

    context = load_analysis_input(bundle)

    assert context.artifact_id == "art-tesseract-001"
    assert context.extraction_run_id == "run-tesseract-001"
    assert context.provider == "tesseract"
    assert context.operation == "TesseractTSV"
    assert context.text == "MITRE"
    assert context.evidence_block_ids == ("tsv-row-2",)
