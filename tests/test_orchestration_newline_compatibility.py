import json
from pathlib import Path

import pytest

from kuma_secure_knowledge_pipeline.contracts import (
    ExtractionProvenance,
    SourceArtifact,
)
from kuma_secure_knowledge_pipeline.evidence import (
    write_extraction_evidence,
)
from kuma_secure_knowledge_pipeline.extraction.textract import (
    normalize_detect_document_text_response,
)
from kuma_secure_knowledge_pipeline.orchestration import (
    AnalysisInputIntegrityError,
    load_analysis_input,
)


@pytest.fixture
def bundle(tmp_path: Path) -> Path:
    artifact = SourceArtifact(
        artifact_id="art-newline-001",
        filename="synthetic.png",
        media_type="image/png",
        sha256="a" * 64,
    )

    provenance = ExtractionProvenance(
        run_id="run-newline-001",
        provider="amazon-textract",
        operation="DetectDocumentText",
        region="us-east-1",
        started_at_utc="2026-10-09T12:00:00Z",
    )

    raw_response = {
        "Blocks": [
            {
                "BlockType": "LINE",
                "Id": "line-001",
                "Page": 1,
                "Confidence": 99.0,
                "Text": "LINE ONE",
            },
            {
                "BlockType": "LINE",
                "Id": "line-002",
                "Page": 1,
                "Confidence": 99.0,
                "Text": "LINE TWO",
            },
        ]
    }

    result = normalize_detect_document_text_response(
        artifact_id=artifact.artifact_id,
        response=raw_response,
    )

    assert "\n" in result.text
    assert "\r" not in result.text

    return write_extraction_evidence(
        output_root=tmp_path,
        artifact=artifact,
        raw_response=raw_response,
        result=result,
        provenance=provenance,
    )


def _rewrite_line_endings(
    bundle: Path,
    newline: bytes,
    *,
    tamper: bool = False,
) -> None:
    normalized = json.loads((bundle / "normalized.json").read_text(encoding="utf-8"))

    text = normalized["text"]

    assert isinstance(text, str)
    assert "\n" in text
    assert "\r" not in text

    if tamper:
        assert "LINE ONE" in text
        text = text.replace(
            "LINE ONE",
            "FORGED LINE",
            1,
        )

    encoded = text.encode("utf-8").replace(
        b"\n",
        newline,
    )

    (bundle / "extracted.txt").write_bytes(encoded)


def test_accepts_windows_crlf_legacy_evidence(
    bundle: Path,
) -> None:
    _rewrite_line_endings(bundle, b"\r\n")

    context = load_analysis_input(bundle)

    assert context.evidence_block_ids == (
        "line-001",
        "line-002",
    )


def test_accepts_legacy_cr_line_endings(
    bundle: Path,
) -> None:
    _rewrite_line_endings(bundle, b"\r")

    context = load_analysis_input(bundle)

    assert context.artifact_id == "art-newline-001"


def test_accepts_exact_lf_evidence(
    bundle: Path,
) -> None:
    _rewrite_line_endings(bundle, b"\n")

    context = load_analysis_input(bundle)

    assert context.operation == "DetectDocumentText"


def test_rejects_content_tampering_despite_crlf(
    bundle: Path,
) -> None:
    _rewrite_line_endings(
        bundle,
        b"\r\n",
        tamper=True,
    )

    with pytest.raises(AnalysisInputIntegrityError):
        load_analysis_input(bundle)
