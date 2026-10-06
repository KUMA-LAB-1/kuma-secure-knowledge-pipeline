from kuma_secure_knowledge_pipeline.extraction.textract import (
    normalize_detect_document_text_response,
)


def test_textract_normalizer_extracts_lines_and_preserves_evidence() -> None:
    response = {
        "Blocks": [
            {
                "BlockType": "LINE",
                "Id": "line-001",
                "Page": 1,
                "Confidence": 99.0,
                "Text": "INCIDENT ID: INC-001",
            },
            {
                "BlockType": "WORD",
                "Id": "word-001",
                "Page": 1,
                "Confidence": 99.8,
                "Text": "INCIDENT",
            },
            {
                "BlockType": "LINE",
                "Id": "line-002",
                "Page": 1,
                "Confidence": 97.5,
                "Text": "SEVERITY: HIGH",
            },
        ]
    }

    result = normalize_detect_document_text_response(
        artifact_id="art-001",
        response=response,
    )

    assert result.provider == "amazon-textract"
    assert result.operation == "DetectDocumentText"
    assert result.text == "INCIDENT ID: INC-001\nSEVERITY: HIGH"
    assert result.average_confidence == 98.25

    assert len(result.evidence_refs) == 2

    assert result.evidence_refs[0].block_id == "line-001"
    assert result.evidence_refs[0].page == 1
    assert result.evidence_refs[0].confidence == 99.0

    assert result.evidence_refs[1].block_id == "line-002"


def test_textract_normalizer_handles_empty_response() -> None:
    result = normalize_detect_document_text_response(
        artifact_id="art-empty",
        response={"Blocks": []},
    )

    assert result.text == ""
    assert result.average_confidence == 0.0
    assert result.evidence_refs == ()
