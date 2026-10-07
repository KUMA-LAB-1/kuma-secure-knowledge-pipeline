import pytest

from kuma_secure_knowledge_pipeline.extraction.textract import (
    TextractResponseError,
    normalize_detect_document_text_response,
)


def _line(
    *,
    text="SECURITY INCIDENT",
    confidence=99.0,
    page=1,
):
    return {
        "BlockType": "LINE",
        "Id": "line-001",
        "Text": text,
        "Confidence": confidence,
        "Page": page,
    }


@pytest.mark.parametrize(
    "invalid_text",
    [
        123,
        True,
        ["SECURITY INCIDENT"],
        {"text": "SECURITY INCIDENT"},
    ],
)
def test_textract_rejects_non_string_line_text(
    invalid_text,
) -> None:
    with pytest.raises(
        TextractResponseError,
        match="Text",
    ):
        normalize_detect_document_text_response(
            artifact_id="art-invalid",
            response={
                "Blocks": [
                    _line(text=invalid_text),
                ]
            },
        )


@pytest.mark.parametrize(
    "invalid_confidence",
    [
        True,
        "99.0",
        None,
        float("nan"),
        float("inf"),
        float("-inf"),
    ],
)
def test_textract_rejects_non_numeric_confidence(
    invalid_confidence,
) -> None:
    with pytest.raises(
        TextractResponseError,
        match="Confidence",
    ):
        normalize_detect_document_text_response(
            artifact_id="art-invalid",
            response={
                "Blocks": [
                    _line(confidence=invalid_confidence),
                ]
            },
        )


@pytest.mark.parametrize(
    "invalid_page",
    [
        True,
        1.5,
        "1",
        None,
    ],
)
def test_textract_rejects_non_integer_page(
    invalid_page,
) -> None:
    with pytest.raises(
        TextractResponseError,
        match="Page",
    ):
        normalize_detect_document_text_response(
            artifact_id="art-invalid",
            response={
                "Blocks": [
                    _line(page=invalid_page),
                ]
            },
        )


def test_textract_preserves_provider_block_id_exactly() -> None:
    provider_id = " line-001 "

    response = {
        "Blocks": [
            {
                **_line(),
                "Id": provider_id,
            }
        ]
    }

    result = normalize_detect_document_text_response(
        artifact_id="art-001",
        response=response,
    )

    assert result.evidence_refs[0].block_id == provider_id


@pytest.mark.parametrize(
    "empty_text",
    [
        "",
        "   ",
        "\t",
    ],
)
def test_textract_rejects_empty_line_text(
    empty_text: str,
) -> None:
    with pytest.raises(
        TextractResponseError,
        match="must not be empty",
    ):
        normalize_detect_document_text_response(
            artifact_id="art-invalid",
            response={
                "Blocks": [
                    _line(text=empty_text),
                ]
            },
        )
