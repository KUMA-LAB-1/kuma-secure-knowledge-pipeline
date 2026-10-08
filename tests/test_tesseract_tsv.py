"""RED contracts for provider-neutral Tesseract TSV normalization."""

import pytest

from kuma_secure_knowledge_pipeline.extraction.tesseract import (
    TesseractResponseError,
    normalize_tesseract_tsv,
)

HEADER = (
    "level\tpage_num\tblock_num\tpar_num\tline_num\tword_num\tleft\ttop\twidth\theight\tconf\ttext"
)


def _word(line: int, word: int, conf: str, text: str) -> str:
    return f"5\t1\t1\t1\t{line}\t{word}\t0\t0\t10\t10\t{conf}\t{text}"


def _sample_tsv(*, login_conf: str = "94") -> str:
    return (
        "\n".join(
            (
                HEADER,
                "4\t1\t1\t1\t1\t0\t0\t0\t10\t10\t-1\t",
                _word(1, 1, "98", "Failed"),
                _word(1, 2, login_conf, "Logins"),
                _word(1, 3, "96", "7"),
                _word(2, 1, "92", "MITRE"),
                _word(2, 2, "90", "T1110"),
            )
        )
        + "\n"
    )


def test_tesseract_tsv_preserves_raw_ocr_text_and_evidence() -> None:
    result = normalize_tesseract_tsv(
        artifact_id="art-001",
        tsv_text=_sample_tsv(),
    )

    assert result.artifact_id == "art-001"
    assert result.provider == "tesseract"
    assert result.operation == "TesseractTSV"

    # Never silently correct 7 to the visual ground truth 17.
    assert result.text == "Failed Logins 7\nMITRE T1110"
    assert "17" not in result.text

    assert result.average_confidence == 94.0
    assert len(result.evidence_refs) == 5

    first = result.evidence_refs[0]
    assert first.artifact_id == "art-001"
    assert first.block_id == "tsv-row-3"
    assert first.page == 1
    assert first.confidence == 98.0


@pytest.mark.parametrize(
    "invalid_confidence",
    ["-1", "101", "nan", "invalid"],
)
def test_tesseract_rejects_invalid_word_confidence(
    invalid_confidence: str,
) -> None:
    with pytest.raises(
        TesseractResponseError,
        match="confidence",
    ):
        normalize_tesseract_tsv(
            artifact_id="art-001",
            tsv_text=_sample_tsv(
                login_conf=invalid_confidence,
            ),
        )


def test_tesseract_rejects_missing_required_columns() -> None:
    malformed = _sample_tsv().replace(
        "conf\ttext",
        "score\ttext",
    )

    with pytest.raises(
        TesseractResponseError,
        match="columns",
    ):
        normalize_tesseract_tsv(
            artifact_id="art-001",
            tsv_text=malformed,
        )


def test_tesseract_rejects_no_recognized_words() -> None:
    empty = (
        "\n".join(
            (
                HEADER,
                "4\t1\t1\t1\t1\t0\t0\t0\t10\t10\t-1\t",
            )
        )
        + "\n"
    )

    with pytest.raises(
        TesseractResponseError,
        match="no WORD rows",
    ):
        normalize_tesseract_tsv(
            artifact_id="art-001",
            tsv_text=empty,
        )
