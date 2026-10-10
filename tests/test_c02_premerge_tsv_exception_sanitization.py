"""Security regression tests for untrusted numeric values in Tesseract TSV.

Synthetic data only. No real OCR records, provider calls, or AWS.
"""

import hashlib
import traceback

import pytest

from kuma_secure_knowledge_pipeline.extraction.tesseract import (
    TSV_COLUMNS,
    TesseractResponseError,
    normalize_tesseract_tsv,
)
from kuma_secure_knowledge_pipeline.orchestration import (
    AnalysisInputIntegrityError,
    _validate_raw_lineage,
)

CANARY = "KUMA_SYNTHETIC_TSV_NUMERIC_CANARY"

COLUMNS = ("level", "page_num", "conf")


def _invalid_tsv(column: str) -> str:
    fields = [
        "5",
        "1",
        "1",
        "1",
        "1",
        "1",
        "0",
        "0",
        "10",
        "10",
        "95",
        "DEMO",
    ]

    fields[TSV_COLUMNS.index(column)] = CANARY

    return "\t".join(TSV_COLUMNS) + "\n" + "\t".join(fields) + "\n"


def _assert_sanitized(error: BaseException) -> None:
    assert error.__cause__ is None
    assert error.__context__ is None
    assert CANARY not in str(error)

    rendered = "".join(traceback.format_exception(error))
    assert CANARY not in rendered


@pytest.mark.parametrize("column", COLUMNS)
def test_tesseract_numeric_parser_does_not_retain_input(
    column: str,
) -> None:
    tsv_text = _invalid_tsv(column)

    with pytest.raises(TesseractResponseError) as caught:
        normalize_tesseract_tsv(
            artifact_id="art-synthetic-tsv",
            tsv_text=tsv_text,
        )

    _assert_sanitized(caught.value)


@pytest.mark.parametrize("column", COLUMNS)
def test_orchestration_tsv_replay_does_not_retain_input(
    column: str,
) -> None:
    tsv_text = _invalid_tsv(column)

    raw_response = {
        "tsv_text": tsv_text,
        "tsv_sha256": hashlib.sha256(tsv_text.encode("utf-8")).hexdigest(),
    }

    with pytest.raises(AnalysisInputIntegrityError) as caught:
        _validate_raw_lineage(
            artifact_id="art-synthetic-tsv",
            provider="tesseract",
            operation="TesseractTSV",
            raw_response=raw_response,
            normalized={},
        )

    _assert_sanitized(caught.value)
