"""Strict, offline normalization of Tesseract TSV output."""

import math

from kuma_secure_knowledge_pipeline.contracts import (
    EvidenceReference,
    ExtractionResult,
)

TESSERACT_PROVIDER = "tesseract"
TESSERACT_TSV_OPERATION = "TesseractTSV"

TSV_COLUMNS = (
    "level",
    "page_num",
    "block_num",
    "par_num",
    "line_num",
    "word_num",
    "left",
    "top",
    "width",
    "height",
    "conf",
    "text",
)


class TesseractResponseError(ValueError):
    """Raised when a Tesseract TSV response violates its contract."""


def _positive_integer(value: str, *, field: str) -> int:
    """Parse a positive TSV identifier without accepting invalid values."""
    try:
        number = int(value)
    except ValueError as exc:
        raise TesseractResponseError(f"Tesseract TSV has invalid {field}.") from exc

    if number < 1:
        raise TesseractResponseError(f"Tesseract TSV has invalid {field}.")

    return number


def _word_confidence(value: str) -> float:
    """Validate confidence on a recognized WORD row."""
    try:
        confidence = float(value)
    except ValueError as exc:
        raise TesseractResponseError("Tesseract WORD confidence must be numeric.") from exc

    if not math.isfinite(confidence) or not 0.0 <= confidence <= 100.0:
        raise TesseractResponseError("Tesseract WORD confidence must be between 0 and 100.")

    return confidence


def normalize_tesseract_tsv(
    *,
    artifact_id: str,
    tsv_text: str,
) -> ExtractionResult:
    """Normalize recognized words while preserving TSV row references.

    This function does not execute an OCR engine or alter raw TSV.
    The caller is responsible for separately preserving raw evidence.
    """

    if not isinstance(artifact_id, str) or not artifact_id.strip():
        raise TesseractResponseError("artifact_id must be a non-empty string.")

    if not isinstance(tsv_text, str):
        raise TesseractResponseError("Tesseract TSV must be a string.")

    raw_rows = tsv_text.splitlines()

    if not raw_rows:
        raise TesseractResponseError("Tesseract TSV is missing required columns.")

    header = raw_rows[0].removeprefix("\ufeff").split("\t")

    if tuple(header) != TSV_COLUMNS:
        raise TesseractResponseError("Tesseract TSV has invalid or missing columns.")

    normalized_lines: list[str] = []
    current_words: list[str] = []
    references: list[EvidenceReference] = []
    current_group: tuple[int, int, int, int] | None = None

    for row_number, raw_row in enumerate(raw_rows[1:], start=2):
        # Split at most 11 times to preserve the last text field.
        fields = raw_row.split("\t", 11)

        if len(fields) != len(TSV_COLUMNS):
            raise TesseractResponseError(f"Tesseract TSV row {row_number} has invalid columns.")

        try:
            level = int(fields[0])
        except ValueError as exc:
            raise TesseractResponseError(
                f"Tesseract TSV row {row_number} has invalid level."
            ) from exc

        if level not in (1, 2, 3, 4, 5):
            raise TesseractResponseError(f"Tesseract TSV row {row_number} has invalid level.")

        # Layout rows may legitimately have confidence -1.
        # Only WORD rows represent recognized text.
        if level != 5:
            continue

        text = fields[11]

        if not text.strip():
            raise TesseractResponseError(f"Tesseract TSV WORD row {row_number} has empty text.")

        page = _positive_integer(fields[1], field="page_num")
        block = _positive_integer(fields[2], field="block_num")
        paragraph = _positive_integer(fields[3], field="par_num")
        line = _positive_integer(fields[4], field="line_num")

        _positive_integer(fields[5], field="word_num")

        confidence = _word_confidence(fields[10])

        # Include the complete hierarchy so reused line numbers
        # in different blocks or pages are not merged.
        group = (page, block, paragraph, line)

        if current_group is not None and group != current_group:
            normalized_lines.append(" ".join(current_words))
            current_words = []

        current_group = group
        current_words.append(text)

        # Reference the physical TSV source row, not a generated ID
        # unrelated to the original OCR response.
        references.append(
            EvidenceReference(
                artifact_id=artifact_id,
                block_id=f"tsv-row-{row_number}",
                page=page,
                confidence=confidence,
            )
        )

    if not references:
        raise TesseractResponseError("Tesseract TSV contains no WORD rows.")

    normalized_lines.append(" ".join(current_words))

    average_confidence = round(
        sum(reference.confidence for reference in references) / len(references),
        2,
    )

    return ExtractionResult(
        artifact_id=artifact_id,
        provider=TESSERACT_PROVIDER,
        operation=TESSERACT_TSV_OPERATION,
        text="\n".join(normalized_lines),
        average_confidence=average_confidence,
        evidence_refs=tuple(references),
    )
