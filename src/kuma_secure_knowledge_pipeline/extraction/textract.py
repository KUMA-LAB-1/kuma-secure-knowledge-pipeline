import math
from collections.abc import Mapping
from typing import Any

from kuma_secure_knowledge_pipeline.contracts import (
    EvidenceReference,
    ExtractionResult,
)


class TextractResponseError(ValueError):
    """Raised when a Textract response violates the expected contract."""


def normalize_detect_document_text_response(
    *,
    artifact_id: str,
    response: Mapping[str, Any],
) -> ExtractionResult:
    """Normalize a validated Amazon Textract DetectDocumentText response."""

    blocks = response.get("Blocks")

    if not isinstance(blocks, list):
        raise TextractResponseError("Textract response field 'Blocks' must be a list.")

    lines: list[str] = []
    evidence_refs: list[EvidenceReference] = []

    for block in blocks:
        if not isinstance(block, Mapping):
            raise TextractResponseError("Textract Block entries must be mappings.")

        if block.get("BlockType") != "LINE":
            continue

        text_value = block.get("Text")

        if not isinstance(text_value, str):
            raise TextractResponseError("Textract LINE block Text must be a string.")

        text = text_value.strip()

        if not text:
            raise TextractResponseError("Textract LINE block Text must not be empty.")

        block_id_value = block.get("Id")

        if not isinstance(block_id_value, str) or not block_id_value.strip():
            raise TextractResponseError("Textract LINE block is missing a valid Id.")

        # Block IDs are opaque provider identifiers.
        # Preserve them exactly so EvidenceReference maps byte-for-byte
        # to the identifier stored in the raw provider response.
        block_id = block_id_value

        confidence_value = block.get("Confidence")

        if isinstance(confidence_value, bool) or not isinstance(
            confidence_value,
            (int, float),
        ):
            raise TextractResponseError("Textract LINE block has invalid Confidence.")

        confidence = float(confidence_value)

        if not math.isfinite(confidence) or not 0.0 <= confidence <= 100.0:
            raise TextractResponseError("Textract LINE block Confidence must be between 0 and 100.")

        page_value = block.get("Page")

        if isinstance(page_value, bool) or not isinstance(page_value, int):
            raise TextractResponseError("Textract LINE block has invalid Page.")

        page = page_value

        if page < 1:
            raise TextractResponseError("Textract LINE block Page must be >= 1.")

        lines.append(text)

        evidence_refs.append(
            EvidenceReference(
                artifact_id=artifact_id,
                block_id=block_id,
                page=page,
                confidence=confidence,
            )
        )

    if not evidence_refs:
        raise TextractResponseError("Textract response contains no valid LINE blocks.")

    average_confidence = sum(reference.confidence for reference in evidence_refs) / len(
        evidence_refs
    )

    return ExtractionResult(
        artifact_id=artifact_id,
        provider="amazon-textract",
        operation="DetectDocumentText",
        text="\n".join(lines),
        average_confidence=round(
            average_confidence,
            2,
        ),
        evidence_refs=tuple(evidence_refs),
    )
