from collections.abc import Mapping
from typing import Any

from kuma_secure_knowledge_pipeline.contracts import (
    EvidenceReference,
    ExtractionResult,
)


def normalize_detect_document_text_response(
    *,
    artifact_id: str,
    response: Mapping[str, Any],
) -> ExtractionResult:
    """Normalize an Amazon Textract DetectDocumentText response."""

    lines: list[str] = []
    evidence_refs: list[EvidenceReference] = []

    for block in response.get("Blocks", []):
        if not isinstance(block, Mapping):
            continue

        if block.get("BlockType") != "LINE":
            continue

        text = str(block.get("Text", "")).strip()

        if not text:
            continue

        confidence = float(block.get("Confidence", 0.0))
        page = int(block.get("Page", 1))
        block_id = str(block.get("Id", ""))

        lines.append(text)

        evidence_refs.append(
            EvidenceReference(
                artifact_id=artifact_id,
                block_id=block_id,
                page=page,
                confidence=confidence,
            )
        )

    average_confidence = (
        sum(reference.confidence for reference in evidence_refs)
        / len(evidence_refs)
        if evidence_refs
        else 0.0
    )

    return ExtractionResult(
        artifact_id=artifact_id,
        provider="amazon-textract",
        operation="DetectDocumentText",
        text="\n".join(lines),
        average_confidence=round(average_confidence, 2),
        evidence_refs=tuple(evidence_refs),
    )
