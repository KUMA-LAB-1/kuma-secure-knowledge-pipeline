import json
from collections.abc import Mapping
from dataclasses import asdict
from pathlib import Path
from typing import Any

from kuma_secure_knowledge_pipeline.contracts import (
    ExtractionResult,
    SourceArtifact,
)


class EvidenceSerializationError(TypeError):
    """Raised when evidence cannot be serialized without coercion."""


def _serialize_json(payload: Any) -> str:
    try:
        return json.dumps(
            payload,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
    except TypeError as exc:
        raise EvidenceSerializationError(
            "Evidence contains data that is not JSON serializable."
        ) from exc


def _write_text(
    destination: Path,
    content: str,
) -> None:
    destination.write_text(
        content,
        encoding="utf-8",
    )


def write_extraction_evidence(
    *,
    output_root: Path,
    artifact: SourceArtifact,
    raw_response: Mapping[str, Any],
    result: ExtractionResult,
) -> Path:
    if result.artifact_id != artifact.artifact_id:
        raise ValueError("Extraction result does not belong to the supplied artifact.")

    manifest = {
        "source": asdict(artifact),
        "extraction": {
            "provider": result.provider,
            "operation": result.operation,
            "average_confidence": result.average_confidence,
            "evidence_count": len(result.evidence_refs),
        },
    }

    # Serialize everything before creating any evidence directory.
    # A type error therefore fails closed without partial evidence.
    raw_json = _serialize_json(dict(raw_response))
    normalized_json = _serialize_json(asdict(result))
    manifest_json = _serialize_json(manifest)

    evidence_dir = output_root / artifact.artifact_id
    evidence_dir.mkdir(parents=True, exist_ok=True)

    _write_text(
        evidence_dir / "raw-response.json",
        raw_json,
    )

    _write_text(
        evidence_dir / "normalized.json",
        normalized_json,
    )

    _write_text(
        evidence_dir / "manifest.json",
        manifest_json,
    )

    _write_text(
        evidence_dir / "extracted.txt",
        result.text,
    )

    return evidence_dir
