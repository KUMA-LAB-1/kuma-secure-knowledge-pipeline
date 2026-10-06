import json
from collections.abc import Mapping
from dataclasses import asdict
from pathlib import Path
from typing import Any

from kuma_secure_knowledge_pipeline.contracts import (
    ExtractionResult,
    SourceArtifact,
)


def _write_json(
    destination: Path,
    payload: Any,
) -> None:
    destination.write_text(
        json.dumps(
            payload,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
            default=str,
        ),
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
        raise ValueError(
            "Extraction result does not belong to the supplied artifact."
        )

    evidence_dir = output_root / artifact.artifact_id
    evidence_dir.mkdir(parents=True, exist_ok=True)

    _write_json(
        evidence_dir / "raw-response.json",
        dict(raw_response),
    )

    _write_json(
        evidence_dir / "normalized.json",
        asdict(result),
    )

    manifest = {
        "source": asdict(artifact),
        "extraction": {
            "provider": result.provider,
            "operation": result.operation,
            "average_confidence": result.average_confidence,
            "evidence_count": len(result.evidence_refs),
        },
    }

    _write_json(
        evidence_dir / "manifest.json",
        manifest,
    )

    (evidence_dir / "extracted.txt").write_text(
        result.text,
        encoding="utf-8",
    )

    return evidence_dir
