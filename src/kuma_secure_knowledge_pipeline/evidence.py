import json
import re
import shutil
import tempfile
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import asdict
from pathlib import Path
from typing import Any

from kuma_secure_knowledge_pipeline.contracts import (
    ExtractionResult,
    SourceArtifact,
)


class EvidenceSerializationError(TypeError):
    """Raised when evidence cannot be serialized without coercion."""


class EvidenceIntegrityError(ValueError):
    """Raised when evidence relationships violate integrity constraints."""


class EvidenceAlreadyExistsError(FileExistsError):
    """Raised when an immutable evidence bundle already exists."""


_SAFE_COMPONENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def _validate_path_component(
    value: str,
    *,
    label: str,
) -> str:
    if not isinstance(value, str) or not _SAFE_COMPONENT.fullmatch(value):
        raise EvidenceIntegrityError(f"{label} contains characters unsafe for an evidence path.")

    return value


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


def _remove_empty_directory(
    directory: Path,
) -> None:
    with suppress(OSError):
        directory.rmdir()


def write_extraction_evidence(
    *,
    output_root: Path,
    artifact: SourceArtifact,
    raw_response: Mapping[str, Any],
    result: ExtractionResult,
) -> Path:
    if result.artifact_id != artifact.artifact_id:
        raise EvidenceIntegrityError("Extraction result does not belong to the supplied artifact.")

    if any(reference.artifact_id != artifact.artifact_id for reference in result.evidence_refs):
        raise EvidenceIntegrityError(
            "Extraction result contains evidence references for a different artifact."
        )

    artifact_component = _validate_path_component(
        artifact.artifact_id,
        label="artifact_id",
    )

    operation_component = _validate_path_component(
        result.operation,
        label="operation",
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

    # Serialize all evidence before touching the filesystem.
    raw_json = _serialize_json(dict(raw_response))
    normalized_json = _serialize_json(asdict(result))
    manifest_json = _serialize_json(manifest)

    artifact_root = output_root / artifact_component
    evidence_dir = artifact_root / operation_component

    if evidence_dir.exists():
        raise EvidenceAlreadyExistsError(
            f"Evidence bundle already exists: {artifact_component}/{operation_component}"
        )

    artifact_root.mkdir(
        parents=True,
        exist_ok=True,
    )

    temporary_dir = Path(
        tempfile.mkdtemp(
            prefix=f".{operation_component}.tmp-",
            dir=artifact_root,
        )
    )

    try:
        _write_text(
            temporary_dir / "raw-response.json",
            raw_json,
        )

        _write_text(
            temporary_dir / "normalized.json",
            normalized_json,
        )

        _write_text(
            temporary_dir / "manifest.json",
            manifest_json,
        )

        _write_text(
            temporary_dir / "extracted.txt",
            result.text,
        )

        try:
            temporary_dir.rename(evidence_dir)
        except OSError as exc:
            if evidence_dir.exists():
                raise EvidenceAlreadyExistsError(
                    f"Evidence bundle already exists: {artifact_component}/{operation_component}"
                ) from exc

            raise

    except Exception:
        shutil.rmtree(
            temporary_dir,
            ignore_errors=True,
        )

        _remove_empty_directory(
            artifact_root,
        )

        raise

    return evidence_dir
