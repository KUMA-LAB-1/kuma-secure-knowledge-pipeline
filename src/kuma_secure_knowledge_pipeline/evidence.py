import json
import re
import shutil
import tempfile
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager, suppress
from dataclasses import asdict
from pathlib import Path
from typing import Any

from kuma_secure_knowledge_pipeline.contracts import (
    ExtractionProvenance,
    ExtractionResult,
    SourceArtifact,
)
from kuma_secure_knowledge_pipeline.provenance import (
    validate_extraction_provenance,
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


def _serialize_json(
    payload: Any,
) -> str:
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


def _validate_run_relationships(
    *,
    provenance: ExtractionProvenance,
    provider: str,
    operation: str,
) -> None:
    validate_extraction_provenance(provenance)

    if provenance.provider != provider:
        raise EvidenceIntegrityError("Provenance provider does not match the evidence provider.")

    if provenance.operation != operation:
        raise EvidenceIntegrityError("Provenance operation does not match the evidence operation.")


def _publish_bundle(
    *,
    output_root: Path,
    artifact_component: str,
    operation_component: str,
    run_component: str,
    files: Sequence[tuple[str, str]],
) -> Path:
    artifact_root = output_root / artifact_component

    operation_root = artifact_root / operation_component

    evidence_dir = operation_root / run_component

    if evidence_dir.exists():
        raise EvidenceAlreadyExistsError(
            "Evidence bundle already exists: "
            f"{artifact_component}/"
            f"{operation_component}/"
            f"{run_component}"
        )

    operation_root.mkdir(
        parents=True,
        exist_ok=True,
    )

    temporary_dir = Path(
        tempfile.mkdtemp(
            prefix=f".{run_component}.tmp-",
            dir=operation_root,
        )
    )

    try:
        for filename, content in files:
            _write_text(
                temporary_dir / filename,
                content,
            )

        try:
            temporary_dir.rename(evidence_dir)
        except OSError as exc:
            if evidence_dir.exists():
                raise EvidenceAlreadyExistsError(
                    "Evidence bundle already exists: "
                    f"{artifact_component}/"
                    f"{operation_component}/"
                    f"{run_component}"
                ) from exc

            raise

    except Exception:
        shutil.rmtree(
            temporary_dir,
            ignore_errors=True,
        )

        _remove_empty_directory(operation_root)

        _remove_empty_directory(artifact_root)

        raise

    return evidence_dir


class EvidenceRunReservation:
    """Fail-closed handle for one reserved evidence run."""

    def __init__(
        self,
        *,
        reservation_path: Path,
        operation_root: Path,
        artifact_root: Path,
    ) -> None:
        self._reservation_path = reservation_path
        self._operation_root = operation_root
        self._artifact_root = artifact_root
        self._resolved = False

    def resolve(self) -> None:
        """Release a reservation only after durable evidence exists."""

        if self._resolved:
            return

        with suppress(FileNotFoundError):
            self._reservation_path.unlink()

        _remove_empty_directory(
            self._operation_root,
        )

        _remove_empty_directory(
            self._artifact_root,
        )

        self._resolved = True


@contextmanager
def reserve_evidence_run(
    *,
    output_root: Path,
    artifact_id: str,
    operation: str,
    run_id: str,
) -> Iterator[EvidenceRunReservation]:
    """Atomically reserve one local evidence run.

    Reservations are fail-closed by default. The caller must explicitly
    resolve the handle only after durable success or durable classified
    failure evidence has been published.
    """

    artifact_component = _validate_path_component(
        artifact_id,
        label="artifact_id",
    )

    operation_component = _validate_path_component(
        operation,
        label="operation",
    )

    run_component = _validate_path_component(
        run_id,
        label="run_id",
    )

    artifact_root = output_root / artifact_component

    operation_root = artifact_root / operation_component

    evidence_dir = operation_root / run_component

    reservation_path = operation_root / f".{run_component}.reservation"

    operation_root.mkdir(
        parents=True,
        exist_ok=True,
    )

    try:
        reservation_path.touch(
            exist_ok=False,
        )
    except FileExistsError as exc:
        raise EvidenceAlreadyExistsError(
            "Evidence run is already reserved: "
            f"{artifact_component}/"
            f"{operation_component}/"
            f"{run_component}"
        ) from exc
    except Exception:
        _remove_empty_directory(
            operation_root,
        )

        _remove_empty_directory(
            artifact_root,
        )

        raise

    if evidence_dir.exists():
        with suppress(FileNotFoundError):
            reservation_path.unlink()

        _remove_empty_directory(
            operation_root,
        )

        _remove_empty_directory(
            artifact_root,
        )

        raise EvidenceAlreadyExistsError(
            "Evidence bundle already exists: "
            f"{artifact_component}/"
            f"{operation_component}/"
            f"{run_component}"
        )

    reservation = EvidenceRunReservation(
        reservation_path=reservation_path,
        operation_root=operation_root,
        artifact_root=artifact_root,
    )

    yield reservation


def write_extraction_evidence(
    *,
    output_root: Path,
    artifact: SourceArtifact,
    raw_response: Mapping[str, Any],
    result: ExtractionResult,
    provenance: ExtractionProvenance,
) -> Path:
    if result.artifact_id != artifact.artifact_id:
        raise EvidenceIntegrityError("Extraction result does not belong to the supplied artifact.")

    if any(reference.artifact_id != artifact.artifact_id for reference in result.evidence_refs):
        raise EvidenceIntegrityError(
            "Extraction result contains evidence references for a different artifact."
        )

    _validate_run_relationships(
        provenance=provenance,
        provider=result.provider,
        operation=result.operation,
    )

    artifact_component = _validate_path_component(
        artifact.artifact_id,
        label="artifact_id",
    )

    operation_component = _validate_path_component(
        result.operation,
        label="operation",
    )

    run_component = _validate_path_component(
        provenance.run_id,
        label="run_id",
    )

    manifest = {
        "status": "success",
        "source": asdict(artifact),
        "run": asdict(provenance),
        "extraction": {
            "provider": result.provider,
            "operation": result.operation,
            "average_confidence": result.average_confidence,
            "evidence_count": len(result.evidence_refs),
        },
    }

    raw_json = _serialize_json(dict(raw_response))

    normalized_json = _serialize_json(asdict(result))

    manifest_json = _serialize_json(manifest)

    return _publish_bundle(
        output_root=output_root,
        artifact_component=artifact_component,
        operation_component=operation_component,
        run_component=run_component,
        files=(
            (
                "raw-response.json",
                raw_json,
            ),
            (
                "normalized.json",
                normalized_json,
            ),
            (
                "manifest.json",
                manifest_json,
            ),
            (
                "extracted.txt",
                result.text,
            ),
        ),
    )


def write_normalization_failure_evidence(
    *,
    output_root: Path,
    artifact: SourceArtifact,
    raw_response: Mapping[str, Any],
    provenance: ExtractionProvenance,
    error_type: str,
) -> Path:
    validate_extraction_provenance(provenance)

    if not isinstance(error_type, str) or not error_type.strip():
        raise EvidenceIntegrityError("error_type must be a non-empty string.")

    artifact_component = _validate_path_component(
        artifact.artifact_id,
        label="artifact_id",
    )

    operation_component = _validate_path_component(
        provenance.operation,
        label="operation",
    )

    run_component = _validate_path_component(
        provenance.run_id,
        label="run_id",
    )

    manifest = {
        "status": "normalization_failed",
        "source": asdict(artifact),
        "run": asdict(provenance),
        "failure": {
            "stage": "normalization",
            "error_type": error_type,
        },
    }

    raw_json = _serialize_json(dict(raw_response))

    manifest_json = _serialize_json(manifest)

    return _publish_bundle(
        output_root=output_root,
        artifact_component=artifact_component,
        operation_component=operation_component,
        run_component=run_component,
        files=(
            (
                "raw-response.json",
                raw_json,
            ),
            (
                "manifest.json",
                manifest_json,
            ),
        ),
    )
