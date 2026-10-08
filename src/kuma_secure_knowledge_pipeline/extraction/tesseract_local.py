"""Offline Tesseract adapter with evidence-first publication."""

import hashlib
import re

# Bandit B404/B603 security review:
# Tesseract is an intentional external OCR dependency.
# Execution uses an argv list, shell=False, explicit binary/model
# paths, fixed output flags, timeout and source-integrity checks.
# The caller must provide a trusted local executable.
import subprocess  # nosec B404
from pathlib import Path

from kuma_secure_knowledge_pipeline.artifacts import (
    build_source_artifact,
    verify_artifact_integrity,
)
from kuma_secure_knowledge_pipeline.contracts import SourceArtifact
from kuma_secure_knowledge_pipeline.evidence import (
    reserve_evidence_run,
    write_extraction_evidence,
    write_normalization_failure_evidence,
)
from kuma_secure_knowledge_pipeline.extraction.tesseract import (
    TesseractResponseError,
    normalize_tesseract_tsv,
)
from kuma_secure_knowledge_pipeline.provenance import create_extraction_provenance

MAX_SOURCE_BYTES = 16 * 1024 * 1024
MAX_TSV_BYTES = 4 * 1024 * 1024


class TesseractRuntimeError(RuntimeError):
    """Local OCR execution failed."""


class TesseractSourceError(ValueError):
    """Source artifact or local OCR configuration is invalid."""


def extract_tesseract_raw(
    *,
    artifact: SourceArtifact,
    source_path: Path,
    binary_path: Path,
    tessdata_dir: Path,
    language: str = "por",
    psm: int = 6,
    timeout_seconds: float = 45,
) -> dict[str, object]:
    """Execute explicit offline OCR and preserve the verbatim UTF-8 TSV."""

    if artifact.media_type not in {"image/png", "image/jpeg"}:
        raise TesseractSourceError("Unsupported OCR media type.")

    size = source_path.stat().st_size
    if not 0 < size <= MAX_SOURCE_BYTES:
        raise TesseractSourceError("Source exceeds permitted size budget.")

    with source_path.open("rb") as handle:
        signature = handle.read(8)

    if artifact.media_type == "image/png" and signature != b"\x89PNG\r\n\x1a\n":
        raise TesseractSourceError("Invalid PNG signature.")

    if artifact.media_type == "image/jpeg" and not signature.startswith(b"\xff\xd8\xff"):
        raise TesseractSourceError("Invalid JPEG signature.")

    verify_artifact_integrity(source_path, artifact)

    if not isinstance(language, str) or not re.fullmatch(r"[A-Za-z0-9_]+", language):
        raise TesseractSourceError("Invalid OCR language.")

    if isinstance(psm, bool) or psm not in {3, 6, 11}:
        raise TesseractSourceError("Unsupported PSM.")

    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not 0 < timeout_seconds <= 120
    ):
        raise TesseractSourceError("Invalid OCR timeout.")

    if not binary_path.is_file() or not (tessdata_dir / f"{language}.traineddata").is_file():
        raise TesseractSourceError("Local OCR runtime unavailable.")

    command = [
        str(binary_path),
        str(source_path),
        "stdout",
        "-l",
        language,
        "--tessdata-dir",
        str(tessdata_dir),
        "--psm",
        str(psm),
        "-c",
        "tessedit_create_tsv=1",
        "-c",
        "tessedit_create_txt=0",
    ]

    try:
        completed = subprocess.run(  # nosec B603
            command,
            capture_output=True,
            timeout=timeout_seconds,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise TesseractRuntimeError("Local OCR process failed or timed out.") from exc

    if completed.returncode != 0:
        raise TesseractRuntimeError("Local OCR process returned a nonzero exit code.")

    raw = completed.stdout

    if not raw or len(raw) > MAX_TSV_BYTES:
        raise TesseractRuntimeError("OCR TSV output violates size bounds.")

    verify_artifact_integrity(source_path, artifact)

    try:
        tsv_text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise TesseractRuntimeError("OCR TSV is not valid UTF-8.") from exc

    return {
        "format": "tsv",
        "engine": "tesseract",
        "language": language,
        "psm": psm,
        "tsv_text": tsv_text,
        "tsv_sha256": hashlib.sha256(raw).hexdigest(),
    }


def run_local_tesseract_pipeline(
    *,
    source_path: Path,
    output_root: Path,
    binary_path: Path,
    tessdata_dir: Path,
    language: str = "por",
    psm: int = 6,
    timeout_seconds: float = 45,
    run_id: str | None = None,
) -> Path:
    """Run offline OCR and publish immutable raw/normalized evidence."""

    artifact = build_source_artifact(source_path)

    provenance = create_extraction_provenance(
        provider="tesseract",
        operation="TesseractTSV",
        region="local",
        run_id=run_id,
    )

    with reserve_evidence_run(
        output_root=output_root,
        artifact_id=artifact.artifact_id,
        operation=provenance.operation,
        run_id=provenance.run_id,
    ) as reservation:
        raw = extract_tesseract_raw(
            artifact=artifact,
            source_path=source_path,
            binary_path=binary_path,
            tessdata_dir=tessdata_dir,
            language=language,
            psm=psm,
            timeout_seconds=timeout_seconds,
        )

        try:
            result = normalize_tesseract_tsv(
                artifact_id=artifact.artifact_id,
                tsv_text=raw["tsv_text"],
            )
        except TesseractResponseError as exc:
            write_normalization_failure_evidence(
                output_root=output_root,
                artifact=artifact,
                raw_response=raw,
                provenance=provenance,
                error_type=type(exc).__name__,
            )
            reservation.resolve()
            raise

        evidence_dir = write_extraction_evidence(
            output_root=output_root,
            artifact=artifact,
            raw_response=raw,
            result=result,
            provenance=provenance,
        )

        reservation.resolve()
        return evidence_dir
