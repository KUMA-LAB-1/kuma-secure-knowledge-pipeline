import hashlib
import json
import math
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from kuma_secure_knowledge_pipeline.contracts import ExtractionProvenance
from kuma_secure_knowledge_pipeline.extraction.tesseract import (
    TesseractResponseError,
    normalize_tesseract_tsv,
)
from kuma_secure_knowledge_pipeline.extraction.textract import (
    TextractResponseError,
    normalize_detect_document_text_response,
)
from kuma_secure_knowledge_pipeline.provenance import validate_extraction_provenance


class AnalysisInputIntegrityError(ValueError):
    """Raised when an analysis input violates evidence consistency."""


@dataclass(frozen=True, slots=True)
class AnalysisInput:
    artifact_id: str
    extraction_run_id: str
    source_sha256: str
    provider: str
    operation: str
    text: str
    evidence_block_ids: tuple[str, ...]


_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")


def _reject_duplicate_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    """Reject ambiguous JSON objects, including nested duplicates."""
    result: dict[str, Any] = {}

    for key, value in pairs:
        if key in result:
            raise AnalysisInputIntegrityError(f"Duplicate JSON key: {key}.")
        result[key] = value

    return result


_JSON_BYTE_LIMITS = {
    "manifest.json": 64 * 1024,
    "normalized.json": 16 * 1024 * 1024,
    "raw-response.json": 32 * 1024 * 1024,
}

_MAX_JSON_DEPTH = 64


def _read_json_text_bounded(path: Path) -> str:
    """Read only an approved amount of evidence JSON bytes."""
    limit = _JSON_BYTE_LIMITS.get(path.name)

    if limit is None:
        raise AnalysisInputIntegrityError("Unsupported evidence JSON filename.")

    try:
        with path.open("rb") as stream:
            content = stream.read(limit + 1)
    except OSError as exc:
        raise AnalysisInputIntegrityError("Cannot read evidence JSON.") from exc

    if len(content) > limit:
        raise AnalysisInputIntegrityError(f"Evidence JSON exceeds byte limit: {path.name}.")

    try:
        return content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AnalysisInputIntegrityError(f"Invalid evidence UTF-8: {path.name}.") from exc


def _validate_json_depth(text: str) -> None:
    """Check structural nesting while ignoring quoted JSON content."""
    depth = 0
    in_string = False
    escaped = False

    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
        elif character == '"':
            in_string = True
        elif character in "[{":
            depth += 1

            if depth > _MAX_JSON_DEPTH:
                raise AnalysisInputIntegrityError("Evidence JSON exceeds nesting depth.")
        elif character in "]}":
            depth -= 1


def _reject_json_constant(token: str) -> float:
    """Disallow Python's nonstandard JSON numeric constants."""
    raise AnalysisInputIntegrityError(f"Non-finite JSON constant rejected: {token}.")


def _parse_finite_json_float(token: str) -> float:
    """Reject floating-point overflow during JSON decoding."""
    result = float(token)

    if not math.isfinite(result):
        raise AnalysisInputIntegrityError("Non-finite JSON numeric value rejected.")

    return result


def _json_object(path: Path) -> dict[str, Any]:
    try:
        content = _read_json_text_bounded(path)
        _validate_json_depth(content)

        value = json.loads(
            content,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
            parse_float=_parse_finite_json_float,
        )
    except AnalysisInputIntegrityError:
        raise
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        ValueError,
        RecursionError,
        OverflowError,
    ) as exc:
        raise AnalysisInputIntegrityError(f"Invalid evidence JSON: {path.name}.") from exc

    if not isinstance(value, dict):
        raise AnalysisInputIntegrityError(f"Evidence JSON is not an object: {path.name}.")

    return value


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AnalysisInputIntegrityError(f"Invalid {label} object.")
    return value


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AnalysisInputIntegrityError(f"Invalid {label} value.")
    return value


def _same_typed_structure(actual: Any, expected: Any) -> bool:
    """Compare JSON-like evidence without bool/int/float equivalence."""
    if type(actual) is not type(expected):
        return False

    if isinstance(expected, dict):
        return actual.keys() == expected.keys() and all(
            _same_typed_structure(actual[key], value) for key, value in expected.items()
        )

    if isinstance(expected, list):
        return len(actual) == len(expected) and all(
            _same_typed_structure(left, right) for left, right in zip(actual, expected, strict=True)
        )

    return actual == expected


def _validate_raw_lineage(
    *,
    artifact_id: str,
    provider: str,
    operation: str,
    raw_response: dict[str, Any],
    normalized: dict[str, Any],
) -> None:
    """Check normalized evidence against replayed raw provider data."""

    if provider == "amazon-textract" and operation == "DetectDocumentText":
        try:
            replayed = normalize_detect_document_text_response(
                artifact_id=artifact_id,
                response=raw_response,
            )
        except TextractResponseError as exc:
            raise AnalysisInputIntegrityError("Invalid raw Textract evidence.") from exc

    elif provider == "tesseract" and operation == "TesseractTSV":
        tsv_text = raw_response.get("tsv_text")
        recorded_sha256 = raw_response.get("tsv_sha256")

        if not isinstance(tsv_text, str) or not isinstance(recorded_sha256, str):
            raise AnalysisInputIntegrityError("Invalid raw tsv evidence.")

        actual_sha256 = hashlib.sha256(tsv_text.encode("utf-8")).hexdigest()

        if actual_sha256 != recorded_sha256:
            raise AnalysisInputIntegrityError("Raw tsv SHA-256 mismatch.")

        try:
            replayed = normalize_tesseract_tsv(
                artifact_id=artifact_id,
                tsv_text=tsv_text,
            )
        except TesseractResponseError as exc:
            raise AnalysisInputIntegrityError("Invalid raw tsv evidence.") from exc

    else:
        raise AnalysisInputIntegrityError("Unsupported evidence provider and operation.")

    replayed_payload = asdict(replayed)
    replayed_payload["evidence_refs"] = list(replayed_payload["evidence_refs"])

    if not _same_typed_structure(normalized, replayed_payload):
        raise AnalysisInputIntegrityError("Normalized evidence differs from raw response.")


_EXTRACTED_TEXT_BYTE_LIMIT = 16 * 1024 * 1024


def _read_extracted_text_bounded(path: Path) -> str:
    """Read extracted text with a strict byte budget."""
    try:
        with path.open("rb") as stream:
            content = stream.read(_EXTRACTED_TEXT_BYTE_LIMIT + 1)
    except OSError as exc:
        raise AnalysisInputIntegrityError("Cannot read extracted text.") from exc

    if len(content) > _EXTRACTED_TEXT_BYTE_LIMIT:
        raise AnalysisInputIntegrityError("Extracted text exceeds byte limit.")

    try:
        return content.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
    except UnicodeDecodeError as exc:
        raise AnalysisInputIntegrityError("Invalid extracted text UTF-8.") from exc


def _reject_redirected_ancestors(bundle_dir: Path) -> None:
    """Reject symlinks and Windows junctions in the path ancestry."""
    for component in (bundle_dir, *bundle_dir.parents):
        try:
            redirected = component.is_symlink() or component.is_junction()
        except OSError as exc:
            raise AnalysisInputIntegrityError(
                "Cannot inspect evidence directory ancestry."
            ) from exc

        if redirected:
            raise AnalysisInputIntegrityError("Redirected evidence directory is not allowed.")


def load_analysis_input(bundle_dir: Path) -> AnalysisInput:
    """Build an analysis context from internally consistent evidence.

    This does not authenticate evidence against an external trusted digest.
    """
    _reject_redirected_ancestors(bundle_dir)

    if not bundle_dir.is_dir() or bundle_dir.is_symlink():
        raise AnalysisInputIntegrityError("Invalid evidence bundle directory.")

    filenames = (
        "manifest.json",
        "normalized.json",
        "extracted.txt",
        "raw-response.json",
    )

    paths = {name: bundle_dir / name for name in filenames}

    for name, path in paths.items():
        if not path.is_file() or path.is_symlink():
            raise AnalysisInputIntegrityError(f"Missing or unsafe evidence file: {name}.")

    manifest = _json_object(paths["manifest.json"])
    normalized = _json_object(paths["normalized.json"])
    raw_response = _json_object(paths["raw-response.json"])

    if manifest.get("status") != "success":
        raise AnalysisInputIntegrityError("Evidence status is not success.")

    source = _object(manifest.get("source"), "source")
    run = _object(manifest.get("run"), "run")

    try:
        validate_extraction_provenance(ExtractionProvenance(**run))
    except (TypeError, ValueError) as exc:
        raise AnalysisInputIntegrityError("Invalid extraction provenance.") from exc
    extraction = _object(manifest.get("extraction"), "extraction")

    artifact_id = _text(source.get("artifact_id"), "source artifact_id")
    extraction_run_id = _text(run.get("run_id"), "run_id")
    source_sha256 = _text(source.get("sha256"), "source sha256")

    if not _SHA256_PATTERN.fullmatch(source_sha256):
        raise AnalysisInputIntegrityError("Invalid source sha256 format.")

    provider = _text(run.get("provider"), "provider")
    operation = _text(run.get("operation"), "operation")

    if (
        bundle_dir.parent.parent.name != artifact_id
        or bundle_dir.parent.name != operation
        or bundle_dir.name != extraction_run_id
    ):
        raise AnalysisInputIntegrityError("Evidence bundle path identity mismatch.")

    if normalized.get("artifact_id") != artifact_id:
        raise AnalysisInputIntegrityError("Normalized artifact mismatch.")

    if normalized.get("provider") != provider or extraction.get("provider") != provider:
        raise AnalysisInputIntegrityError("Provider mismatch.")

    if normalized.get("operation") != operation or extraction.get("operation") != operation:
        raise AnalysisInputIntegrityError("Operation mismatch.")

    text = _text(normalized.get("text"), "normalized text")

    extracted = _read_extracted_text_bounded(paths["extracted.txt"])

    if extracted != text:
        raise AnalysisInputIntegrityError("Extracted text mismatch.")

    refs = normalized.get("evidence_refs")

    if not isinstance(refs, list) or not refs:
        raise AnalysisInputIntegrityError("Missing evidence references.")

    evidence_count = extraction.get("evidence_count")

    if type(evidence_count) is not int or evidence_count != len(refs):
        raise AnalysisInputIntegrityError("Evidence reference count mismatch.")

    recorded_confidence = extraction.get("average_confidence")
    normalized_confidence = normalized.get("average_confidence")

    if (
        type(recorded_confidence) not in (int, float)
        or not math.isfinite(recorded_confidence)
        or not _same_typed_structure(
            recorded_confidence,
            normalized_confidence,
        )
    ):
        raise AnalysisInputIntegrityError("Manifest average confidence mismatch.")

    block_ids = []

    for ref in refs:
        ref_obj = _object(ref, "evidence reference")

        if ref_obj.get("artifact_id") != artifact_id:
            raise AnalysisInputIntegrityError("Reference artifact mismatch.")

        block_ids.append(_text(ref_obj.get("block_id"), "evidence block_id"))

    _validate_raw_lineage(
        artifact_id=artifact_id,
        provider=provider,
        operation=operation,
        raw_response=raw_response,
        normalized=normalized,
    )

    return AnalysisInput(
        artifact_id=artifact_id,
        extraction_run_id=extraction_run_id,
        source_sha256=source_sha256,
        provider=provider,
        operation=operation,
        text=text,
        evidence_block_ids=tuple(block_ids),
    )
