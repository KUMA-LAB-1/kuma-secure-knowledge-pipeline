"""Offline content-addressed stage storage, independent of AWS and GenAI SDKs.

Root is operator-controlled private storage, not an untrusted or shared folder.
A SHA-256 reference detects accidental corruption, not malicious replacement
by an actor who controls both the store and its index.
"""

import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any


class StageStoreError(ValueError):
    """Malformed reference, corrupt record, or conflicting durable write."""


_KINDS = frozenset({"bundle", "context", "request", "enrichment", "result", "audit"})
_REFERENCE = re.compile(r"(bundle|context|request|enrichment|result|audit):([0-9a-f]{64})\Z")
_EXECUTION = re.compile(r"(?:local-[A-Za-z0-9_-]{1,80}|arn:aws:states:[A-Za-z0-9:._/-]{1,240})\Z")
_ERROR_CODE = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")
_MAX_RECORD_BYTES = 20 * 1024 * 1024


def validate_execution_id(value: object) -> str:
    if type(value) is not str or not _EXECUTION.fullmatch(value):
        raise StageStoreError("Invalid execution identifier.")
    return value


def validate_error_code(value: object) -> str:
    if type(value) is not str or not _ERROR_CODE.fullmatch(value):
        raise StageStoreError("Invalid error code.")
    return value


def _canonical(value: object) -> bytes:
    invalid_encoding = False

    try:
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        invalid_encoding = True

    if invalid_encoding:
        raise StageStoreError("Invalid record encoding.")

    return encoded


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise StageStoreError("Duplicate stored JSON key.")
        result[key] = value
    return result


def _check_ancestry(path: Path) -> None:
    for part in (path, *path.parents):
        inspection_failed = False

        try:
            redirected = part.is_symlink() or (hasattr(part, "is_junction") and part.is_junction())
        except OSError:
            inspection_failed = True

        if inspection_failed:
            raise StageStoreError("Cannot inspect storage path.")

        if redirected:
            raise StageStoreError("Redirected storage path is forbidden.")


def _private_dir(path: Path) -> None:
    _check_ancestry(path)

    creation_failed = False

    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError:
        creation_failed = True

    if creation_failed:
        raise StageStoreError("Cannot create private storage directory.")

    _check_ancestry(path)

    if not path.is_dir():
        raise StageStoreError("Invalid storage directory.")


def _atomic_create_once(destination: Path, content: bytes) -> None:
    """Write complete bytes before publishing with a no-overwrite hardlink."""
    if len(content) > _MAX_RECORD_BYTES:
        raise StageStoreError("Stage record exceeds byte limit.")

    _private_dir(destination.parent)

    creation_failed = False

    try:
        fd, temporary = tempfile.mkstemp(prefix=".kuma-stage-", dir=destination.parent)
    except OSError:
        creation_failed = True

    if creation_failed:
        raise StageStoreError("Cannot create temporary stage record.")

    write_failed = False
    publish_failed = False
    existing_destination = False
    cleanup_failed = False

    try:
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
        except OSError:
            write_failed = True

        if not write_failed:
            try:
                os.link(temporary, destination)
            except FileExistsError:
                existing_destination = True
            except OSError:
                publish_failed = True
    finally:
        try:
            Path(temporary).unlink(missing_ok=True)
        except OSError:
            cleanup_failed = True

    if write_failed:
        if cleanup_failed:
            raise StageStoreError("Cannot write temporary stage record; temporary cleanup failed.")
        raise StageStoreError("Cannot write temporary stage record.")

    if publish_failed:
        if cleanup_failed:
            raise StageStoreError(
                "Cannot publish stage record atomically; temporary cleanup failed."
            )
        raise StageStoreError("Cannot publish stage record atomically.")

    if existing_destination:
        read_failure_message = None

        try:
            existing_content = _read_bytes(destination)
        except StageStoreError as exc:
            read_failure_message = str(exc)

        if read_failure_message is not None:
            if cleanup_failed:
                if read_failure_message == "Cannot read stage record.":
                    raise StageStoreError("Cannot read stage record; temporary cleanup failed.")
                raise StageStoreError(
                    "Cannot verify existing stage record; temporary cleanup failed."
                )
            raise StageStoreError(read_failure_message)

        if existing_content != content:
            if cleanup_failed:
                raise StageStoreError(
                    "Conflicting existing stage record; temporary cleanup failed."
                )
            raise StageStoreError("Conflicting existing stage record.")

    if cleanup_failed:
        raise StageStoreError("Temporary cleanup failed; verify publication state.")


def _read_bytes(path: Path) -> bytes:
    _check_ancestry(path)
    if not path.is_file():
        raise StageStoreError("Missing stage record.")
    read_failed = False

    try:
        with path.open("rb") as stream:
            content = stream.read(_MAX_RECORD_BYTES + 1)
    except OSError:
        read_failed = True

    if read_failed:
        raise StageStoreError("Cannot read stage record.")

    if len(content) > _MAX_RECORD_BYTES:
        raise StageStoreError("Stage record exceeds byte limit.")
    return content


class LocalStageStore:
    """Stage artifacts are private filesystem records, never ASL state payloads."""

    def __init__(self, *, root: Path, evidence_root: Path) -> None:
        if not root.is_absolute() or not evidence_root.is_absolute():
            raise StageStoreError("Storage roots must be absolute.")
        _check_ancestry(evidence_root)

        if not evidence_root.is_dir():
            raise StageStoreError("Evidence root missing.")

        _check_ancestry(root)

        root_resolution_failed = False

        try:
            planned_root = root.resolve(strict=False)
            approved_evidence = evidence_root.resolve(strict=True)
        except (OSError, ValueError, RuntimeError):
            root_resolution_failed = True

        if root_resolution_failed:
            raise StageStoreError("Cannot resolve storage roots.")

        if planned_root.is_relative_to(approved_evidence) or approved_evidence.is_relative_to(
            planned_root
        ):
            raise StageStoreError("Storage roots must not overlap.")

        _private_dir(root)
        final_resolution_failed = False
        try:
            resolved_root = root.resolve(strict=True)
        except (OSError, ValueError, RuntimeError):
            final_resolution_failed = True
        if final_resolution_failed:
            raise StageStoreError("Cannot resolve storage roots.")
        self.root = resolved_root
        self.evidence_root = approved_evidence

    def check_bundle_path(self, path: Path) -> Path:
        """Validate that a pre-registered path stays inside the evidence root."""
        if not path.is_absolute():
            raise StageStoreError("Bundle path must be absolute.")
        _check_ancestry(path)
        invalid_path = False

        try:
            resolved = path.resolve(strict=True)
            resolved.relative_to(self.evidence_root)
        except (OSError, ValueError):
            invalid_path = True

        if invalid_path:
            raise StageStoreError("Bundle outside approved evidence root.")

        if not resolved.is_dir():
            raise StageStoreError("Bundle directory missing.")
        return resolved

    def put(self, kind: str, data: dict[str, Any], *, execution_id: str) -> str:
        if kind not in _KINDS or type(data) is not dict:
            raise StageStoreError("Invalid stage record kind or data.")
        execution_id = validate_execution_id(execution_id)
        document = {"kind": kind, "execution_id": execution_id, "data": data}
        payload = _canonical(document)
        digest = hashlib.sha256(payload).hexdigest()
        _atomic_create_once(self.root / kind / f"{digest}.json", payload)
        return f"{kind}:{digest}"

    def get(self, reference: object, *, kind: str, execution_id: str) -> dict[str, Any]:
        execution_id = validate_execution_id(execution_id)
        if type(reference) is not str:
            raise StageStoreError("Invalid stage reference.")
        match = _REFERENCE.fullmatch(reference)
        if match is None or match.group(1) != kind:
            raise StageStoreError("Invalid stage reference.")
        digest = match.group(2)
        raw = _read_bytes(self.root / kind / f"{digest}.json")
        if hashlib.sha256(raw).hexdigest() != digest:
            raise StageStoreError("Stage content digest mismatch.")
        invalid_json = False

        try:
            document = json.loads(raw, object_pairs_hook=_no_duplicate_keys)
        except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError):
            invalid_json = True

        if invalid_json:
            raise StageStoreError("Invalid stored stage JSON.")
        if (
            type(document) is not dict
            or set(document) != {"kind", "execution_id", "data"}
            or document["kind"] != kind
            or document["execution_id"] != execution_id
            or type(document["data"]) is not dict
        ):
            raise StageStoreError("Stage record ownership or schema mismatch.")
        return document["data"]

    def commit_result(
        self, *, execution_id: str, result_ref: str, artifact_id: str, extraction_run_id: str
    ) -> None:
        """Exactly one result reference can be committed per execution id."""
        execution_id = validate_execution_id(execution_id)
        result = self.get(result_ref, kind="result", execution_id=execution_id)
        if (
            result.get("artifact_id") != artifact_id
            or result.get("extraction_run_id") != extraction_run_id
        ):
            raise StageStoreError("Commit identity differs from stored result.")
        index_name = hashlib.sha256(execution_id.encode("utf-8")).hexdigest()
        payload = _canonical(
            {
                "execution_id": execution_id,
                "result_ref": result_ref,
                "artifact_id": artifact_id,
                "extraction_run_id": extraction_run_id,
            }
        )
        _atomic_create_once(self.root / "commits" / f"{index_name}.json", payload)
