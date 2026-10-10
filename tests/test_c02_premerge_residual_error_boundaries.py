"""Residual exception disclosure regression tests for C02.

Synthetic inputs only. No network or AWS.
"""

import json
import traceback
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

import pytest

from kuma_secure_knowledge_pipeline.contracts import (
    EvidenceReference,
    ExtractionProvenance,
    ExtractionResult,
    SourceArtifact,
)
from kuma_secure_knowledge_pipeline.evidence import write_extraction_evidence
from kuma_secure_knowledge_pipeline.orchestration import (
    AnalysisInputIntegrityError,
    _read_extracted_text_bounded,
    _read_json_text_bounded,
    load_analysis_input,
)
from kuma_secure_knowledge_pipeline.provenance import (
    validate_extraction_provenance,
)
from kuma_secure_knowledge_pipeline.stepfunctions_store import (
    LocalStageStore,
    StageStoreError,
    _atomic_create_once,
    _check_ancestry,
    _private_dir,
    _read_bytes,
)

PATH_CANARY = "KUMA_SYNTHETIC_PRIVATE_PATH_038"
INVALID_TIMESTAMP = "2099-99-99T99:99:99Z"


def _assert_sanitized(error: BaseException, marker: str) -> None:
    assert error.__cause__ is None
    assert error.__context__ is None
    assert marker not in str(error)
    assert marker not in "".join(traceback.format_exception(error))


def _provenance(timestamp: str) -> ExtractionProvenance:
    return ExtractionProvenance(
        run_id="run-residual-038",
        provider="amazon-textract",
        operation="DetectDocumentText",
        region="us-east-1",
        started_at_utc=timestamp,
    )


def test_missing_evidence_path_does_not_leak_via_exception(
    tmp_path: Path,
) -> None:
    path = tmp_path / PATH_CANARY / "raw-response.json"

    assert not path.exists()

    with pytest.raises(AnalysisInputIntegrityError) as caught:
        _read_json_text_bounded(path)

    _assert_sanitized(caught.value, PATH_CANARY)


def test_invalid_provenance_timestamp_does_not_chain_value() -> None:
    with pytest.raises(ValueError) as caught:
        validate_extraction_provenance(_provenance(INVALID_TIMESTAMP))

    _assert_sanitized(caught.value, INVALID_TIMESTAMP)


def test_orchestration_provenance_does_not_chain_timestamp(
    tmp_path: Path,
) -> None:
    artifact = SourceArtifact(
        artifact_id="art-residual-038",
        filename="synthetic.png",
        media_type="image/png",
        sha256="a" * 64,
    )

    valid = _provenance("2026-10-10T12:00:00Z")

    result = ExtractionResult(
        artifact_id=artifact.artifact_id,
        provider=valid.provider,
        operation=valid.operation,
        text="SYNTHETIC INCIDENT",
        average_confidence=95.0,
        evidence_refs=(
            EvidenceReference(
                artifact_id=artifact.artifact_id,
                block_id="line-001",
                page=1,
                confidence=95.0,
            ),
        ),
    )

    raw_response = {
        "Blocks": [
            {
                "BlockType": "LINE",
                "Id": "line-001",
                "Page": 1,
                "Confidence": 95.0,
                "Text": result.text,
            }
        ]
    }

    bundle = write_extraction_evidence(
        output_root=tmp_path,
        artifact=artifact,
        raw_response=raw_response,
        result=result,
        provenance=valid,
    )

    manifest_path = bundle / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["run"]["started_at_utc"] = INVALID_TIMESTAMP

    manifest_path.write_text(
        json.dumps(manifest),
        encoding="utf-8",
    )

    with pytest.raises(AnalysisInputIntegrityError) as caught:
        load_analysis_input(bundle)

    _assert_sanitized(caught.value, INVALID_TIMESTAMP)


def test_missing_extracted_text_path_does_not_leak(
    tmp_path: Path,
) -> None:
    path = tmp_path / PATH_CANARY / "extracted.txt"
    assert not path.exists()

    with pytest.raises(AnalysisInputIntegrityError) as caught:
        _read_extracted_text_bounded(path)

    _assert_sanitized(caught.value, PATH_CANARY)


def test_c02_final_055_missing_bundle_path_does_not_chain(
    tmp_path: Path,
) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    store = LocalStageStore(
        root=tmp_path / "private-store",
        evidence_root=evidence,
    )
    missing = evidence / PATH_CANARY / "missing-bundle"

    with pytest.raises(StageStoreError) as caught:
        store.check_bundle_path(missing)

    _assert_sanitized(caught.value, PATH_CANARY)


def test_c02_final_055_read_failure_does_not_chain(
    tmp_path: Path,
) -> None:
    record = tmp_path / (PATH_CANARY + ".json")
    record.write_bytes(b'{"synthetic":true}')

    synthetic_error = PermissionError(
        13,
        "Synthetic access denied",
        str(record),
    )

    with (
        patch.object(Path, "open", side_effect=synthetic_error),
        pytest.raises(StageStoreError) as caught,
    ):
        _read_bytes(record)

    _assert_sanitized(caught.value, PATH_CANARY)


@pytest.mark.parametrize("root_nested", [True, False])
def test_c02_final_055_rejects_overlapping_storage_roots(
    tmp_path: Path,
    root_nested: bool,
) -> None:
    if root_nested:
        evidence = tmp_path / "evidence"
        evidence.mkdir()
        root = evidence / "private-store"
    else:
        root = tmp_path / "parent-store"
        evidence = root / "evidence"
        evidence.mkdir(parents=True)

    with pytest.raises(StageStoreError, match="overlap"):
        LocalStageStore(root=root, evidence_root=evidence)

    if root_nested:
        assert not root.exists()


def test_c02_final_056_ancestry_io_failure_is_sanitized(
    tmp_path: Path,
) -> None:
    path = tmp_path / PATH_CANARY / "evidence"

    synthetic_error = PermissionError(13, "Synthetic ancestry failure", str(path))

    with (
        patch.object(Path, "is_symlink", side_effect=synthetic_error),
        pytest.raises(StageStoreError) as caught,
    ):
        _check_ancestry(path)

    _assert_sanitized(caught.value, PATH_CANARY)


def test_c02_final_056_atomic_publish_failure_is_sanitized(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "private" / "bundle" / "record.json"

    synthetic_error = PermissionError(
        13,
        "Synthetic publication failure",
        str(tmp_path / PATH_CANARY / "publication"),
    )

    with (
        patch("os.link", side_effect=synthetic_error),
        pytest.raises(StageStoreError) as caught,
    ):
        _atomic_create_once(destination, b'{"synthetic":true}')

    _assert_sanitized(caught.value, PATH_CANARY)
    assert not destination.exists()
    assert not list(destination.parent.glob(".kuma-stage-*"))


def test_c02_final_056_private_dir_failure_is_sanitized(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "private"

    synthetic_error = PermissionError(
        13,
        "Synthetic directory creation failure",
        str(tmp_path / PATH_CANARY / "directory"),
    )

    with (
        patch.object(Path, "mkdir", side_effect=synthetic_error),
        pytest.raises(StageStoreError) as caught,
    ):
        _private_dir(directory)

    _assert_sanitized(caught.value, PATH_CANARY)


def test_c02_final_057_mkstemp_failure_is_sanitized(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "case-mkstemp" / "result.json"
    error = PermissionError(
        13,
        "Synthetic temporary file creation failure",
        str(tmp_path / PATH_CANARY / "mkstemp"),
    )

    with (
        patch("tempfile.mkstemp", side_effect=error),
        pytest.raises(StageStoreError) as caught,
    ):
        _atomic_create_once(destination, b"{}")

    _assert_sanitized(caught.value, PATH_CANARY)
    assert not destination.exists()
    assert not list(destination.parent.glob(".kuma-stage-*"))


def test_c02_final_057_fsync_failure_is_sanitized(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "case-fsync" / "result.json"
    error = PermissionError(
        13,
        "Synthetic filesystem synchronization failure",
        str(tmp_path / PATH_CANARY / "fsync"),
    )

    with (
        patch("os.fsync", side_effect=error),
        pytest.raises(StageStoreError) as caught,
    ):
        _atomic_create_once(destination, b"{}")

    _assert_sanitized(caught.value, PATH_CANARY)
    assert not destination.exists()
    assert not list(destination.parent.glob(".kuma-stage-*"))


def test_c02_final_057_cleanup_failure_preserves_published_record(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "case-cleanup" / "result.json"
    payload = b'{"synthetic":true}'

    error = PermissionError(
        13,
        "Synthetic temporary cleanup failure",
        str(tmp_path / PATH_CANARY / "unlink"),
    )

    with (
        patch.object(Path, "unlink", side_effect=error),
        pytest.raises(StageStoreError) as caught,
    ):
        _atomic_create_once(destination, payload)

    _assert_sanitized(caught.value, PATH_CANARY)

    # Publication precedes the simulated cleanup failure.
    assert destination.read_bytes() == payload

    leftovers = list(destination.parent.glob(".kuma-stage-*"))
    assert len(leftovers) == 1

    # Retry with the original filesystem operations must be idempotent.
    _atomic_create_once(destination, payload)
    assert destination.read_bytes() == payload

    # Remove only the synthetic orphan created by this fixture.
    for temporary in leftovers:
        temporary.unlink()


@pytest.mark.parametrize(
    ("failure_stage", "expected_message"),
    [
        ("write", "Cannot write temporary stage record; temporary cleanup failed."),
        ("publish", "Cannot publish stage record atomically; temporary cleanup failed."),
        ("conflict", "Conflicting existing stage record; temporary cleanup failed."),
    ],
)
def test_c02_final_058_primary_failure_survives_cleanup_failure(
    tmp_path: Path,
    failure_stage: str,
    expected_message: str,
) -> None:
    destination = tmp_path / failure_stage / "record.json"
    destination.parent.mkdir(parents=True)

    original_content = b'{"existing":true}'
    new_content = b'{"new":true}'

    if failure_stage == "conflict":
        destination.write_bytes(original_content)

    original_unlink = Path.unlink

    def fail_temporary_cleanup(
        path: Path,
        *args: object,
        **kwargs: object,
    ) -> None:
        if path.name.startswith(".kuma-stage-"):
            raise PermissionError(
                13,
                "Synthetic cleanup failure",
                str(tmp_path / PATH_CANARY / "cleanup"),
            )
        original_unlink(path, *args, **kwargs)

    synthetic_error = PermissionError(
        13,
        "Synthetic primary operation failure",
        str(tmp_path / PATH_CANARY / failure_stage),
    )

    try:
        with ExitStack() as mocks, pytest.raises(StageStoreError) as caught:
            mocks.enter_context(patch.object(Path, "unlink", fail_temporary_cleanup))

            if failure_stage == "write":
                mocks.enter_context(patch("os.fsync", side_effect=synthetic_error))
            elif failure_stage == "publish":
                mocks.enter_context(patch("os.link", side_effect=synthetic_error))

            _atomic_create_once(destination, new_content)

        _assert_sanitized(caught.value, PATH_CANARY)
        assert str(caught.value) == expected_message

        if failure_stage == "conflict":
            assert destination.read_bytes() == original_content
        else:
            assert not destination.exists()

        assert len(list(destination.parent.glob(".kuma-stage-*"))) == 1
    finally:
        for temporary in destination.parent.glob(".kuma-stage-*"):
            original_unlink(temporary, missing_ok=True)


@pytest.mark.parametrize("cleanup_failure", [False, True])
def test_c02_final_059_read_failure_reports_cleanup_state(
    tmp_path: Path,
    cleanup_failure: bool,
) -> None:
    destination = tmp_path / "read-cleanup" / "record.json"
    destination.parent.mkdir(parents=True)

    original_content = b'{"original":true}'
    destination.write_bytes(original_content)

    original_open = Path.open
    original_unlink = Path.unlink

    def fail_existing_read(
        path: Path,
        *args: object,
        **kwargs: object,
    ):
        mode = args[0] if args else kwargs.get("mode", "r")

        if path == destination and mode == "rb":
            raise PermissionError(
                13,
                "Synthetic read failure",
                str(tmp_path / PATH_CANARY / "read"),
            )

        return original_open(path, *args, **kwargs)

    def fail_temporary_cleanup(
        path: Path,
        *args: object,
        **kwargs: object,
    ) -> None:
        if path.name.startswith(".kuma-stage-"):
            raise PermissionError(
                13,
                "Synthetic cleanup failure",
                str(tmp_path / PATH_CANARY / "cleanup"),
            )

        original_unlink(path, *args, **kwargs)

    expected_message = (
        "Cannot read stage record; temporary cleanup failed."
        if cleanup_failure
        else "Cannot read stage record."
    )

    try:
        with ExitStack() as mocks:
            mocks.enter_context(patch.object(Path, "open", fail_existing_read))

            if cleanup_failure:
                mocks.enter_context(
                    patch.object(
                        Path,
                        "unlink",
                        fail_temporary_cleanup,
                    )
                )

            with pytest.raises(StageStoreError) as caught:
                _atomic_create_once(destination, b'{"new":true}')

        _assert_sanitized(caught.value, PATH_CANARY)

        assert str(caught.value) == expected_message
        assert destination.read_bytes() == original_content

        leftovers = list(destination.parent.glob(".kuma-stage-*"))

        assert len(leftovers) == int(cleanup_failure)
    finally:
        for temporary in destination.parent.glob(".kuma-stage-*"):
            original_unlink(temporary, missing_ok=True)


def test_c02_final_061_other_read_error_with_failed_cleanup(tmp_path: Path) -> None:
    destination = tmp_path / "061-read" / "record.json"
    destination.parent.mkdir(parents=True)
    original_payload = b'{"existing":true}'
    destination.write_bytes(original_payload)
    original_unlink = Path.unlink

    def cleanup_denied(path: Path, *args: object, **kwargs: object) -> None:
        if path.name.startswith(".kuma-stage-"):
            raise PermissionError(
                13, "Synthetic cleanup denied", str(tmp_path / PATH_CANARY / "cleanup")
            )
        original_unlink(path, *args, **kwargs)

    try:
        with (
            patch.object(Path, "unlink", cleanup_denied),
            patch(
                "kuma_secure_knowledge_pipeline.stepfunctions_store._read_bytes",
                side_effect=StageStoreError("Stage record exceeds byte limit."),
            ),
            pytest.raises(StageStoreError) as caught,
        ):
            _atomic_create_once(destination, b'{"new":true}')

        _assert_sanitized(caught.value, PATH_CANARY)
        assert str(caught.value) == (
            "Cannot verify existing stage record; temporary cleanup failed."
        )
        assert destination.read_bytes() == original_payload
        assert len(list(destination.parent.glob(".kuma-stage-*"))) == 1
    finally:
        for temporary in destination.parent.glob(".kuma-stage-*"):
            original_unlink(temporary, missing_ok=True)


def test_c02_final_061_final_root_resolution_is_sanitized(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    root = tmp_path / "private-store"
    original_resolve = Path.resolve

    def deny_final_resolution(path: Path, *args: object, **kwargs: object) -> Path:
        strict = kwargs.get("strict", args[0] if args else False)
        if path == root and strict is True:
            raise PermissionError(
                13, "Synthetic final resolution denied", str(tmp_path / PATH_CANARY / "root")
            )
        return original_resolve(path, *args, **kwargs)

    with (
        patch.object(Path, "resolve", deny_final_resolution),
        pytest.raises(StageStoreError) as caught,
    ):
        LocalStageStore(root=root, evidence_root=evidence)

    _assert_sanitized(caught.value, PATH_CANARY)
    assert str(caught.value) == "Cannot resolve storage roots."
    assert evidence.is_dir()
