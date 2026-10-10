"""Permanent RED regressions for C02 pre-merge failure boundaries.

Synthetic canaries only. No cloud, network, or production evidence.
"""

import traceback
from pathlib import Path

import pytest

from kuma_secure_knowledge_pipeline.orchestration import (
    AnalysisInputIntegrityError,
    _json_object,
    _validate_raw_lineage,
)
from kuma_secure_knowledge_pipeline.stepfunctions_store import (
    LocalStageStore,
    StageStoreError,
)

CANARY = "KUMA_SYNTHETIC_C02_PREMERGE_CANARY"
CANARY_BYTES = CANARY.encode("ascii")


def _assert_sanitized(error: BaseException) -> None:
    assert error.__cause__ is None
    assert error.__context__ is None
    assert CANARY not in str(error)
    assert CANARY not in "".join(traceback.format_exception(error))


def test_malformed_evidence_json_does_not_retain_original_payload(
    tmp_path: Path,
) -> None:
    path = tmp_path / "raw-response.json"
    path.write_bytes(b'{"note":"' + CANARY_BYTES + b'",')

    with pytest.raises(AnalysisInputIntegrityError) as caught:
        _json_object(path)

    _assert_sanitized(caught.value)


def test_invalid_evidence_utf8_does_not_retain_original_bytes(
    tmp_path: Path,
) -> None:
    path = tmp_path / "raw-response.json"
    path.write_bytes(b'{"note":"' + CANARY_BYTES + b'\xff"}')

    with pytest.raises(AnalysisInputIntegrityError) as caught:
        _json_object(path)

    _assert_sanitized(caught.value)


def test_duplicate_json_key_is_not_echoed_in_diagnostics(
    tmp_path: Path,
) -> None:
    path = tmp_path / "raw-response.json"
    path.write_bytes(b'{"' + CANARY_BYTES + b'":1,"' + CANARY_BYTES + b'":2}')

    with pytest.raises(AnalysisInputIntegrityError) as caught:
        _json_object(path)

    _assert_sanitized(caught.value)


def test_invalid_tesseract_unicode_is_rejected_without_retention() -> None:
    with pytest.raises(AnalysisInputIntegrityError) as caught:
        _validate_raw_lineage(
            artifact_id="sha256-" + "a" * 64,
            provider="tesseract",
            operation="TesseractTSV",
            raw_response={
                "tsv_text": CANARY + "\ud800",
                "tsv_sha256": "0" * 64,
            },
            normalized={},
        )

    _assert_sanitized(caught.value)


def test_invalid_stage_store_unicode_does_not_retain_payload(
    tmp_path: Path,
) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()

    store = LocalStageStore(
        root=tmp_path / "private-store",
        evidence_root=evidence_root,
    )

    with pytest.raises(StageStoreError) as caught:
        store.put(
            "enrichment",
            {"model_text": CANARY + "\ud800"},
            execution_id="local-premerge-001",
        )

    _assert_sanitized(caught.value)
