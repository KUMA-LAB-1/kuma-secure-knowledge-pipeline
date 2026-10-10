"""Secondary C02 pre-merge exception-chain regression tests.

Synthetic inputs only. No network, AWS, or production evidence.
"""

import hashlib
import traceback
from pathlib import Path

import pytest

from kuma_secure_knowledge_pipeline.orchestration import (
    AnalysisInputIntegrityError,
    _read_extracted_text_bounded,
)
from kuma_secure_knowledge_pipeline.stepfunctions_store import (
    LocalStageStore,
    StageStoreError,
)

CANARY = "KUMA_SYNTHETIC_SECONDARY_BOUNDARY"
TOKEN = CANARY.encode("ascii")


def _assert_safe_exception_boundary(error: BaseException) -> None:
    """Verify sanitized messages and absence of chained exceptions."""
    assert error.__cause__ is None
    assert error.__context__ is None
    assert CANARY not in str(error)
    assert CANARY not in "".join(traceback.format_exception(error))


def test_invalid_extracted_utf8_does_not_chain_source_bytes(
    tmp_path: Path,
) -> None:
    extracted = tmp_path / "extracted.txt"
    extracted.write_bytes(TOKEN + b"\xff")

    with pytest.raises(AnalysisInputIntegrityError) as caught:
        _read_extracted_text_bounded(extracted)

    _assert_safe_exception_boundary(caught.value)


def test_invalid_stored_json_does_not_chain_original_document(
    tmp_path: Path,
) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()

    store = LocalStageStore(
        root=tmp_path / "private-store",
        evidence_root=evidence_root,
    )

    malformed = (
        b'{"kind":"bundle","execution_id":"local-review-029","data":{"note":"' + TOKEN + b'"},'
    )

    digest = hashlib.sha256(malformed).hexdigest()

    record = store.root / "bundle" / f"{digest}.json"
    record.parent.mkdir(parents=True, exist_ok=True)
    record.write_bytes(malformed)

    with pytest.raises(StageStoreError) as caught:
        store.get(
            f"bundle:{digest}",
            kind="bundle",
            execution_id="local-review-029",
        )

    _assert_safe_exception_boundary(caught.value)
