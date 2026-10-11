"""Security regressions for CSV Unicode exception-chain retention."""

import traceback

import pytest

from kuma_secure_knowledge_pipeline.artifacts import build_source_artifact
from kuma_secure_knowledge_pipeline.knowledge_contracts import SourceLocator
from kuma_secure_knowledge_pipeline.knowledge_csv import (
    CsvEvidenceResolutionError,
    resolve_csv_record,
)
from kuma_secure_knowledge_pipeline.knowledge_evidence import (
    load_verified_source_snapshot,
)

CANARY = b"KUMA_SYNTHETIC_CSV_CHAIN_CANARY"


def _snapshot(tmp_path, invalid_fragment=b""):
    content = b"record_id,description\nDOC-0001," + CANARY + invalid_fragment + b"\n"

    path = tmp_path / "unicode-chain.csv"
    path.write_bytes(content)

    artifact = build_source_artifact(path)

    locator = SourceLocator(
        artifact_id=artifact.artifact_id,
        source_sha256=artifact.sha256,
        kind="csv_row",
        record_index=1,
        record_id="DOC-0001",
    )

    return load_verified_source_snapshot(
        source_path=path,
        artifact=artifact,
        locator=locator,
    )


def test_valid_utf8_control_resolves_without_error(tmp_path):
    snapshot = _snapshot(tmp_path)

    resolved = resolve_csv_record(snapshot)

    assert resolved.record_id == "DOC-0001"
    assert resolved.fields[1] == (
        "description",
        CANARY.decode("ascii"),
    )


@pytest.mark.parametrize(
    "invalid_fragment",
    [
        pytest.param(b"\xff", id="invalid-leading-byte"),
        pytest.param(b"\xc3", id="incomplete-multibyte"),
        pytest.param(b"\xed\xa0\x80", id="invalid-surrogate"),
    ],
)
def test_invalid_utf8_does_not_preserve_source_in_exception_chain(
    tmp_path,
    invalid_fragment,
):
    snapshot = _snapshot(tmp_path, invalid_fragment)

    with pytest.raises(CsvEvidenceResolutionError) as captured:
        resolve_csv_record(snapshot)

    error = captured.value

    assert str(error) == "CSV content is not valid UTF-8."

    formatted = "".join(traceback.format_exception(error))

    assert CANARY.decode("ascii") not in str(error)
    assert CANARY.decode("ascii") not in formatted

    # Compare booleans instead of exposing exception repr or raw bytes.
    # A failure must not print the sensitive-looking synthetic payload.
    chained_exception_present = error.__cause__ is not None or error.__context__ is not None

    if chained_exception_present:
        pytest.fail(
            "CSV exception chain retained original decode exception.",
            pytrace=False,
        )
