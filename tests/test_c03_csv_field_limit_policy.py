"""RED contract: the CSV parser requires a canonical runtime field limit."""

import subprocess
import sys

import pytest

_CANONICAL_CSV_FIELD_LIMIT = 131072

# The global csv.field_size_limit setting is mutated only in child processes.
# This prevents interference with other tests or threads in the pytest process.
_ISOLATED_PROBE = r"""
import csv
import sys
from pathlib import Path

from kuma_secure_knowledge_pipeline.artifacts import build_source_artifact
from kuma_secure_knowledge_pipeline.knowledge_contracts import SourceLocator
from kuma_secure_knowledge_pipeline.knowledge_csv import (
    CsvEvidenceResolutionError,
    resolve_csv_record,
)
from kuma_secure_knowledge_pipeline.knowledge_evidence import (
    load_verified_source_snapshot,
)

csv.field_size_limit(int(sys.argv[2]))
path = Path(sys.argv[1])
artifact = build_source_artifact(path)
locator = SourceLocator(
    artifact_id=artifact.artifact_id,
    source_sha256=artifact.sha256,
    kind="csv_row",
    record_index=1,
    record_id="DOC-0001",
)
snapshot = load_verified_source_snapshot(
    source_path=path,
    artifact=artifact,
    locator=locator,
)

try:
    record = resolve_csv_record(snapshot)
except CsvEvidenceResolutionError as error:
    message = str(error)
    if message == "CSV field size limit is not configured as required.":
        print("POLICY_REJECTED")
    elif message == "Malformed CSV structure.":
        print("PARSER_REJECTED")
    else:
        print("OTHER_DOMAIN_REJECTION")
else:
    if record.fields == (
        ("record_id", "DOC-0001"),
        ("description", "A" * 64),
    ):
        print("ACCEPTED")
    else:
        print("INCORRECT_RESULT")
"""


def _isolated_result(tmp_path, limit: int) -> str:
    path = tmp_path / "csv-field-limit.csv"
    path.write_bytes(b"record_id,description\nDOC-0001," + b"A" * 64 + b"\n")

    result = subprocess.run(
        [sys.executable, "-B", "-c", _ISOLATED_PROBE, str(path), str(limit)],
        capture_output=True,
        text=True,
        check=False,
        timeout=20,
    )
    assert result.returncode == 0, "Isolated runtime CSV probe did not complete."
    return result.stdout.strip()


def test_canonical_field_limit_accepts_valid_snapshot(tmp_path):
    assert _isolated_result(tmp_path, _CANONICAL_CSV_FIELD_LIMIT) == "ACCEPTED"


@pytest.mark.parametrize(
    "limit",
    [
        pytest.param(32, id="too-small"),
        pytest.param(262144, id="too-large"),
    ],
)
def test_noncanonical_field_limit_fails_closed(tmp_path, limit):
    assert _isolated_result(tmp_path, limit) == "POLICY_REJECTED"
