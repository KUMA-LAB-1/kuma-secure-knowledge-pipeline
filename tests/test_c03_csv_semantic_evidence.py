"""Semantic CSV evidence: resolve actual records from verified bytes."""

from dataclasses import FrozenInstanceError, replace

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

ROWS = b"record_id,amount,supplier\nDOC-0001,100,Alpha\nDOC-0002,200,Beta\n"


def _snapshot(
    tmp_path,
    content=ROWS,
    *,
    record_index=1,
    record_id="DOC-0001",
    kind="csv_row",
    media_type=None,
):
    path = tmp_path / "casos.csv"
    path.write_bytes(content)

    artifact = build_source_artifact(path)

    if media_type is not None:
        artifact = replace(artifact, media_type=media_type)

    if kind == "csv_row":
        locator = SourceLocator(
            artifact_id=artifact.artifact_id,
            source_sha256=artifact.sha256,
            kind=kind,
            record_index=record_index,
            record_id=record_id,
        )
    else:
        locator = SourceLocator(
            artifact_id=artifact.artifact_id,
            source_sha256=artifact.sha256,
            kind="pdf_page",
            page=1,
        )

    snapshot = load_verified_source_snapshot(
        source_path=path,
        artifact=artifact,
        locator=locator,
    )

    return path, snapshot


def test_resolves_actual_csv_record(tmp_path):
    _, snapshot = _snapshot(
        tmp_path,
        record_index=2,
        record_id="DOC-0002",
    )

    result = resolve_csv_record(snapshot)

    assert result.artifact_id == snapshot.artifact.artifact_id
    assert result.source_sha256 == snapshot.artifact.sha256
    assert result.record_index == 2
    assert result.record_id == "DOC-0002"
    assert result.fields == (
        ("record_id", "DOC-0002"),
        ("amount", "200"),
        ("supplier", "Beta"),
    )


def test_uses_snapshot_not_original_file(tmp_path):
    path, snapshot = _snapshot(tmp_path)
    path.unlink()

    result = resolve_csv_record(snapshot)

    assert result.record_id == "DOC-0001"
    assert result.fields[1] == ("amount", "100")


def test_accepts_utf8_bom(tmp_path):
    content = b"\xef\xbb\xbf" + ROWS
    _, snapshot = _snapshot(tmp_path, content)

    result = resolve_csv_record(snapshot)

    assert result.record_id == "DOC-0001"
    assert result.fields[0] == ("record_id", "DOC-0001")


def test_accepts_semicolon_and_preserves_decimal_text(tmp_path):
    content = ("record_id;valor;municipio\r\nDOC-0001;1.234,56;São Pedro\r\n").encode()

    _, snapshot = _snapshot(tmp_path, content)

    result = resolve_csv_record(snapshot, delimiter=";")

    assert result.fields == (
        ("record_id", "DOC-0001"),
        ("valor", "1.234,56"),
        ("municipio", "São Pedro"),
    )


def test_counts_csv_records_not_physical_lines(tmp_path):
    content = (
        b"record_id,description,amount\r\n"
        b'DOC-0001,"item,\r\nmultiline",100\r\n'
        b"DOC-0002,normal,200\r\n"
    )

    _, snapshot = _snapshot(
        tmp_path,
        content,
        record_index=2,
        record_id="DOC-0002",
    )

    result = resolve_csv_record(snapshot)

    assert result.record_index == 2
    assert result.fields[1] == ("description", "normal")


def test_rejects_nonexistent_csv_record(tmp_path):
    _, snapshot = _snapshot(
        tmp_path,
        record_index=99,
        record_id="DOC-0099",
    )

    with pytest.raises(CsvEvidenceResolutionError):
        resolve_csv_record(snapshot)


def test_rejects_mismatched_record_identifier(tmp_path):
    _, snapshot = _snapshot(
        tmp_path,
        record_index=2,
        record_id="DOC-0001",
    )

    with pytest.raises(CsvEvidenceResolutionError):
        resolve_csv_record(snapshot)


@pytest.mark.parametrize(
    "content",
    [
        b"record_id,amount,amount\nDOC-0001,100,200\n",
        b"record_id,,amount\nDOC-0001,x,100\n",
        b"amount,supplier\n100,Alpha\n",
        b"",
    ],
)
def test_rejects_invalid_header_or_empty_csv(tmp_path, content):
    if not content:
        path = tmp_path / "casos.csv"
        path.write_bytes(content)
        with pytest.raises(ValueError):
            build_source_artifact(path)
        return

    _, snapshot = _snapshot(tmp_path, content)

    with pytest.raises(CsvEvidenceResolutionError):
        resolve_csv_record(snapshot)


@pytest.mark.parametrize(
    "content",
    [
        b"record_id,amount,supplier\nDOC-0001,100\n",
        b"record_id,amount\nDOC-0001,100,extra\n",
    ],
)
def test_rejects_ragged_csv_rows(tmp_path, content):
    _, snapshot = _snapshot(tmp_path, content)

    with pytest.raises(CsvEvidenceResolutionError):
        resolve_csv_record(snapshot)


def test_rejects_duplicate_record_identifiers(tmp_path):
    content = b"record_id,amount\nDOC-0001,100\nDOC-0001,200\n"

    _, snapshot = _snapshot(tmp_path, content)

    with pytest.raises(CsvEvidenceResolutionError):
        resolve_csv_record(snapshot)


def test_rejects_malformed_csv_quoting(tmp_path):
    content = b'record_id,description\nDOC-0001,"unterminated\n'

    _, snapshot = _snapshot(tmp_path, content)

    with pytest.raises(CsvEvidenceResolutionError):
        resolve_csv_record(snapshot)


def test_rejects_invalid_utf8(tmp_path):
    content = b"record_id,amount\nDOC-0001,\xff\n"
    _, snapshot = _snapshot(tmp_path, content)

    with pytest.raises(CsvEvidenceResolutionError):
        resolve_csv_record(snapshot)


def test_rejects_wrong_location_kind(tmp_path):
    _, snapshot = _snapshot(tmp_path, kind="pdf_page")

    with pytest.raises(CsvEvidenceResolutionError):
        resolve_csv_record(snapshot)


def test_rejects_incompatible_media_type(tmp_path):
    _, snapshot = _snapshot(
        tmp_path,
        media_type="application/pdf",
    )

    with pytest.raises(CsvEvidenceResolutionError):
        resolve_csv_record(snapshot)


@pytest.mark.parametrize("delimiter", ["", "||", "\n"])
def test_rejects_invalid_delimiter(tmp_path, delimiter):
    _, snapshot = _snapshot(tmp_path)

    with pytest.raises(CsvEvidenceResolutionError):
        resolve_csv_record(snapshot, delimiter=delimiter)


def test_result_is_immutable(tmp_path):
    _, snapshot = _snapshot(tmp_path)
    result = resolve_csv_record(snapshot)

    assert isinstance(result.fields, tuple)

    with pytest.raises(FrozenInstanceError):
        result.fields = ()
