"""Adversarial semantic CSV parsing and structural integrity tests."""

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


def _snapshot(
    tmp_path,
    content,
    *,
    record_id="DOC-0001",
):
    path = tmp_path / "evidence.csv"
    path.write_bytes(content)

    artifact = build_source_artifact(path)

    locator = SourceLocator(
        artifact_id=artifact.artifact_id,
        source_sha256=artifact.sha256,
        kind="csv_row",
        record_index=1,
        record_id=record_id,
    )

    return load_verified_source_snapshot(
        source_path=path,
        artifact=artifact,
        locator=locator,
    )


def test_preserves_quoted_delimiter(tmp_path):
    snapshot = _snapshot(
        tmp_path,
        b'record_id,description\nDOC-0001,"suporte, rede"\n',
    )

    result = resolve_csv_record(snapshot)

    assert result.fields[1] == ("description", "suporte, rede")


def test_preserves_multiline_quoted_value(tmp_path):
    snapshot = _snapshot(
        tmp_path,
        b'record_id,description\nDOC-0001,"linha 1\nlinha 2"\n',
    )

    result = resolve_csv_record(snapshot)

    assert result.fields[1] == (
        "description",
        "linha 1\nlinha 2",
    )


def test_preserves_correctly_escaped_quotes(tmp_path):
    snapshot = _snapshot(
        tmp_path,
        b'record_id,description\nDOC-0001,"texto ""legitimo"""\n',
    )

    result = resolve_csv_record(snapshot)

    assert result.fields[1] == (
        "description",
        'texto "legitimo"',
    )


def test_rejects_malformed_later_record(tmp_path):
    snapshot = _snapshot(
        tmp_path,
        b"record_id,amount\nDOC-0001,100\nDOC-0002\n",
    )

    with pytest.raises(CsvEvidenceResolutionError):
        resolve_csv_record(snapshot)


def test_rejects_duplicate_identifier_after_target(tmp_path):
    snapshot = _snapshot(
        tmp_path,
        b"record_id,amount\nDOC-0001,100\nDOC-0001,900\n",
    )

    with pytest.raises(CsvEvidenceResolutionError):
        resolve_csv_record(snapshot)


def test_record_identifier_remains_case_sensitive(tmp_path):
    snapshot = _snapshot(
        tmp_path,
        b"record_id,amount\nDOC-0001,100\n",
        record_id="doc-0001",
    )

    with pytest.raises(CsvEvidenceResolutionError):
        resolve_csv_record(snapshot)


def test_preserves_formula_like_text_without_evaluation(tmp_path):
    snapshot = _snapshot(
        tmp_path,
        b"record_id,formula\nDOC-0001,=1+2\n",
    )

    result = resolve_csv_record(snapshot)

    assert result.fields[1] == ("formula", "=1+2")


def test_supports_explicit_identifier_column_and_pipe(tmp_path):
    snapshot = _snapshot(
        tmp_path,
        b"protocolo|valor\nPR-1|1.234,56\n",
        record_id="PR-1",
    )

    result = resolve_csv_record(
        snapshot,
        id_column="protocolo",
        delimiter="|",
    )

    assert result.fields == (
        ("protocolo", "PR-1"),
        ("valor", "1.234,56"),
    )


def test_rejects_unescaped_quote_in_unquoted_field(tmp_path):
    snapshot = _snapshot(
        tmp_path,
        b'record_id,description\nDOC-0001,valor"alterado\n',
    )

    with pytest.raises(CsvEvidenceResolutionError):
        resolve_csv_record(snapshot)
