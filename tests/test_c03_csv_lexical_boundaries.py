"""Boundary cases for strict CSV evidence syntax."""

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


def _snapshot(tmp_path, content):
    path = tmp_path / "lexical.csv"
    path.write_bytes(content.encode())

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


VALID_CASES = [
    pytest.param(
        'record_id,description\nDOC-0001,"suporte, rede"\n',
        ",",
        "suporte, rede",
        id="quoted-delimiter",
    ),
    pytest.param(
        'record_id,description\nDOC-0001,"texto ""legitimo"""\n',
        ",",
        'texto "legitimo"',
        id="doubled-quote",
    ),
    pytest.param(
        'record_id,description\nDOC-0001,""\n',
        ",",
        "",
        id="empty-quoted-field",
    ),
    pytest.param(
        'record_id,description\r\nDOC-0001,"a\r\nb"\r\n',
        ",",
        "a\r\nb",
        id="quoted-crlf",
    ),
    pytest.param(
        'record_id,description\r\nDOC-0001,"a\nb"\r\n',
        ",",
        "a\nb",
        id="quoted-lf-inside-crlf",
    ),
    pytest.param(
        "record_id,description\nDOC-0001,ok",
        ",",
        "ok",
        id="no-final-newline",
    ),
    pytest.param(
        'record_id;description\nDOC-0001;"a;b"\n',
        ";",
        "a;b",
        id="semicolon-quoted",
    ),
    pytest.param(
        'record_id|description\nDOC-0001|"a ""b""|c"\n',
        "|",
        'a "b"|c',
        id="pipe-escaped-quotes",
    ),
    pytest.param(
        "record_id\tdescription\nDOC-0001\tok\n",
        "\t",
        "ok",
        id="tab-delimiter",
    ),
    pytest.param(
        'record_id,"description"\nDOC-0001,ok\n',
        ",",
        "ok",
        id="quoted-header",
    ),
    pytest.param(
        'record_id,description\n"DOC-0001",ok\n',
        ",",
        "ok",
        id="quoted-identifier",
    ),
    pytest.param(
        "record_id,description\nDOC-0001,\n",
        ",",
        "",
        id="empty-unquoted-field",
    ),
    pytest.param(
        "record_id,description\nDOC-0001,São Pedro\n",
        ",",
        "São Pedro",
        id="unicode-value",
    ),
]


@pytest.mark.parametrize(
    ("content", "delimiter", "expected_value"),
    VALID_CASES,
)
def test_legal_csv_boundary(
    tmp_path,
    content,
    delimiter,
    expected_value,
):
    snapshot = _snapshot(tmp_path, content)
    resolved = resolve_csv_record(
        snapshot,
        delimiter=delimiter,
    )

    assert resolved.record_index == 1
    assert resolved.record_id == "DOC-0001"
    assert resolved.fields[1] == (
        "description",
        expected_value,
    )


INVALID_CASES = [
    pytest.param(
        'record_id,descr"iption\nDOC-0001,ok\n',
        ",",
        id="unquoted-header-quote",
    ),
    pytest.param(
        'record_id,description\nDOC-0001,ok\nDOC-0002,bad"quote\n',
        ",",
        id="malformed-later-record",
    ),
    pytest.param(
        'record_id,description\nDOC-0001,"abc"x\n',
        ",",
        id="junk-after-closing-quote",
    ),
    pytest.param(
        'record_id,description\nDOC-0001,"abc" \n',
        ",",
        id="whitespace-after-closing-quote",
    ),
    pytest.param(
        'record_id,description\nDOC-0001,"abc\\"def"\n',
        ",",
        id="unsupported-backslash-escape",
    ),
    pytest.param(
        'record_id,description\nDOC-0001,"missing\n',
        ",",
        id="unterminated-quote",
    ),
    pytest.param(
        'record_id,description\nDOC-0001,prefix"suffix\n',
        ",",
        id="quote-in-unquoted-field",
    ),
    pytest.param(
        'record_id,description\nDOC-0001,""x\n',
        ",",
        id="characters-after-empty-quoted-field",
    ),
    pytest.param(
        'record_id,description\nDOC-0001,"a"""x\n',
        ",",
        id="characters-after-escaped-quote",
    ),
]


@pytest.mark.parametrize(
    ("content", "delimiter"),
    INVALID_CASES,
)
def test_illegal_csv_boundary(
    tmp_path,
    content,
    delimiter,
):
    snapshot = _snapshot(tmp_path, content)

    with pytest.raises(CsvEvidenceResolutionError):
        resolve_csv_record(
            snapshot,
            delimiter=delimiter,
        )
