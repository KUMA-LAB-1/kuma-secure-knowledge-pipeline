"""Tests for PDF page resolution against verified snapshot bytes."""

from dataclasses import FrozenInstanceError, replace
from io import BytesIO

import pytest
from pypdf import PdfWriter

from kuma_secure_knowledge_pipeline.artifacts import build_source_artifact
from kuma_secure_knowledge_pipeline.knowledge_contracts import SourceLocator
from kuma_secure_knowledge_pipeline.knowledge_evidence import (
    load_verified_source_snapshot,
)
from kuma_secure_knowledge_pipeline.knowledge_pdf import (
    PdfEvidenceResolutionError,
    resolve_pdf_page,
)


def _pdf(*, page_count=3, encrypted=False):
    writer = PdfWriter()

    for _ in range(page_count):
        writer.add_blank_page(width=72, height=72)

    if encrypted:
        writer.encrypt("synthetic-test-password")

    output = BytesIO()
    writer.write(output)
    return output.getvalue()


def _snapshot(
    tmp_path,
    data=None,
    *,
    page=2,
    filename="synthetic.pdf",
    media_type=None,
    kind="pdf_page",
):
    content = _pdf() if data is None else data
    path = tmp_path / filename
    path.write_bytes(content)

    artifact = build_source_artifact(path)

    if media_type is not None:
        artifact = replace(artifact, media_type=media_type)

    if kind == "pdf_page":
        locator = SourceLocator(
            artifact_id=artifact.artifact_id,
            source_sha256=artifact.sha256,
            kind="pdf_page",
            page=page,
        )
    else:
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
        max_bytes=max(len(content), 1),
    )

    return path, snapshot


def test_resolves_existing_page(tmp_path):
    _, snapshot = _snapshot(tmp_path)

    result = resolve_pdf_page(snapshot)

    assert result.artifact_id == snapshot.artifact.artifact_id
    assert result.source_sha256 == snapshot.artifact.sha256
    assert result.page == 2
    assert result.page_count == 3


@pytest.mark.parametrize("page", [1, 3])
def test_resolves_first_and_last_page(tmp_path, page):
    _, snapshot = _snapshot(tmp_path, page=page)

    result = resolve_pdf_page(snapshot)

    assert result.page == page
    assert result.page_count == 3


def test_uses_snapshot_after_original_file_is_deleted(tmp_path):
    path, snapshot = _snapshot(tmp_path)
    path.unlink()

    assert resolve_pdf_page(snapshot).page == 2


def test_uses_snapshot_after_original_file_changes(tmp_path):
    path, snapshot = _snapshot(tmp_path)
    path.write_bytes(b"changed source")

    assert resolve_pdf_page(snapshot).page_count == 3


def test_rejects_nonexistent_page(tmp_path):
    _, snapshot = _snapshot(tmp_path, page=4)

    with pytest.raises(PdfEvidenceResolutionError, match="does not exist"):
        resolve_pdf_page(snapshot)


def test_rejects_truncated_pdf(tmp_path):
    _, snapshot = _snapshot(tmp_path, _pdf()[:75])

    with pytest.raises(PdfEvidenceResolutionError):
        resolve_pdf_page(snapshot)


def test_rejects_fake_pdf_with_valid_header(tmp_path):
    _, snapshot = _snapshot(tmp_path, b"%PDF-1.7\nnot a real PDF")

    with pytest.raises(PdfEvidenceResolutionError):
        resolve_pdf_page(snapshot)


def test_rejects_invalid_header(tmp_path):
    _, snapshot = _snapshot(tmp_path, b"ordinary text")

    with pytest.raises(PdfEvidenceResolutionError, match="header"):
        resolve_pdf_page(snapshot)


def test_rejects_encrypted_pdf(tmp_path):
    _, snapshot = _snapshot(tmp_path, _pdf(encrypted=True))

    with pytest.raises(PdfEvidenceResolutionError, match="Encrypted"):
        resolve_pdf_page(snapshot)


def test_rejects_wrong_media_type(tmp_path):
    _, snapshot = _snapshot(
        tmp_path,
        media_type="text/plain",
    )

    with pytest.raises(PdfEvidenceResolutionError, match="registered"):
        resolve_pdf_page(snapshot)


def test_rejects_wrong_file_extension(tmp_path):
    _, snapshot = _snapshot(
        tmp_path,
        filename="synthetic.csv",
        media_type="application/pdf",
    )

    with pytest.raises(PdfEvidenceResolutionError, match="registered"):
        resolve_pdf_page(snapshot)


def test_rejects_wrong_locator_kind(tmp_path):
    _, snapshot = _snapshot(tmp_path, kind="csv_row")

    with pytest.raises(PdfEvidenceResolutionError, match="locator"):
        resolve_pdf_page(snapshot)


def test_rejects_non_snapshot():
    with pytest.raises(PdfEvidenceResolutionError, match="snapshot"):
        resolve_pdf_page(object())


@pytest.mark.parametrize(
    "bad_limit",
    [None, True, False, 0, -1, 1.0, "256", 1025],
)
def test_rejects_invalid_page_limit(tmp_path, bad_limit):
    _, snapshot = _snapshot(tmp_path)

    with pytest.raises(PdfEvidenceResolutionError, match="limit"):
        resolve_pdf_page(snapshot, max_pages=bad_limit)


def test_rejects_page_count_above_limit(tmp_path):
    _, snapshot = _snapshot(tmp_path)

    with pytest.raises(PdfEvidenceResolutionError, match="count"):
        resolve_pdf_page(snapshot, max_pages=2)


def test_rejects_zero_page_document(tmp_path):
    _, snapshot = _snapshot(tmp_path, _pdf(page_count=0))

    with pytest.raises(PdfEvidenceResolutionError):
        resolve_pdf_page(snapshot)


def test_rejects_oversized_pdf_snapshot(tmp_path):
    content = _pdf() + b" " * (16 * 1024 * 1024)
    _, snapshot = _snapshot(tmp_path, content)

    with pytest.raises(PdfEvidenceResolutionError, match="input limit"):
        resolve_pdf_page(snapshot)


def test_result_is_immutable(tmp_path):
    _, snapshot = _snapshot(tmp_path)
    result = resolve_pdf_page(snapshot)

    with pytest.raises(FrozenInstanceError):
        result.page = 3
