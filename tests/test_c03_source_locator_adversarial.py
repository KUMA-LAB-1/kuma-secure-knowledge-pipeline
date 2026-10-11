"""Adversarial validation for content-addressed source locations."""

import pytest

from kuma_secure_knowledge_pipeline.knowledge_contracts import SourceLocator

SHA = "a" * 64
ARTIFACT_ID = f"sha256-{SHA}"


@pytest.mark.parametrize(
    "bad_sha",
    [
        None,
        True,
        0,
        b"a" * 64,
        "A" * 64,
        "a" * 63,
        "a" * 65,
        "z" * 64,
    ],
)
def test_rejects_invalid_source_digests(bad_sha):
    with pytest.raises(ValueError):
        SourceLocator(
            artifact_id=ARTIFACT_ID,
            source_sha256=bad_sha,
            kind="pdf_page",
            page=1,
        )


@pytest.mark.parametrize(
    "bad_identity",
    [
        None,
        True,
        "",
        "sha256-" + "b" * 64,
        "sha256-" + "A" * 64,
        "sha256-" + SHA + "/../../",
    ],
)
def test_rejects_forged_artifact_identity(bad_identity):
    with pytest.raises(ValueError):
        SourceLocator(
            artifact_id=bad_identity,
            source_sha256=SHA,
            kind="pdf_page",
            page=1,
        )


@pytest.mark.parametrize(
    "bad_kind",
    [
        None,
        True,
        "",
        "PDF_PAGE",
        "pdf_page ",
        "csv_row\n",
        "pdf_page/../../",
    ],
)
def test_rejects_unsupported_location_kinds(bad_kind):
    with pytest.raises(ValueError):
        SourceLocator(
            artifact_id=ARTIFACT_ID,
            source_sha256=SHA,
            kind=bad_kind,
            page=1,
        )


@pytest.mark.parametrize(
    "bad_page",
    [None, 0, -1, True, False, 1.0, "1", float("inf")],
)
def test_rejects_invalid_pdf_page_types(bad_page):
    with pytest.raises(ValueError):
        SourceLocator(
            artifact_id=ARTIFACT_ID,
            source_sha256=SHA,
            kind="pdf_page",
            page=bad_page,
        )


@pytest.mark.parametrize(
    "extra",
    [
        {"record_index": 1},
        {"record_id": "OPP-0001"},
        {"region": (0.0, 0.0, 1.0, 1.0)},
    ],
)
def test_pdf_rejects_cross_format_fields(extra):
    with pytest.raises(ValueError):
        SourceLocator(
            artifact_id=ARTIFACT_ID,
            source_sha256=SHA,
            kind="pdf_page",
            page=1,
            **extra,
        )


@pytest.mark.parametrize(
    "bad_region",
    [
        None,
        [0.0, 0.0, 1.0, 1.0],
        (0.0, 0.0, 1.0),
        (0.0, 0.0, 1.0, 1.0, 1.0),
        (0.0, 0.0, 0.0, 1.0),
        (0.0, 0.0, 1.0, 0.0),
        (0.9, 0.1, 0.2, 0.8),
        (0.1, 0.9, 0.8, 0.2),
        (-0.01, 0.0, 0.9, 0.9),
        (0.0, 0.0, 1.01, 1.0),
        (0.0, 0.0, 1.0, float("nan")),
        (0.0, 0.0, float("inf"), 1.0),
        (False, 0.0, 1.0, 1.0),
        (0.0, 0.0, True, 1.0),
        (0.0, 0.0, "1", 1.0),
    ],
)
def test_rejects_invalid_image_geometry(bad_region):
    with pytest.raises(ValueError):
        SourceLocator(
            artifact_id=ARTIFACT_ID,
            source_sha256=SHA,
            kind="image_region",
            region=bad_region,
        )


@pytest.mark.parametrize(
    "extra",
    [
        {"page": 1},
        {"record_index": 1},
        {"record_id": "OPP-0001"},
    ],
)
def test_image_rejects_cross_format_fields(extra):
    with pytest.raises(ValueError):
        SourceLocator(
            artifact_id=ARTIFACT_ID,
            source_sha256=SHA,
            kind="image_region",
            region=(0.1, 0.2, 0.8, 0.9),
            **extra,
        )


@pytest.mark.parametrize(
    "bad_index",
    [None, 0, -1, True, False, 1.0, "1", float("nan")],
)
def test_rejects_invalid_csv_record_index(bad_index):
    with pytest.raises(ValueError):
        SourceLocator(
            artifact_id=ARTIFACT_ID,
            source_sha256=SHA,
            kind="csv_row",
            record_index=bad_index,
            record_id="OPP-0001",
        )


@pytest.mark.parametrize(
    "bad_record_id",
    [
        None,
        True,
        "",
        "  ",
        "OPP 0001",
        "OPP\n0001",
        "OPP/../../",
        "../secret",
        "OPP' OR 1=1 --",
        "OPP-\x00-1",
        "ÁREA-01",
        "A" * 129,
    ],
)
def test_rejects_invalid_csv_record_identifier(bad_record_id):
    with pytest.raises(ValueError):
        SourceLocator(
            artifact_id=ARTIFACT_ID,
            source_sha256=SHA,
            kind="csv_row",
            record_index=1,
            record_id=bad_record_id,
        )


@pytest.mark.parametrize(
    "extra",
    [
        {"page": 1},
        {"region": (0.0, 0.0, 1.0, 1.0)},
    ],
)
def test_csv_rejects_cross_format_fields(extra):
    with pytest.raises(ValueError):
        SourceLocator(
            artifact_id=ARTIFACT_ID,
            source_sha256=SHA,
            kind="csv_row",
            record_index=1,
            record_id="OPP-0001",
            **extra,
        )


def test_valid_boundary_locations_remain_accepted():
    pdf = SourceLocator(
        artifact_id=ARTIFACT_ID,
        source_sha256=SHA,
        kind="pdf_page",
        page=1,
    )

    image = SourceLocator(
        artifact_id=ARTIFACT_ID,
        source_sha256=SHA,
        kind="image_region",
        region=(0.0, 0.0, 1.0, 1.0),
    )

    csv = SourceLocator(
        artifact_id=ARTIFACT_ID,
        source_sha256=SHA,
        kind="csv_row",
        record_index=1,
        record_id="OPP:2026-0001",
    )

    assert pdf.page == 1
    assert image.region == (0.0, 0.0, 1.0, 1.0)
    assert csv.record_id == "OPP:2026-0001"
