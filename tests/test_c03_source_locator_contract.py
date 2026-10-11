from dataclasses import FrozenInstanceError

import pytest

from kuma_secure_knowledge_pipeline.knowledge_contracts import SourceLocator

_SHA = "a" * 64
_ID = f"sha256-{_SHA}"


def test_pdf_page_locator():
    locator = SourceLocator(
        artifact_id=_ID,
        source_sha256=_SHA,
        kind="pdf_page",
        page=3,
    )

    assert locator.page == 3
    assert locator.kind == "pdf_page"


def test_image_region_locator():
    locator = SourceLocator(
        artifact_id=_ID,
        source_sha256=_SHA,
        kind="image_region",
        region=(0.1, 0.2, 0.9, 0.8),
    )

    assert locator.region == (0.1, 0.2, 0.9, 0.8)


def test_csv_row_locator():
    locator = SourceLocator(
        artifact_id=_ID,
        source_sha256=_SHA,
        kind="csv_row",
        record_index=42,
        record_id="OPP-0042",
    )

    assert locator.record_index == 42
    assert locator.record_id == "OPP-0042"


def test_rejects_source_identity_mismatch():
    with pytest.raises(ValueError):
        SourceLocator(
            artifact_id=_ID,
            source_sha256="b" * 64,
            kind="pdf_page",
            page=1,
        )


def test_rejects_invalid_locations():
    invalid = (
        {"kind": "pdf_page", "page": 0},
        {"kind": "csv_row", "record_index": 0, "record_id": "OPP-1"},
        {"kind": "image_region", "region": (-0.1, 0.2, 0.9, 0.8)},
        {"kind": "pdf_page", "page": 1, "record_index": 2},
    )

    for fields in invalid:
        with pytest.raises(ValueError):
            SourceLocator(
                artifact_id=_ID,
                source_sha256=_SHA,
                **fields,
            )


def test_locator_is_immutable():
    locator = SourceLocator(
        artifact_id=_ID,
        source_sha256=_SHA,
        kind="pdf_page",
        page=1,
    )

    with pytest.raises(FrozenInstanceError):
        locator.page = 2
