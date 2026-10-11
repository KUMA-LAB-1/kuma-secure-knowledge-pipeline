"""Immutable source locations for future knowledge retrieval."""

import math
import re
from dataclasses import dataclass

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_RECORD_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_KINDS = frozenset({"pdf_page", "image_region", "csv_row"})


@dataclass(frozen=True, slots=True, kw_only=True)
class SourceLocator:
    """Identify one location in a content-addressed source artifact.

    Page and record indices are one-based. Image regions use
    normalized (left, top, right, bottom) coordinates.
    """

    artifact_id: str
    source_sha256: str
    kind: str
    page: int | None = None
    region: tuple[float, float, float, float] | None = None
    record_index: int | None = None
    record_id: str | None = None

    def __post_init__(self) -> None:
        if type(self.source_sha256) is not str or _SHA256.fullmatch(self.source_sha256) is None:
            raise ValueError("Invalid source SHA-256.")

        if type(self.artifact_id) is not str or self.artifact_id != f"sha256-{self.source_sha256}":
            raise ValueError("Source identity mismatch.")

        if type(self.kind) is not str or self.kind not in _KINDS:
            raise ValueError("Unsupported source location kind.")

        if self.kind == "pdf_page":
            self._validate_pdf_page()
        elif self.kind == "image_region":
            self._validate_image_region()
        else:
            self._validate_csv_row()

    def _validate_pdf_page(self) -> None:
        if type(self.page) is not int or self.page < 1:
            raise ValueError("Invalid PDF page.")

        if any(value is not None for value in (self.region, self.record_index, self.record_id)):
            raise ValueError("Unexpected fields for PDF location.")

    def _validate_image_region(self) -> None:
        if any(value is not None for value in (self.page, self.record_index, self.record_id)):
            raise ValueError("Unexpected fields for image location.")

        region = self.region

        if type(region) is not tuple or len(region) != 4:
            raise ValueError("Invalid image region.")

        if any(
            type(value) not in (int, float) or not 0 <= value <= 1 or not math.isfinite(value)
            for value in region
        ):
            raise ValueError("Invalid image coordinates.")

        left, top, right, bottom = region

        if left >= right or top >= bottom:
            raise ValueError("Image region must have positive area.")

    def _validate_csv_row(self) -> None:
        if self.page is not None or self.region is not None:
            raise ValueError("Unexpected fields for CSV location.")

        if type(self.record_index) is not int or self.record_index < 1:
            raise ValueError("Invalid CSV record index.")

        if type(self.record_id) is not str or _RECORD_ID.fullmatch(self.record_id) is None:
            raise ValueError("Invalid CSV record identifier.")
