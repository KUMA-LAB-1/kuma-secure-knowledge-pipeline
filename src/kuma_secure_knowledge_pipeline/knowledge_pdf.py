"""Resolve PDF page references from verified immutable source bytes."""

from dataclasses import dataclass
from io import BytesIO

from pypdf import PdfReader

from kuma_secure_knowledge_pipeline.knowledge_evidence import (
    VerifiedSourceSnapshot,
)

_MAX_PDF_BYTES = 16 * 1024 * 1024
_MAX_PAGES = 1024


class PdfEvidenceResolutionError(ValueError):
    """A PDF page could not be resolved against verified source bytes."""


@dataclass(frozen=True, slots=True, kw_only=True)
class ResolvedPdfPage:
    """Immutable page identity, without asserting content authenticity."""

    artifact_id: str
    source_sha256: str
    page: int
    page_count: int


def resolve_pdf_page(
    snapshot: VerifiedSourceSnapshot,
    *,
    max_pages: int = 256,
) -> ResolvedPdfPage:
    """Resolve a one-based PDF page without extracting text or images."""
    if not isinstance(snapshot, VerifiedSourceSnapshot):
        raise PdfEvidenceResolutionError("Invalid verified source snapshot.")

    if snapshot.locator.kind != "pdf_page":
        raise PdfEvidenceResolutionError("Source locator is not a PDF page.")

    if (
        snapshot.artifact.media_type != "application/pdf"
        or not snapshot.artifact.filename.lower().endswith(".pdf")
    ):
        raise PdfEvidenceResolutionError("Source is not registered as PDF.")

    if type(max_pages) is not int or not 1 <= max_pages <= _MAX_PAGES:
        raise PdfEvidenceResolutionError("Invalid PDF page limit.")

    content = snapshot.content

    if len(content) > _MAX_PDF_BYTES:
        raise PdfEvidenceResolutionError("PDF source exceeds parser input limit.")

    if not content.startswith(b"%PDF-"):
        raise PdfEvidenceResolutionError("Invalid PDF header.")

    try:
        with BytesIO(content) as stream:
            reader = PdfReader(stream, strict=True)

            try:
                if reader.is_encrypted:
                    raise PdfEvidenceResolutionError("Encrypted PDF is not supported.")

                page_count = len(reader.pages)

                if not 1 <= page_count <= max_pages:
                    raise PdfEvidenceResolutionError("PDF page count outside configured limit.")

                if snapshot.locator.page > page_count:
                    raise PdfEvidenceResolutionError("PDF page does not exist.")

                page = reader.pages[snapshot.locator.page - 1]

                if page.get("/Type") != "/Page":
                    raise PdfEvidenceResolutionError("Invalid PDF page object.")
            finally:
                reader.close()

    except PdfEvidenceResolutionError:
        raise
    except Exception:
        raise PdfEvidenceResolutionError("Cannot resolve PDF structure.") from None

    return ResolvedPdfPage(
        artifact_id=snapshot.artifact.artifact_id,
        source_sha256=snapshot.artifact.sha256,
        page=snapshot.locator.page,
        page_count=page_count,
    )
