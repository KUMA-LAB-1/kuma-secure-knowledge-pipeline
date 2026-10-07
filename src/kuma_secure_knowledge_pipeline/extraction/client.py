from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from kuma_secure_knowledge_pipeline.artifacts import (
    InvalidArtifactError,
    verify_artifact_bytes,
)
from kuma_secure_knowledge_pipeline.contracts import (
    ExtractionResult,
    SourceArtifact,
)
from kuma_secure_knowledge_pipeline.extraction.textract import (
    normalize_detect_document_text_response,
)

TEXTRACT_PROVIDER = "amazon-textract"
DETECT_DOCUMENT_TEXT_OPERATION = "DetectDocumentText"

SUPPORTED_MEDIA_TYPES = frozenset(
    {
        "image/png",
        "image/jpeg",
    }
)

_MEDIA_SIGNATURES = {
    "image/png": (b"\x89PNG\r\n\x1a\n",),
    "image/jpeg": (b"\xff\xd8\xff",),
}


class UnsupportedMediaTypeError(ValueError):
    """Raised when a file is not supported by the current OCR adapter."""


class TextractProviderError(RuntimeError):
    """Raised when Amazon Textract cannot complete the provider call."""


class TextractClientProtocol(Protocol):
    def detect_document_text(
        self,
        **kwargs: Any,
    ) -> dict[str, Any]: ...


def _verify_media_signature(
    document_bytes: bytes,
    media_type: str,
) -> None:
    signatures = _MEDIA_SIGNATURES.get(media_type)

    if signatures is None:
        raise UnsupportedMediaTypeError(f"Unsupported media type for OCR: {media_type}")

    header = document_bytes[:16]

    if not any(header.startswith(signature) for signature in signatures):
        raise InvalidArtifactError(
            "Source artifact signature does not match its declared media type."
        )


@dataclass(slots=True)
class TextractExtractor:
    """Amazon Textract adapter with security checks at the boundary."""

    client: TextractClientProtocol

    def extract_raw(
        self,
        *,
        artifact: SourceArtifact,
        source_path: Path,
    ) -> dict[str, Any]:
        if artifact.media_type not in SUPPORTED_MEDIA_TYPES:
            raise UnsupportedMediaTypeError(
                f"Unsupported media type for OCR: {artifact.media_type}"
            )

        # Read exactly once. These are the same bytes that are
        # integrity-checked, signature-checked, and sent to the provider.
        document_bytes = source_path.read_bytes()

        verify_artifact_bytes(
            document_bytes,
            artifact,
        )

        _verify_media_signature(
            document_bytes,
            artifact.media_type,
        )

        try:
            return self.client.detect_document_text(
                Document={
                    "Bytes": document_bytes,
                }
            )
        except Exception as exc:
            raise TextractProviderError("Textract provider call failed.") from exc

    def extract(
        self,
        *,
        artifact: SourceArtifact,
        source_path: Path,
    ) -> tuple[
        dict[str, Any],
        ExtractionResult,
    ]:
        raw_response = self.extract_raw(
            artifact=artifact,
            source_path=source_path,
        )

        result = normalize_detect_document_text_response(
            artifact_id=artifact.artifact_id,
            response=raw_response,
        )

        return raw_response, result
