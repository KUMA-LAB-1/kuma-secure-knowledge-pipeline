from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from kuma_secure_knowledge_pipeline.artifacts import (
    InvalidArtifactError,
    verify_artifact_integrity,
)
from kuma_secure_knowledge_pipeline.contracts import (
    ExtractionResult,
    SourceArtifact,
)
from kuma_secure_knowledge_pipeline.extraction.textract import (
    normalize_detect_document_text_response,
)

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
    source_path: Path,
    media_type: str,
) -> None:
    signatures = _MEDIA_SIGNATURES.get(media_type)

    if signatures is None:
        raise UnsupportedMediaTypeError(f"Unsupported media type for OCR: {media_type}")

    with source_path.open("rb") as source:
        header = source.read(16)

    if not any(header.startswith(signature) for signature in signatures):
        raise InvalidArtifactError(
            "Source artifact signature does not match its declared media type."
        )


@dataclass(slots=True)
class TextractExtractor:
    """Amazon Textract adapter with security checks at the boundary."""

    client: TextractClientProtocol

    def extract(
        self,
        *,
        artifact: SourceArtifact,
        source_path: Path,
    ) -> tuple[dict[str, Any], ExtractionResult]:
        if artifact.media_type not in SUPPORTED_MEDIA_TYPES:
            raise UnsupportedMediaTypeError(
                f"Unsupported media type for OCR: {artifact.media_type}"
            )

        verify_artifact_integrity(
            source_path,
            artifact,
        )

        _verify_media_signature(
            source_path,
            artifact.media_type,
        )

        document_bytes = source_path.read_bytes()

        try:
            response = self.client.detect_document_text(
                Document={
                    "Bytes": document_bytes,
                }
            )
        except Exception as exc:
            raise TextractProviderError("Textract provider call failed.") from exc

        result = normalize_detect_document_text_response(
            artifact_id=artifact.artifact_id,
            response=response,
        )

        return response, result
