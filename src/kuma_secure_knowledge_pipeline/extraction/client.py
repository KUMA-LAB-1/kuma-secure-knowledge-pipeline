from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from kuma_secure_knowledge_pipeline.artifacts import (
    verify_artifact_integrity,
)
from kuma_secure_knowledge_pipeline.contracts import (
    ExtractionResult,
    SourceArtifact,
)
from kuma_secure_knowledge_pipeline.extraction.textract import (
    normalize_detect_document_text_response,
)


class TextractClientProtocol(Protocol):
    def detect_document_text(
        self,
        **kwargs: Any,
    ) -> dict[str, Any]: ...


@dataclass(slots=True)
class TextractExtractor:
    """Amazon Textract adapter with an injectable client for testability."""

    client: TextractClientProtocol

    def extract(
        self,
        *,
        artifact: SourceArtifact,
        source_path: Path,
    ) -> tuple[dict[str, Any], ExtractionResult]:
        verify_artifact_integrity(source_path, artifact)

        document_bytes = source_path.read_bytes()

        response = self.client.detect_document_text(
            Document={
                "Bytes": document_bytes,
            }
        )

        result = normalize_detect_document_text_response(
            artifact_id=artifact.artifact_id,
            response=response,
        )

        return response, result
