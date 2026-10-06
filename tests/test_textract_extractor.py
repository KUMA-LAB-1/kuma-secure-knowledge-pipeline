from pathlib import Path
from typing import Any

import pytest

from kuma_secure_knowledge_pipeline.artifacts import (
    ArtifactIntegrityError,
    build_source_artifact,
)
from kuma_secure_knowledge_pipeline.extraction.client import TextractExtractor


class FakeTextractClient:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def detect_document_text(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)

        return {
            "Blocks": [
                {
                    "BlockType": "LINE",
                    "Id": "line-001",
                    "Page": 1,
                    "Confidence": 99.2,
                    "Text": "INCIDENT ID: INC-001",
                },
                {
                    "BlockType": "LINE",
                    "Id": "line-002",
                    "Page": 1,
                    "Confidence": 98.8,
                    "Text": "SEVERITY: HIGH",
                },
            ]
        }


def test_textract_extractor_reads_file_and_calls_client(tmp_path: Path) -> None:
    source = tmp_path / "security-report.png"
    source.write_bytes(b"fake-png-content")

    artifact = build_source_artifact(source)
    client = FakeTextractClient()

    raw_response, result = TextractExtractor(client).extract(
        artifact=artifact,
        source_path=source,
    )

    assert client.calls[0]["Document"]["Bytes"] == b"fake-png-content"

    assert raw_response["Blocks"][0]["Id"] == "line-001"

    assert result.artifact_id == artifact.artifact_id
    assert result.text == "INCIDENT ID: INC-001\nSEVERITY: HIGH"
    assert result.average_confidence == 99.0


def test_textract_extractor_rejects_tampered_file_before_client_call(
    tmp_path: Path,
) -> None:
    source = tmp_path / "security-report.png"
    source.write_bytes(b"original")

    artifact = build_source_artifact(source)

    source.write_bytes(b"tampered")

    client = FakeTextractClient()

    with pytest.raises(ArtifactIntegrityError):
        TextractExtractor(client).extract(
            artifact=artifact,
            source_path=source,
        )

    assert client.calls == []
