from pathlib import Path
from typing import Any

import pytest

from kuma_secure_knowledge_pipeline.artifacts import (
    build_source_artifact,
)
from kuma_secure_knowledge_pipeline.extraction.client import (
    TextractExtractor,
)


def _png_bytes() -> bytes:
    return b"\x89PNG\r\n\x1a\nsynthetic-test-content"


class FakeTextractClient:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def detect_document_text(
        self,
        **kwargs: Any,
    ) -> dict[str, Any]:
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


class FailingTextractClient:
    def __init__(self) -> None:
        self.calls = 0

    def detect_document_text(
        self,
        **kwargs: Any,
    ) -> dict[str, Any]:
        self.calls += 1
        raise RuntimeError("provider-down")


def test_textract_extractor_reads_file_and_calls_client(
    tmp_path: Path,
) -> None:
    source = tmp_path / "security-report.png"
    source.write_bytes(_png_bytes())

    artifact = build_source_artifact(source)
    client = FakeTextractClient()

    raw_response, result = TextractExtractor(client).extract(
        artifact=artifact,
        source_path=source,
    )

    assert client.calls[0]["Document"]["Bytes"] == _png_bytes()
    assert raw_response["Blocks"][0]["Id"] == "line-001"

    assert result.artifact_id == artifact.artifact_id
    assert result.text == ("INCIDENT ID: INC-001\nSEVERITY: HIGH")
    assert result.average_confidence == 99.0


def test_textract_extractor_rejects_tampered_file_before_client_call(
    tmp_path: Path,
) -> None:
    source = tmp_path / "security-report.png"
    source.write_bytes(_png_bytes())

    artifact = build_source_artifact(source)

    source.write_bytes(b"\x89PNG\r\n\x1a\ntampered")

    client = FakeTextractClient()

    with pytest.raises(ValueError):
        TextractExtractor(client).extract(
            artifact=artifact,
            source_path=source,
        )

    assert client.calls == []


def test_textract_extractor_rejects_unsupported_media_before_client_call(
    tmp_path: Path,
) -> None:
    source = tmp_path / "security-report.txt"
    source.write_bytes(b"not-an-image")

    artifact = build_source_artifact(source)
    client = FakeTextractClient()

    with pytest.raises(
        ValueError,
        match="Unsupported media type",
    ):
        TextractExtractor(client).extract(
            artifact=artifact,
            source_path=source,
        )

    assert client.calls == []


def test_textract_extractor_rejects_fake_png_before_client_call(
    tmp_path: Path,
) -> None:
    source = tmp_path / "security-report.png"

    source.write_bytes(b"this-is-not-really-a-png")

    artifact = build_source_artifact(source)
    client = FakeTextractClient()

    with pytest.raises(
        ValueError,
        match="signature",
    ):
        TextractExtractor(client).extract(
            artifact=artifact,
            source_path=source,
        )

    assert client.calls == []


def test_textract_extractor_wraps_provider_failure(
    tmp_path: Path,
) -> None:
    source = tmp_path / "security-report.png"
    source.write_bytes(_png_bytes())

    artifact = build_source_artifact(source)
    client = FailingTextractClient()

    with pytest.raises(
        RuntimeError,
        match="Textract provider call failed",
    ) as error:
        TextractExtractor(client).extract(
            artifact=artifact,
            source_path=source,
        )

    assert client.calls == 1
    assert isinstance(
        error.value.__cause__,
        RuntimeError,
    )
