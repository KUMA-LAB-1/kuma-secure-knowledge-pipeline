from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import kuma_secure_knowledge_pipeline.extraction.client as client_module
from kuma_secure_knowledge_pipeline.contracts import (
    ExtractionProvenance,
)
from kuma_secure_knowledge_pipeline.runner import (
    run_local_pipeline,
)

EXPECTED_REGION = "us-east-1"


def _fixture() -> Path:
    return (
        Path(__file__).parent
        / "fixtures"
        / "ocr"
        / "textract"
        / "v2"
        / "KUMA_TEXTRACT_FIXTURE_INCIDENT_v2.png"
    )


def _provenance() -> ExtractionProvenance:
    return ExtractionProvenance(
        run_id="run-runtime-region-001",
        provider="amazon-textract",
        operation="DetectDocumentText",
        region=EXPECTED_REGION,
        started_at_utc="2026-10-07T20:30:00Z",
    )


class RegionAwareFakeClient:
    def __init__(
        self,
        region_name: str,
    ) -> None:
        self.meta = SimpleNamespace(
            region_name=region_name,
        )
        self.calls = 0

    def detect_document_text(
        self,
        **kwargs: Any,
    ) -> dict[str, Any]:
        self.calls += 1

        return {
            "DocumentMetadata": {
                "Pages": 1,
            },
            "Blocks": [
                {
                    "BlockType": "LINE",
                    "Id": "line-region-001",
                    "Page": 1,
                    "Confidence": 99.9,
                    "Text": "REGION BOUNDARY",
                }
            ],
        }


def test_runner_rejects_wrong_concrete_client_region_before_provider(
    tmp_path: Path,
) -> None:
    client = RegionAwareFakeClient(
        "eu-west-1",
    )

    with pytest.raises(
        ValueError,
        match="region",
    ):
        run_local_pipeline(
            source_path=_fixture(),
            output_root=tmp_path,
            client=client,
            provenance=_provenance(),
        )

    assert client.calls == 0

    assert not any(tmp_path.iterdir())


def test_boto3_factory_pins_profile_and_region(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    class FakeSession:
        def __init__(
            self,
            *,
            profile_name: str | None = None,
            region_name: str | None = None,
        ) -> None:
            captured["session_profile"] = profile_name
            captured["session_region"] = region_name

        def client(
            self,
            service_name: str,
            *,
            region_name: str | None = None,
        ) -> Any:
            captured["service_name"] = service_name
            captured["client_region"] = region_name

            return RegionAwareFakeClient(
                region_name or "unknown",
            )

    fake_boto3 = SimpleNamespace(
        Session=FakeSession,
    )

    monkeypatch.setattr(
        client_module,
        "boto3",
        fake_boto3,
        raising=False,
    )

    factory = getattr(
        client_module,
        "create_textract_client",
        None,
    )

    assert callable(factory), "Concrete boto3 Textract factory is missing"

    assert (
        getattr(
            client_module,
            "TEXTRACT_REGION",
            None,
        )
        == EXPECTED_REGION
    )

    client = factory(
        profile_name="synthetic-project-profile",
        region_name=EXPECTED_REGION,
    )

    assert captured == {
        "session_profile": "synthetic-project-profile",
        "session_region": EXPECTED_REGION,
        "service_name": "textract",
        "client_region": EXPECTED_REGION,
    }

    assert client.meta.region_name == EXPECTED_REGION
