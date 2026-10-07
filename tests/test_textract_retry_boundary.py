from types import SimpleNamespace
from typing import Any

import pytest

import kuma_secure_knowledge_pipeline.extraction.client as client_module

EXPECTED_REGION = "us-east-1"


class RegionAwareFakeClient:
    def __init__(
        self,
        region_name: str,
    ) -> None:
        self.meta = SimpleNamespace(
            region_name=region_name,
        )


def test_textract_factory_disables_sdk_retries(
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
            config: Any | None = None,
        ) -> Any:
            captured["service_name"] = service_name
            captured["client_region"] = region_name
            captured["config"] = config

            return RegionAwareFakeClient(
                region_name or "unknown",
            )

    monkeypatch.setattr(
        client_module.boto3,
        "Session",
        FakeSession,
    )

    client = client_module.create_textract_client(
        profile_name="synthetic-project-profile",
        region_name=EXPECTED_REGION,
    )

    config = captured["config"]

    assert config is not None, "Textract client must receive an explicit botocore Config"

    retries = getattr(
        config,
        "retries",
        {},
    )

    assert retries.get("total_max_attempts") == 1, (
        "Textract must perform exactly one total SDK attempt"
    )

    assert retries.get("mode") == "standard"

    assert captured["service_name"] == "textract"
    assert captured["client_region"] == EXPECTED_REGION
    assert client.meta.region_name == EXPECTED_REGION
