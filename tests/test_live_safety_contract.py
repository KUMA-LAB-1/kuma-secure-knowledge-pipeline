import tomllib
from pathlib import Path
from typing import Any

import pytest

from kuma_secure_knowledge_pipeline.contracts import (
    ExtractionProvenance,
)
from kuma_secure_knowledge_pipeline.evidence import (
    EvidenceAlreadyExistsError,
    EvidenceSerializationError,
)
from kuma_secure_knowledge_pipeline.extraction.client import (
    TextractProviderError,
)
from kuma_secure_knowledge_pipeline.runner import (
    run_local_pipeline,
)

PROVIDER = "amazon-textract"
OPERATION = "DetectDocumentText"
REGION = "us-east-1"


def _fixture() -> Path:
    return (
        Path(__file__).parent
        / "fixtures"
        / "ocr"
        / "textract"
        / "v2"
        / "KUMA_TEXTRACT_FIXTURE_INCIDENT_v2.png"
    )


def _provenance(
    run_id: str,
) -> ExtractionProvenance:
    return ExtractionProvenance(
        run_id=run_id,
        provider=PROVIDER,
        operation=OPERATION,
        region=REGION,
        started_at_utc="2026-10-07T18:30:00Z",
    )


class AlwaysFailingTextractClient:
    def __init__(self) -> None:
        self.calls = 0

    def detect_document_text(
        self,
        **kwargs: Any,
    ) -> dict[str, Any]:
        self.calls += 1

        raise RuntimeError("synthetic-ambiguous-provider-failure")


class NonSerializableTextractClient:
    def __init__(self) -> None:
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
                    "Id": "line-live-safety-001",
                    "Page": 1,
                    "Confidence": 99.9,
                    "Text": "LIVE SAFETY CONTRACT",
                }
            ],
            "UnexpectedObject": object(),
        }


def test_ambiguous_provider_failure_keeps_fail_closed_reservation(
    tmp_path: Path,
) -> None:
    client = AlwaysFailingTextractClient()

    provenance = _provenance("run-ambiguous-provider-001")

    with pytest.raises(
        TextractProviderError,
        match="provider call failed",
    ):
        run_local_pipeline(
            source_path=_fixture(),
            output_root=tmp_path,
            client=client,
            provenance=provenance,
        )

    assert client.calls == 1

    reservations = list(tmp_path.rglob("*.reservation"))

    assert len(reservations) == 1

    # O mesmo run_id deve ficar bloqueado.
    # Não sabemos com certeza se o provider
    # processou a primeira tentativa.
    with pytest.raises(
        EvidenceAlreadyExistsError,
    ):
        run_local_pipeline(
            source_path=_fixture(),
            output_root=tmp_path,
            client=client,
            provenance=provenance,
        )

    assert client.calls == 1


def test_post_provider_serialization_failure_keeps_fail_closed_reservation(
    tmp_path: Path,
) -> None:
    client = NonSerializableTextractClient()

    provenance = _provenance("run-post-provider-serialization-001")

    with pytest.raises(
        EvidenceSerializationError,
    ):
        run_local_pipeline(
            source_path=_fixture(),
            output_root=tmp_path,
            client=client,
            provenance=provenance,
        )

    assert client.calls == 1

    reservations = list(tmp_path.rglob("*.reservation"))

    assert len(reservations) == 1

    with pytest.raises(
        EvidenceAlreadyExistsError,
    ):
        run_local_pipeline(
            source_path=_fixture(),
            output_root=tmp_path,
            client=client,
            provenance=provenance,
        )

    assert client.calls == 1


def test_project_declares_aws_crt_for_login_credentials() -> None:
    pyproject_path = Path("pyproject.toml")
    lock_path = Path("uv.lock")

    project = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))

    dependencies = [dependency.lower() for dependency in project["project"]["dependencies"]]

    assert any(dependency.startswith("boto3[crt]") for dependency in dependencies), (
        "aws login credentials require the Boto3 CRT extra in this project"
    )

    lock = lock_path.read_text(encoding="utf-8").lower()

    assert 'name = "awscrt"' in lock
