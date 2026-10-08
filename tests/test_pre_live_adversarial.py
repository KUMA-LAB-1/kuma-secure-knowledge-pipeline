from pathlib import Path
from typing import Any

import pytest

import kuma_secure_knowledge_pipeline.runner as runner_module
from kuma_secure_knowledge_pipeline.contracts import (
    ExtractionProvenance,
)
from kuma_secure_knowledge_pipeline.evidence import (
    EvidenceAlreadyExistsError,
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
    *,
    run_id: str,
    provider: str = PROVIDER,
    operation: str = OPERATION,
    started_at_utc: str = "2026-10-07T15:00:00Z",
) -> ExtractionProvenance:
    return ExtractionProvenance(
        run_id=run_id,
        provider=provider,
        operation=operation,
        region=REGION,
        started_at_utc=started_at_utc,
    )


class CountingTextractClient:
    def __init__(self) -> None:
        self.calls = 0
        self.payloads: list[dict[str, Any]] = []

    def detect_document_text(
        self,
        **kwargs: Any,
    ) -> dict[str, Any]:
        self.calls += 1
        self.payloads.append(kwargs)

        return {
            "DocumentMetadata": {
                "Pages": 1,
            },
            "Blocks": [
                {
                    "BlockType": "LINE",
                    "Id": "line-001",
                    "Page": 1,
                    "Confidence": 99.5,
                    "Text": "SYNTHETIC SECURITY FIXTURE",
                }
            ],
        }


def test_unsafe_run_id_is_rejected_before_provider_call(
    tmp_path: Path,
) -> None:
    client = CountingTextractClient()

    with pytest.raises(
        ValueError,
        match="run_id|unsafe",
    ):
        run_local_pipeline(
            source_path=_fixture(),
            output_root=tmp_path,
            client=client,
            provenance=_provenance(
                run_id="../escape",
            ),
        )

    assert client.calls == 0

    assert not any(tmp_path.iterdir())


def test_existing_run_is_rejected_before_second_provider_call(
    tmp_path: Path,
) -> None:
    client = CountingTextractClient()

    provenance = _provenance(
        run_id="run-duplicate-001",
    )

    first = run_local_pipeline(
        source_path=_fixture(),
        output_root=tmp_path,
        client=client,
        provenance=provenance,
    )

    assert first.is_dir()
    assert client.calls == 1

    with pytest.raises(
        EvidenceAlreadyExistsError,
        match="already exists",
    ):
        run_local_pipeline(
            source_path=_fixture(),
            output_root=tmp_path,
            client=client,
            provenance=provenance,
        )

    # A execução duplicada deve morrer antes de nova chamada faturável.
    assert client.calls == 1


def test_noncanonical_timestamp_is_rejected_before_provider_call(
    tmp_path: Path,
) -> None:
    client = CountingTextractClient()

    with pytest.raises(
        ValueError,
        match="started_at_utc|canonical",
    ):
        run_local_pipeline(
            source_path=_fixture(),
            output_root=tmp_path,
            client=client,
            provenance=_provenance(
                run_id="run-noncanonical-001",
                started_at_utc="2026-10-07 15:00:00Z",
            ),
        )

    assert client.calls == 0

    assert not any(tmp_path.iterdir())


def test_provider_mismatch_is_rejected_before_provider_call(
    tmp_path: Path,
) -> None:
    client = CountingTextractClient()

    with pytest.raises(
        ValueError,
        match="provider",
    ):
        run_local_pipeline(
            source_path=_fixture(),
            output_root=tmp_path,
            client=client,
            provenance=_provenance(
                run_id="run-provider-mismatch",
                provider="unexpected-provider",
            ),
        )

    assert client.calls == 0

    assert not any(tmp_path.iterdir())


def test_unexpected_normalizer_bug_is_not_persisted_as_provider_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = CountingTextractClient()

    provenance = _provenance(
        run_id="run-unexpected-bug-001",
    )

    def raise_unexpected_bug(
        **kwargs: Any,
    ) -> None:
        raise RuntimeError("synthetic-normalizer-bug")

    monkeypatch.setattr(
        runner_module,
        "normalize_detect_document_text_response",
        raise_unexpected_bug,
    )

    with pytest.raises(
        RuntimeError,
        match="synthetic-normalizer-bug",
    ):
        run_local_pipeline(
            source_path=_fixture(),
            output_root=tmp_path,
            client=client,
            provenance=provenance,
        )

    assert client.calls == 1

    # O bug interno não pode gerar bundle classificado
    # falsamente como evidência do provider.
    assert not list(tmp_path.rglob("raw-response.json"))

    assert not list(tmp_path.rglob("manifest.json"))

    assert not list(tmp_path.rglob("normalized.json"))

    assert not list(tmp_path.rglob("extracted.txt"))

    # Porém o provider já foi chamado.
    # A reservation deve permanecer fail-closed para
    # impedir uma segunda chamada com o mesmo run_id.
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

    assert len(list(tmp_path.rglob("*.reservation"))) == 1


def test_region_mismatch_is_rejected_before_provider_call(
    tmp_path: Path,
) -> None:
    client = CountingTextractClient()

    provenance = ExtractionProvenance(
        run_id="run-region-mismatch",
        provider=PROVIDER,
        operation=OPERATION,
        region="eu-west-1",
        started_at_utc="2026-10-07T15:00:00Z",
    )

    with pytest.raises(
        ValueError,
        match="region",
    ):
        run_local_pipeline(
            source_path=_fixture(),
            output_root=tmp_path,
            client=client,
            provenance=provenance,
        )

    assert client.calls == 0

    assert not any(tmp_path.iterdir())
