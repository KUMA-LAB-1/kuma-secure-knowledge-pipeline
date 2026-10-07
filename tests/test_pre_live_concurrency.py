from pathlib import Path
from threading import Event, Lock, Thread
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


class BlockingTextractClient:
    def __init__(self) -> None:
        self.calls = 0
        self._lock = Lock()
        self.first_call_entered = Event()
        self.second_call_entered = Event()
        self.release_first_call = Event()

    def detect_document_text(
        self,
        **kwargs: Any,
    ) -> dict[str, Any]:
        with self._lock:
            self.calls += 1
            call_number = self.calls

        if call_number == 1:
            self.first_call_entered.set()

            if not self.release_first_call.wait(timeout=5.0):
                raise RuntimeError("synthetic concurrency test timeout")

        elif call_number == 2:
            self.second_call_entered.set()

        return {
            "DocumentMetadata": {
                "Pages": 1,
            },
            "Blocks": [
                {
                    "BlockType": "LINE",
                    "Id": f"line-{call_number:03d}",
                    "Page": 1,
                    "Confidence": 99.5,
                    "Text": "SYNTHETIC CONCURRENCY FIXTURE",
                }
            ],
        }


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
        run_id="run-concurrency-001",
        provider="amazon-textract",
        operation="DetectDocumentText",
        region="us-east-1",
        started_at_utc="2026-10-07T15:00:00Z",
    )


def test_same_run_id_is_atomically_reserved_before_provider_call(
    tmp_path: Path,
) -> None:
    client = BlockingTextractClient()

    results: list[Path] = []
    errors: list[BaseException] = []

    def worker() -> None:
        try:
            evidence_dir = run_local_pipeline(
                source_path=_fixture(),
                output_root=tmp_path,
                client=client,
                provenance=_provenance(),
            )

            results.append(evidence_dir)

        except BaseException as exc:
            errors.append(exc)

    first = Thread(
        target=worker,
        name="kuma-run-first",
    )

    second = Thread(
        target=worker,
        name="kuma-run-second",
    )

    first.start()

    assert client.first_call_entered.wait(timeout=2.0)

    second.start()

    second.join(timeout=1.0)

    second_reached_provider = client.second_call_entered.is_set()

    client.release_first_call.set()

    first.join(timeout=3.0)
    second.join(timeout=3.0)

    assert not first.is_alive()
    assert not second.is_alive()

    assert not second_reached_provider

    assert client.calls == 1

    assert len(results) == 1
    assert len(errors) == 1

    assert isinstance(
        errors[0],
        EvidenceAlreadyExistsError,
    )

    evidence_dir = results[0]

    assert evidence_dir.is_dir()

    assert not list(tmp_path.rglob("*.reservation"))

    assert {path.name for path in evidence_dir.iterdir()} == {
        "raw-response.json",
        "normalized.json",
        "manifest.json",
        "extracted.txt",
    }


class FailingThenSuccessfulTextractClient:
    def __init__(self) -> None:
        self.calls = 0

    def detect_document_text(
        self,
        **kwargs: Any,
    ) -> dict[str, Any]:
        self.calls += 1

        if self.calls == 1:
            raise RuntimeError("synthetic-provider-down")

        return {
            "DocumentMetadata": {
                "Pages": 1,
            },
            "Blocks": [
                {
                    "BlockType": "LINE",
                    "Id": "line-retry-001",
                    "Page": 1,
                    "Confidence": 99.7,
                    "Text": "SYNTHETIC RETRY",
                }
            ],
        }


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
                    "Id": "line-serialize-001",
                    "Page": 1,
                    "Confidence": 99.8,
                    "Text": "SYNTHETIC SERIALIZATION",
                }
            ],
            "UnexpectedObject": object(),
        }


def test_reservation_is_retained_after_ambiguous_provider_failure(
    tmp_path: Path,
) -> None:
    client = FailingThenSuccessfulTextractClient()

    provenance = _provenance()

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


def test_reservation_is_retained_after_post_provider_serialization_failure(
    tmp_path: Path,
) -> None:
    client = NonSerializableTextractClient()

    provenance = _provenance()

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

    assert len(list(tmp_path.rglob("*.reservation"))) == 1
