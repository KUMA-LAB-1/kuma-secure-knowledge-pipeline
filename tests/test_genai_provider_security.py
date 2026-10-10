"""Adversarial tests for the offline provider-neutral GenAI interface."""

import json
from dataclasses import is_dataclass

import pytest

from kuma_secure_knowledge_pipeline.genai_provider import (
    FakeGenAIProvider,
    GenAIProviderExecutionError,
    GenAIProviderIntegrityError,
    enrich_with_provider,
)
from kuma_secure_knowledge_pipeline.genai_request import (
    GenAIRequest,
    build_genai_request,
)
from kuma_secure_knowledge_pipeline.genai_response import (
    GenAIResponseIntegrityError,
)
from kuma_secure_knowledge_pipeline.orchestration import AnalysisInput


@pytest.fixture
def genai_request() -> GenAIRequest:
    context = AnalysisInput(
        artifact_id="sha256-" + "a" * 64,
        extraction_run_id="run-provider-security-001",
        source_sha256="a" * 64,
        provider="tesseract",
        operation="TesseractTSV",
        text="SYNTHETIC AUTHENTICATION EVENT",
        evidence_block_ids=("tsv-row-2", "tsv-row-3"),
    )
    return build_genai_request(context)


def response_bytes(
    *,
    reference: str = "tsv-row-2",
    confirmed: bool = False,
    facts: bool = True,
) -> bytes:
    payload = {
        "facts": (
            [
                {
                    "statement": "Synthetic authentication event",
                    "evidence_block_ids": [reference],
                }
            ]
            if facts
            else []
        ),
        "hypotheses": ["Possible account abuse"],
        "missing_evidence": ["Authentication logs"],
        "recommended_checks": ["Review source IP"],
        "incident_confirmed": confirmed,
    }
    return json.dumps(payload, ensure_ascii=False).encode()


class RecordingProvider:
    def __init__(self, output: object) -> None:
        self.output = output
        self.calls = 0
        self.last_request: object = None

    def generate(self, request: object) -> object:
        self.calls += 1
        self.last_request = request
        return self.output


class FailingProvider:
    def generate(self, request: object) -> bytes:
        raise RuntimeError("Synthetic adapter failure")


def test_fake_is_deterministic_and_preserves_bytes(
    genai_request: GenAIRequest,
) -> None:
    raw = response_bytes()
    fake = FakeGenAIProvider(raw)

    assert is_dataclass(fake)
    assert hasattr(fake, "__slots__")
    assert fake.generate(genai_request) == raw
    assert fake.generate(genai_request) == raw
    assert fake.response_bytes is raw


def test_valid_fake_result_is_structured(
    genai_request: GenAIRequest,
) -> None:
    result = enrich_with_provider(
        genai_request,
        provider=FakeGenAIProvider(response_bytes()),
    )

    assert len(result.facts) == 1
    assert result.facts[0].evidence_block_ids == ("tsv-row-2",)
    assert result.incident_confirmed is False


def test_hypotheses_remain_separate_from_facts(
    genai_request: GenAIRequest,
) -> None:
    result = enrich_with_provider(
        genai_request,
        provider=FakeGenAIProvider(response_bytes()),
    )

    assert result.hypotheses == ("Possible account abuse",)
    assert result.missing_evidence == ("Authentication logs",)
    assert result.recommended_checks == ("Review source IP",)
    assert len(result.facts) == 1


def test_model_confirmation_remains_blocked(
    genai_request: GenAIRequest,
) -> None:
    fake = FakeGenAIProvider(response_bytes(confirmed=True))

    with pytest.raises(GenAIResponseIntegrityError):
        enrich_with_provider(genai_request, provider=fake)


def test_unknown_evidence_reference_remains_blocked(
    genai_request: GenAIRequest,
) -> None:
    fake = FakeGenAIProvider(response_bytes(reference="tsv-row-999"))

    with pytest.raises(GenAIResponseIntegrityError):
        enrich_with_provider(genai_request, provider=fake)


def test_malformed_provider_json_remains_blocked(
    genai_request: GenAIRequest,
) -> None:
    fake = FakeGenAIProvider(b'{"facts":')

    with pytest.raises(GenAIResponseIntegrityError):
        enrich_with_provider(genai_request, provider=fake)


def test_provider_receives_request_exactly_once(
    genai_request: GenAIRequest,
) -> None:
    provider = RecordingProvider(response_bytes())

    result = enrich_with_provider(
        genai_request,
        provider=provider,
    )

    assert provider.calls == 1
    assert provider.last_request is genai_request
    assert result.incident_confirmed is False


def test_empty_facts_do_not_confirm_incident(
    genai_request: GenAIRequest,
) -> None:
    fake = FakeGenAIProvider(response_bytes(facts=False))

    result = enrich_with_provider(
        genai_request,
        provider=fake,
    )

    assert result.facts == ()
    assert result.incident_confirmed is False


def test_rejects_forged_request_before_provider_call() -> None:
    provider = RecordingProvider(response_bytes())

    with pytest.raises(GenAIProviderIntegrityError):
        enrich_with_provider(object(), provider=provider)

    assert provider.calls == 0


def test_rejects_provider_without_generate(
    genai_request: GenAIRequest,
) -> None:
    with pytest.raises(GenAIProviderIntegrityError):
        enrich_with_provider(genai_request, provider=object())


def test_rejects_fake_constructed_with_nonbytes() -> None:
    with pytest.raises(GenAIProviderIntegrityError):
        FakeGenAIProvider("not bytes")


def test_fake_rejects_forged_request_on_direct_call() -> None:
    fake = FakeGenAIProvider(response_bytes())

    with pytest.raises(GenAIProviderIntegrityError):
        fake.generate(object())


def test_rejects_provider_returning_text(
    genai_request: GenAIRequest,
) -> None:
    provider = RecordingProvider('{"facts":[]}')

    with pytest.raises(GenAIProviderIntegrityError):
        enrich_with_provider(genai_request, provider=provider)


def test_rejects_provider_returning_none(
    genai_request: GenAIRequest,
) -> None:
    provider = RecordingProvider(None)

    with pytest.raises(GenAIProviderIntegrityError):
        enrich_with_provider(genai_request, provider=provider)


def test_normalizes_provider_runtime_error(
    genai_request: GenAIRequest,
) -> None:
    with pytest.raises(GenAIProviderExecutionError):
        enrich_with_provider(
            genai_request,
            provider=FailingProvider(),
        )
