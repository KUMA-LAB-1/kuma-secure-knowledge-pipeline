"""Adversarial tests for sanitized GenAI failure boundaries.

All failures are synthetic. No network or AWS services are invoked.
"""

import http.client
import traceback

import pytest

from kuma_secure_knowledge_pipeline.genai_ollama import (
    OllamaLocalError,
    OllamaLocalProvider,
)
from kuma_secure_knowledge_pipeline.genai_provider import (
    GenAIProviderExecutionError,
    GenAIProviderIntegrityError,
    enrich_with_provider,
)
from kuma_secure_knowledge_pipeline.genai_request import (
    SYSTEM_INSTRUCTIONS,
    build_genai_request,
)
from kuma_secure_knowledge_pipeline.orchestration import AnalysisInput

CANARY = "KUMA_SYNTHETIC_PRIVATE_ERROR_CANARY"


def _request():
    return build_genai_request(
        AnalysisInput(
            artifact_id="sha256-" + "a" * 64,
            extraction_run_id="run-sanitize-001",
            source_sha256="a" * 64,
            provider="tesseract",
            operation="TesseractTSV",
            text="SYNTHETIC SECURITY EVENT",
            evidence_block_ids=("tsv-row-1",),
        )
    )


def _assert_sanitized(error: BaseException) -> None:
    assert error.__cause__ is None
    assert error.__context__ is None
    assert CANARY not in "".join(traceback.format_exception(error))


class FailingProvider:
    def generate(self, request):
        raise RuntimeError(CANARY)


class MutatingFailingProvider:
    def generate(self, request):
        object.__setattr__(request, "system_instructions", CANARY)
        raise RuntimeError(CANARY)


def test_provider_failure_does_not_expose_original_exception():
    with pytest.raises(GenAIProviderExecutionError) as caught:
        enrich_with_provider(
            _request(),
            provider=FailingProvider(),
        )

    _assert_sanitized(caught.value)


def test_mutating_provider_failure_restores_policy_and_sanitizes():
    request = _request()

    with pytest.raises(GenAIProviderIntegrityError) as caught:
        enrich_with_provider(
            request,
            provider=MutatingFailingProvider(),
        )

    assert request.system_instructions == SYSTEM_INSTRUCTIONS
    _assert_sanitized(caught.value)


def test_ollama_transport_failure_does_not_expose_original_error(
    monkeypatch: pytest.MonkeyPatch,
):
    def synthetic_connection(*args, **kwargs):
        raise OSError(CANARY)

    monkeypatch.setattr(
        http.client,
        "HTTPConnection",
        synthetic_connection,
    )

    with pytest.raises(OllamaLocalError) as caught:
        OllamaLocalProvider().generate(_request())

    _assert_sanitized(caught.value)


def test_ollama_deeply_nested_envelope_is_rejected_safely(
    monkeypatch: pytest.MonkeyPatch,
):
    depth = 4096
    payload = b"[" * depth + b"0" + b"]" * depth

    class SyntheticResponse:
        status = 200

        def read(self, count):
            return payload[:count]

    class SyntheticConnection:
        def __init__(self, *args, **kwargs):
            pass

        def request(self, *args, **kwargs):
            pass

        def getresponse(self):
            return SyntheticResponse()

        def close(self):
            pass

    monkeypatch.setattr(
        http.client,
        "HTTPConnection",
        SyntheticConnection,
    )

    with pytest.raises(OllamaLocalError) as caught:
        OllamaLocalProvider().generate(_request())

    _assert_sanitized(caught.value)
