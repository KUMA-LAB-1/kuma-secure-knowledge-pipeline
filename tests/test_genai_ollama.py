"""Contract tests for the local-only Ollama provider."""

import http.client
import json

import pytest

from kuma_secure_knowledge_pipeline.genai_ollama import (
    OllamaLocalError,
    OllamaLocalProvider,
)
from kuma_secure_knowledge_pipeline.genai_provider import enrich_with_provider
from kuma_secure_knowledge_pipeline.genai_request import build_genai_request
from kuma_secure_knowledge_pipeline.genai_response import GenAIResponseIntegrityError
from kuma_secure_knowledge_pipeline.orchestration import AnalysisInput


def _request():
    context = AnalysisInput(
        artifact_id="sha256-" + "a" * 64,
        extraction_run_id="run-ollama-001",
        source_sha256="a" * 64,
        provider="tesseract",
        operation="TesseractTSV",
        text="SYNTHETIC AUTHENTICATION EVENT",
        evidence_block_ids=("tsv-row-2",),
    )
    return build_genai_request(context)


def _envelope(reference="tsv-row-2", model="qwen3:4b-instruct"):
    content = {
        "facts": [
            {
                "statement": "Synthetic authentication event",
                "evidence_block_ids": [reference],
            }
        ],
        "hypotheses": [],
        "missing_evidence": [],
        "recommended_checks": [],
        "incident_confirmed": False,
    }
    return json.dumps(
        {
            "model": model,
            "done": True,
            "done_reason": "stop",
            "message": {
                "role": "assistant",
                "content": json.dumps(content),
            },
        }
    ).encode("utf-8")


def _serve(monkeypatch, payload):
    observed = {}

    class Response:
        status = 200

        def read(self, count):
            return payload[:count]

    class Connection:
        def __init__(self, host, port, *, timeout):
            observed.update(host=host, port=port, timeout=timeout)

        def request(self, method, path, body, headers):
            observed.update(method=method, path=path, body=body, headers=headers)

        def getresponse(self):
            return Response()

        def close(self):
            observed["closed"] = True

    monkeypatch.setattr(http.client, "HTTPConnection", Connection)
    return observed


def test_adapter_integrates_with_enrichment_contract(monkeypatch):
    observed = _serve(monkeypatch, _envelope())
    request = _request()

    result = enrich_with_provider(
        request,
        provider=OllamaLocalProvider(),
    )

    assert result.facts[0].evidence_block_ids == ("tsv-row-2",)
    assert result.incident_confirmed is False

    assert observed["host"] == "127.0.0.1"
    assert observed["port"] == 11434
    assert observed["path"] == "/api/chat"
    assert observed["method"] == "POST"
    assert observed["closed"] is True

    body = json.loads(observed["body"])
    assert body["model"] == "qwen3:4b-instruct"
    assert body["stream"] is False
    assert body["format"]["type"] == "object"
    assert body["messages"][0]["role"] == "system"
    assert "SYNTHETIC AUTHENTICATION EVENT" in body["messages"][1]["content"]


def test_adapter_cannot_authorize_forged_reference(monkeypatch):
    _serve(monkeypatch, _envelope(reference="forged-reference"))

    with pytest.raises(GenAIResponseIntegrityError):
        enrich_with_provider(
            _request(),
            provider=OllamaLocalProvider(),
        )


def test_adapter_rejects_oversized_transport(monkeypatch):
    _serve(monkeypatch, b"x" * 1_048_577)

    with pytest.raises(OllamaLocalError):
        OllamaLocalProvider().generate(_request())


def test_adapter_rejects_model_mismatch(monkeypatch):
    _serve(monkeypatch, _envelope(model="gemma3:4b"))

    with pytest.raises(OllamaLocalError):
        OllamaLocalProvider().generate(_request())


def test_adapter_rejects_invalid_configuration():
    with pytest.raises(ValueError):
        OllamaLocalProvider(model="unapproved-model")

    with pytest.raises(ValueError):
        OllamaLocalProvider(timeout_seconds=True)


def test_adapter_handles_unavailable_local_service(monkeypatch):
    def unavailable(host, port, *, timeout):
        raise ConnectionRefusedError("Synthetic local connection failure")

    monkeypatch.setattr(http.client, "HTTPConnection", unavailable)

    with pytest.raises(OllamaLocalError, match="Local inference failed"):
        OllamaLocalProvider().generate(_request())
