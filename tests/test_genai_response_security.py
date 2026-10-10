"""Adversarial contract tests for untrusted GenAI responses."""

from copy import deepcopy

import pytest

from kuma_secure_knowledge_pipeline.genai_request import (
    GenAIRequest,
    build_genai_request,
)
from kuma_secure_knowledge_pipeline.genai_response import (
    GenAIResponseIntegrityError,
    validate_genai_response,
)
from kuma_secure_knowledge_pipeline.orchestration import AnalysisInput


@pytest.fixture
def genai_request() -> GenAIRequest:
    context = AnalysisInput(
        artifact_id="sha256-" + "a" * 64,
        extraction_run_id="run-genai-response-001",
        source_sha256="a" * 64,
        provider="tesseract",
        operation="TesseractTSV",
        text="17 FAILED LOGIN ATTEMPTS",
        evidence_block_ids=("tsv-row-2", "tsv-row-3"),
    )
    return build_genai_request(context)


@pytest.fixture
def payload() -> dict[str, object]:
    return {
        "facts": [
            {
                "statement": "17 failed login attempts observed",
                "evidence_block_ids": ["tsv-row-2"],
            }
        ],
        "hypotheses": ["Possible account abuse"],
        "missing_evidence": ["Authentication logs"],
        "recommended_checks": ["Review source IP"],
        "incident_confirmed": False,
    }


def test_valid_response_preserves_fact_citations(
    genai_request: GenAIRequest,
    payload: dict[str, object],
) -> None:
    response = validate_genai_response(
        payload,
        request=genai_request,
    )

    assert len(response.facts) == 1
    assert response.facts[0].evidence_block_ids == ("tsv-row-2",)
    assert response.hypotheses == ("Possible account abuse",)
    assert response.incident_confirmed is False


def test_valid_response_is_deterministic_and_non_mutating(
    genai_request: GenAIRequest,
    payload: dict[str, object],
) -> None:
    original = deepcopy(payload)

    first = validate_genai_response(
        payload,
        request=genai_request,
    )
    second = validate_genai_response(
        payload,
        request=genai_request,
    )

    assert first == second
    assert payload == original


def test_rejects_unknown_fact_reference(
    genai_request: GenAIRequest,
    payload: dict[str, object],
) -> None:
    modified = deepcopy(payload)
    modified["facts"][0]["evidence_block_ids"] = ["tsv-row-999"]

    with pytest.raises(GenAIResponseIntegrityError):
        validate_genai_response(modified, request=genai_request)


def test_rejects_fact_without_citations(
    genai_request: GenAIRequest,
    payload: dict[str, object],
) -> None:
    modified = deepcopy(payload)
    modified["facts"][0]["evidence_block_ids"] = []

    with pytest.raises(GenAIResponseIntegrityError):
        validate_genai_response(modified, request=genai_request)


def test_rejects_duplicate_fact_citations(
    genai_request: GenAIRequest,
    payload: dict[str, object],
) -> None:
    modified = deepcopy(payload)
    modified["facts"][0]["evidence_block_ids"] = [
        "tsv-row-2",
        "tsv-row-2",
    ]

    with pytest.raises(GenAIResponseIntegrityError):
        validate_genai_response(modified, request=genai_request)


def test_rejects_model_confirmed_incident(
    genai_request: GenAIRequest,
    payload: dict[str, object],
) -> None:
    modified = deepcopy(payload)
    modified["incident_confirmed"] = True

    with pytest.raises(GenAIResponseIntegrityError):
        validate_genai_response(modified, request=genai_request)


def test_rejects_string_instead_of_boolean(
    genai_request: GenAIRequest,
    payload: dict[str, object],
) -> None:
    modified = deepcopy(payload)
    modified["incident_confirmed"] = "false"

    with pytest.raises(GenAIResponseIntegrityError):
        validate_genai_response(modified, request=genai_request)


def test_rejects_unexpected_top_level_fields(
    genai_request: GenAIRequest,
    payload: dict[str, object],
) -> None:
    modified = deepcopy(payload)
    modified["system_override"] = "synthetic canary"

    with pytest.raises(GenAIResponseIntegrityError):
        validate_genai_response(modified, request=genai_request)


def test_rejects_unexpected_fact_fields(
    genai_request: GenAIRequest,
    payload: dict[str, object],
) -> None:
    modified = deepcopy(payload)
    modified["facts"][0]["authority"] = "system"

    with pytest.raises(GenAIResponseIntegrityError):
        validate_genai_response(modified, request=genai_request)


def test_rejects_empty_fact_statement(
    genai_request: GenAIRequest,
    payload: dict[str, object],
) -> None:
    modified = deepcopy(payload)
    modified["facts"][0]["statement"] = "   "

    with pytest.raises(GenAIResponseIntegrityError):
        validate_genai_response(modified, request=genai_request)


def test_rejects_excessively_long_hypothesis(
    genai_request: GenAIRequest,
    payload: dict[str, object],
) -> None:
    modified = deepcopy(payload)
    modified["hypotheses"] = ["X" * 8193]

    with pytest.raises(GenAIResponseIntegrityError):
        validate_genai_response(modified, request=genai_request)


def test_rejects_forged_request_object(
    payload: dict[str, object],
) -> None:
    with pytest.raises(GenAIResponseIntegrityError):
        validate_genai_response(payload, request=object())
