"""Adversarial tests for Unicode exception retention at GenAI boundaries."""

import traceback
from dataclasses import replace

import pytest

from kuma_secure_knowledge_pipeline.genai_provider import (
    FakeGenAIProvider,
    GenAIProviderIntegrityError,
    enrich_with_provider,
)
from kuma_secure_knowledge_pipeline.genai_request import (
    GenAIRequestIntegrityError,
    build_genai_request,
)
from kuma_secure_knowledge_pipeline.genai_response import (
    GenAIResponseIntegrityError,
    validate_genai_response,
)
from kuma_secure_knowledge_pipeline.orchestration import AnalysisInput

CANARY = "KUMA_SYNTHETIC_UNICODE_BOUNDARY_CANARY"
INVALID_TEXT = CANARY + "\ud800"


def _context(text: str) -> AnalysisInput:
    return AnalysisInput(
        artifact_id="sha256-" + "a" * 64,
        extraction_run_id="run-unicode-sanitize-001",
        source_sha256="a" * 64,
        provider="tesseract",
        operation="TesseractTSV",
        text=text,
        evidence_block_ids=("tsv-row-1",),
    )


def _request():
    return build_genai_request(_context("SYNTHETIC VALID EVIDENCE"))


def _response(*, field: str):
    facts = []
    recommended_checks = []

    if field == "fact":
        facts = [
            {
                "statement": INVALID_TEXT,
                "evidence_block_ids": ["tsv-row-1"],
            }
        ]

    if field == "recommended_checks":
        recommended_checks = [INVALID_TEXT]

    return {
        "facts": facts,
        "hypotheses": [],
        "missing_evidence": [],
        "recommended_checks": recommended_checks,
        "incident_confirmed": False,
    }


@pytest.mark.parametrize(
    ("boundary", "expected_error"),
    [
        ("build_request", GenAIRequestIntegrityError),
        ("enrich_invalid_request", GenAIProviderIntegrityError),
        ("response_fact", GenAIResponseIntegrityError),
        ("response_recommended_checks", GenAIResponseIntegrityError),
    ],
)
def test_unicode_failure_does_not_retain_sensitive_input(
    boundary: str,
    expected_error: type[Exception],
) -> None:
    with pytest.raises(expected_error) as caught:
        if boundary == "build_request":
            build_genai_request(_context(INVALID_TEXT))

        elif boundary == "enrich_invalid_request":
            invalid_request = replace(
                _request(),
                evidence_text=INVALID_TEXT,
            )
            enrich_with_provider(
                invalid_request,
                provider=FakeGenAIProvider(b"{}"),
            )

        elif boundary == "response_fact":
            validate_genai_response(
                _response(field="fact"),
                request=_request(),
            )

        elif boundary == "response_recommended_checks":
            validate_genai_response(
                _response(field="recommended_checks"),
                request=_request(),
            )

        else:
            raise AssertionError("Unexpected test boundary.")

    error = caught.value

    assert error.__cause__ is None
    assert error.__context__ is None

    assert CANARY not in str(error)
    assert CANARY not in "".join(traceback.format_exception(error))
