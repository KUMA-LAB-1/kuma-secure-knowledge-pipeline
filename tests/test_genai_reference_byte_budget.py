"""Exact byte and identifier boundaries for GenAI evidence references."""

from dataclasses import replace

import pytest

from kuma_secure_knowledge_pipeline.genai_request import (
    MAX_GENAI_REFERENCE_UTF8_BYTES,
    GenAIRequestIntegrityError,
    build_genai_request,
)
from kuma_secure_knowledge_pipeline.orchestration import AnalysisInput


@pytest.fixture
def context() -> AnalysisInput:
    return AnalysisInput(
        artifact_id="sha256-" + "a" * 64,
        extraction_run_id="run-exact-reference-budget",
        source_sha256="a" * 64,
        provider="tesseract",
        operation="TesseractTSV",
        text="SYNTHETIC INCIDENT EVIDENCE",
        evidence_block_ids=("tsv-row-2",),
    )


def ascii_references() -> tuple[str, ...]:
    return tuple(f"ref-{index:04d}-" + "x" * 23 for index in range(1024))


def unicode_references() -> tuple[str, ...]:
    return tuple(f"ref-{index:04d}-" + "é" * 11 + "x" for index in range(1024))


def total_bytes(references: tuple[str, ...]) -> int:
    return sum(len(reference.encode("utf-8")) for reference in references)


def test_accepts_exact_32768_ascii_bytes(
    context: AnalysisInput,
) -> None:
    references = ascii_references()

    assert MAX_GENAI_REFERENCE_UTF8_BYTES == 32768
    assert len(references) == 1024
    assert total_bytes(references) == 32768

    request = build_genai_request(replace(context, evidence_block_ids=references))

    assert request.evidence_block_ids == references


def test_rejects_32769_ascii_bytes(
    context: AnalysisInput,
) -> None:
    references = ascii_references()
    oversized = (references[0] + "x", *references[1:])

    assert len(oversized) == 1024
    assert total_bytes(oversized) == 32769

    with pytest.raises(GenAIRequestIntegrityError):
        build_genai_request(replace(context, evidence_block_ids=oversized))


def test_accepts_exact_32768_unicode_bytes(
    context: AnalysisInput,
) -> None:
    references = unicode_references()

    assert len(references) == 1024
    assert total_bytes(references) == 32768

    request = build_genai_request(replace(context, evidence_block_ids=references))

    assert request.evidence_block_ids == references


def test_rejects_32769_unicode_bytes(
    context: AnalysisInput,
) -> None:
    references = unicode_references()
    oversized = (references[0] + "x", *references[1:])

    assert total_bytes(oversized) == 32769

    with pytest.raises(GenAIRequestIntegrityError):
        build_genai_request(replace(context, evidence_block_ids=oversized))


def test_accepts_exact_256_character_reference(
    context: AnalysisInput,
) -> None:
    reference = "ref-" + "x" * 252

    assert len(reference) == 256

    request = build_genai_request(replace(context, evidence_block_ids=(reference,)))

    assert request.evidence_block_ids == (reference,)


def test_rejects_257_character_reference(
    context: AnalysisInput,
) -> None:
    reference = "ref-" + "x" * 253

    assert len(reference) == 257

    with pytest.raises(GenAIRequestIntegrityError):
        build_genai_request(replace(context, evidence_block_ids=(reference,)))
