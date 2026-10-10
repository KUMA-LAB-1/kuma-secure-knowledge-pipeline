"""Functional tests for the local evidence-to-GenAI workflow."""

import json
from pathlib import Path

import pytest

from kuma_secure_knowledge_pipeline.contracts import (
    EvidenceReference,
    ExtractionProvenance,
    ExtractionResult,
    SourceArtifact,
)
from kuma_secure_knowledge_pipeline.evidence import write_extraction_evidence
from kuma_secure_knowledge_pipeline.genai_workflow import (
    WorkflowExecutionError,
    run_local_workflow,
)
from kuma_secure_knowledge_pipeline.orchestration import AnalysisInputIntegrityError


def _synthetic_bundle(tmp_path: Path) -> Path:
    artifact = SourceArtifact(
        artifact_id="art-workflow-001",
        filename="synthetic.png",
        media_type="image/png",
        sha256="a" * 64,
    )
    provenance = ExtractionProvenance(
        run_id="run-workflow-001",
        provider="amazon-textract",
        operation="DetectDocumentText",
        region="us-east-1",
        started_at_utc="2026-10-09T12:00:00Z",
    )
    result = ExtractionResult(
        artifact_id=artifact.artifact_id,
        provider=provenance.provider,
        operation=provenance.operation,
        text="SYNTHETIC AUTHENTICATION EVENT",
        average_confidence=99.0,
        evidence_refs=(
            EvidenceReference(
                artifact_id=artifact.artifact_id,
                block_id="line-001",
                page=1,
                confidence=99.0,
            ),
        ),
    )
    raw_response = {
        "Blocks": [
            {
                "BlockType": "LINE",
                "Id": "line-001",
                "Page": 1,
                "Confidence": 99.0,
                "Text": result.text,
            }
        ]
    }
    return write_extraction_evidence(
        output_root=tmp_path,
        artifact=artifact,
        raw_response=raw_response,
        result=result,
        provenance=provenance,
    )


def _response_bytes() -> bytes:
    payload = {
        "facts": [
            {
                "statement": "Synthetic authentication event",
                "evidence_block_ids": ["line-001"],
            }
        ],
        "hypotheses": [],
        "missing_evidence": [],
        "recommended_checks": ["Review source evidence"],
        "incident_confirmed": False,
    }
    return json.dumps(payload).encode("utf-8")


class CountingProvider:
    def __init__(self, response: bytes):
        self.response = response
        self.calls = 0

    def generate(self, request):
        self.calls += 1
        return self.response


def test_workflow_completes_with_grounded_enrichment(tmp_path: Path) -> None:
    bundle = _synthetic_bundle(tmp_path)
    provider = CountingProvider(_response_bytes())

    execution = run_local_workflow(bundle, provider=provider)

    assert execution.states == (
        "LOAD_EVIDENCE",
        "BUILD_REQUEST",
        "ENRICH",
        "SUCCEEDED",
    )
    assert execution.artifact_id == "art-workflow-001"
    assert execution.extraction_run_id == "run-workflow-001"
    assert execution.source_sha256 == "a" * 64
    assert execution.provider == "amazon-textract"
    assert execution.operation == "DetectDocumentText"
    assert execution.enrichment.facts[0].evidence_block_ids == ("line-001",)
    assert execution.enrichment.incident_confirmed is False
    assert provider.calls == 1


def test_workflow_rejects_tampered_bundle_before_provider(tmp_path: Path) -> None:
    bundle = _synthetic_bundle(tmp_path)
    (bundle / "extracted.txt").write_text("FORGED", encoding="utf-8")
    provider = CountingProvider(_response_bytes())

    with pytest.raises(WorkflowExecutionError) as caught:
        run_local_workflow(bundle, provider=provider)

    assert caught.value.failed_state == "LOAD_EVIDENCE"
    assert caught.value.states == ("LOAD_EVIDENCE", "FAILED")
    assert isinstance(caught.value.__cause__, AnalysisInputIntegrityError)
    assert provider.calls == 0


def test_workflow_rejects_invalid_provider_output(tmp_path: Path) -> None:
    bundle = _synthetic_bundle(tmp_path)
    provider = CountingProvider(b'{"facts": INVALID')

    with pytest.raises(WorkflowExecutionError) as caught:
        run_local_workflow(bundle, provider=provider)

    assert caught.value.failed_state == "ENRICH"
    assert caught.value.states == (
        "LOAD_EVIDENCE",
        "BUILD_REQUEST",
        "ENRICH",
        "FAILED",
    )
    assert caught.value.__cause__ is not None
    assert "INVALID" not in str(caught.value)
    assert provider.calls == 1
