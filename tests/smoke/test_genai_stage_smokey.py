"""Offline OCR-to-GenAI stage smoke using synthetic inputs only.

No AWS requests, live Textract, Bedrock, Ollama, or external services.
"""

import hashlib
import json
from pathlib import Path

import pytest

from kuma_secure_knowledge_pipeline.contracts import ExtractionProvenance
from kuma_secure_knowledge_pipeline.genai_provider import FakeGenAIProvider
from kuma_secure_knowledge_pipeline.runner import run_local_pipeline
from kuma_secure_knowledge_pipeline.stepfunctions_handlers import OfflineStepHandlers
from kuma_secure_knowledge_pipeline.stepfunctions_store import LocalStageStore


class SyntheticTextractClient:
    """Injected test double: never invokes the AWS SDK."""

    def __init__(self) -> None:
        self.calls = 0

    def detect_document_text(self, **kwargs):
        self.calls += 1
        assert "Document" in kwargs
        return {
            "Blocks": [
                {
                    "BlockType": "LINE",
                    "Id": "line-001",
                    "Page": 1,
                    "Confidence": 99.0,
                    "Text": "SYNTHETIC AUTHENTICATION ALERT",
                }
            ]
        }


@pytest.mark.smoke
def test_offline_genai_stage_smokey_reopens_grounded_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    execution_id = "local-smoke-genai-001"
    canary = "KUMA_GENAI_SMOKE_SECRET_CANARY"

    monkeypatch.setenv("KUMA_GENAI_SMOKE_CANARY", canary)

    source = tmp_path / "synthetic-incident.png"
    source_bytes = b"\x89PNG\r\n\x1a\nsynthetic-offline-test-fixture"
    source.write_bytes(source_bytes)

    evidence_root = tmp_path / "evidence"
    store_root = tmp_path / "private-store"

    client = SyntheticTextractClient()

    provenance = ExtractionProvenance(
        run_id="run-genai-smokey-001",
        provider="amazon-textract",
        operation="DetectDocumentText",
        region="us-east-1",
        started_at_utc="2026-10-10T10:00:00Z",
    )

    bundle = run_local_pipeline(
        source_path=source,
        output_root=evidence_root,
        client=client,
        provenance=provenance,
    )

    assert client.calls == 1

    response = {
        "facts": [
            {
                "statement": "Synthetic authentication alert requires review",
                "evidence_block_ids": ["line-001"],
            }
        ],
        "hypotheses": [],
        "missing_evidence": [],
        "recommended_checks": ["Review source authentication logs"],
        "incident_confirmed": False,
    }

    provider = FakeGenAIProvider(json.dumps(response).encode("utf-8"))

    store = LocalStageStore(
        root=store_root,
        evidence_root=evidence_root,
    )

    handlers = OfflineStepHandlers(
        store=store,
        providers={"offline-fake": provider},
    )

    bundle_ref = handlers.register_bundle(
        bundle,
        execution_id=execution_id,
    )

    loaded = handlers.load_evidence(
        {
            "bundle_ref": bundle_ref,
            "execution_id": execution_id,
        }
    )

    requested = handlers.build_request(
        {
            "context_ref": loaded["context_ref"],
            "execution_id": execution_id,
        }
    )

    enriched = handlers.enrich(
        {
            "request_ref": requested["request_ref"],
            "model_profile": "offline-fake",
            "execution_id": execution_id,
        }
    )

    persist_event = {
        "artifact_id": loaded["artifact_id"],
        "extraction_run_id": loaded["extraction_run_id"],
        "enrichment_ref": enriched["enrichment_ref"],
        "execution_id": execution_id,
    }

    result = handlers.persist_result(persist_event)

    assert set(result) == {"result_ref", "sha256"}
    assert result["result_ref"] == f"result:{result['sha256']}"

    reopened = LocalStageStore(
        root=store_root,
        evidence_root=evidence_root,
    )

    stored = reopened.get(
        result["result_ref"],
        kind="result",
        execution_id=execution_id,
    )

    assert stored["artifact_id"] == loaded["artifact_id"]
    assert stored["extraction_run_id"] == loaded["extraction_run_id"]

    assert stored["source_sha256"] == hashlib.sha256(source_bytes).hexdigest()

    assert stored["enrichment"]["facts"][0]["evidence_block_ids"] == ["line-001"]

    assert stored["enrichment"]["incident_confirmed"] is False

    assert handlers.persist_result(persist_event) == result
    assert len(list((store_root / "commits").glob("*.json"))) == 1

    stage_payloads = [loaded, requested, enriched, result]
    forwarded = json.dumps(stage_payloads)

    assert canary not in forwarded
    assert str(source) not in forwarded
    assert "SYNTHETIC AUTHENTICATION ALERT" not in forwarded
    assert canary not in json.dumps(stored)
