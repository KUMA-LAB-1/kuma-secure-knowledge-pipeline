"""Functional offline tests for the ASL-compatible handler and durable store."""

import hashlib
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
from kuma_secure_knowledge_pipeline.genai_provider import FakeGenAIProvider
from kuma_secure_knowledge_pipeline.stepfunctions_handlers import OfflineStepHandlers
from kuma_secure_knowledge_pipeline.stepfunctions_store import (
    LocalStageStore,
    StageStoreError,
)


def _bundle(root: Path) -> Path:
    artifact = SourceArtifact(
        artifact_id="art-stages-001",
        filename="synthetic.png",
        media_type="image/png",
        sha256="a" * 64,
    )
    provenance = ExtractionProvenance(
        run_id="run-stages-001",
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
        output_root=root,
        artifact=artifact,
        raw_response=raw_response,
        result=result,
        provenance=provenance,
    )


def _fake_output(*, reference: str = "line-001") -> bytes:
    return json.dumps(
        {
            "facts": [
                {
                    "statement": "Synthetic authentication event",
                    "evidence_block_ids": [reference],
                }
            ],
            "hypotheses": [],
            "missing_evidence": [],
            "recommended_checks": ["Review authentication logs"],
            "incident_confirmed": False,
        }
    ).encode("utf-8")


@pytest.fixture
def system(tmp_path: Path):
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    bundle = _bundle(evidence_root)
    store = LocalStageStore(root=tmp_path / "private-store", evidence_root=evidence_root)
    handlers = OfflineStepHandlers(
        store=store,
        providers={"offline-fake": FakeGenAIProvider(_fake_output())},
    )
    return handlers, store, bundle


def _through_enrich(handlers, bundle, *, execution_id="local-demo-001"):
    bundle_ref = handlers.register_bundle(bundle, execution_id=execution_id)
    loaded = handlers.load_evidence({"bundle_ref": bundle_ref, "execution_id": execution_id})
    requested = handlers.build_request(
        {"context_ref": loaded["context_ref"], "execution_id": execution_id}
    )
    enriched = handlers.enrich(
        {
            "request_ref": requested["request_ref"],
            "model_profile": "offline-fake",
            "execution_id": execution_id,
        }
    )
    return loaded, requested, enriched


def _persist(handlers, loaded, enriched, *, execution_id="local-demo-001"):
    return handlers.persist_result(
        {
            "artifact_id": loaded["artifact_id"],
            "extraction_run_id": loaded["extraction_run_id"],
            "enrichment_ref": enriched["enrichment_ref"],
            "execution_id": execution_id,
        }
    )


def test_all_four_stages_store_durable_grounded_result(system):
    handlers, store, bundle = system
    loaded, requested, enriched = _through_enrich(handlers, bundle)
    output = _persist(handlers, loaded, enriched)

    assert set(loaded) == {"context_ref", "artifact_id", "extraction_run_id"}
    assert set(requested) == {"request_ref"}
    assert set(enriched) == {"enrichment_ref"}
    assert set(output) == {"result_ref", "sha256"}
    assert output["result_ref"] == f"result:{output['sha256']}"
    stored = store.get(output["result_ref"], kind="result", execution_id="local-demo-001")
    assert stored["artifact_id"] == "art-stages-001"
    assert stored["enrichment"]["facts"][0]["evidence_block_ids"] == ["line-001"]
    assert stored["enrichment"]["incident_confirmed"] is False
    assert len(list((store.root / "commits").glob("*.json"))) == 1


def test_result_commit_is_idempotent_and_rejects_conflicting_reference(system):
    handlers, store, bundle = system
    loaded, _, enriched = _through_enrich(handlers, bundle)
    first = _persist(handlers, loaded, enriched)
    assert _persist(handlers, loaded, enriched) == first

    another = store.put(
        "result",
        {
            "artifact_id": loaded["artifact_id"],
            "extraction_run_id": loaded["extraction_run_id"],
            "test": True,
        },
        execution_id="local-demo-001",
    )
    with pytest.raises(StageStoreError, match="Conflicting"):
        store.commit_result(
            execution_id="local-demo-001",
            result_ref=another,
            artifact_id=loaded["artifact_id"],
            extraction_run_id=loaded["extraction_run_id"],
        )


def test_different_execution_cannot_read_reference(system):
    handlers, store, bundle = system
    ref = handlers.register_bundle(bundle, execution_id="local-demo-001")
    with pytest.raises(StageStoreError, match="ownership"):
        store.get(ref, kind="bundle", execution_id="local-demo-002")
    with pytest.raises(StageStoreError, match="ownership"):
        handlers.load_evidence({"bundle_ref": ref, "execution_id": "local-demo-002"})


def test_tampered_stored_data_fails_digest_gate(system):
    handlers, store, bundle = system
    ref = handlers.register_bundle(bundle, execution_id="local-demo-001")
    path = store.root / "bundle" / (ref.split(":", 1)[1] + ".json")
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(StageStoreError, match="digest"):
        handlers.load_evidence({"bundle_ref": ref, "execution_id": "local-demo-001"})


def test_modified_evidence_before_build_request_fails_closed(system):
    handlers, _, bundle = system
    ref = handlers.register_bundle(bundle, execution_id="local-demo-001")
    loaded = handlers.load_evidence({"bundle_ref": ref, "execution_id": "local-demo-001"})
    (bundle / "extracted.txt").write_text("FORGED", encoding="utf-8")
    with pytest.raises(ValueError):
        handlers.build_request(
            {"context_ref": loaded["context_ref"], "execution_id": "local-demo-001"}
        )


def test_unapproved_model_profile_does_not_invoke_provider(system):
    handlers, _, bundle = system
    ref = handlers.register_bundle(bundle, execution_id="local-demo-001")
    loaded = handlers.load_evidence({"bundle_ref": ref, "execution_id": "local-demo-001"})
    requested = handlers.build_request(
        {"context_ref": loaded["context_ref"], "execution_id": "local-demo-001"}
    )
    with pytest.raises(StageStoreError, match="Unapproved"):
        handlers.enrich(
            {
                "request_ref": requested["request_ref"],
                "model_profile": "unapproved-bedrock-profile",
                "execution_id": "local-demo-001",
            }
        )


def test_persistence_rejects_unmatched_artifact_id(system):
    handlers, _, bundle = system
    loaded, _, enriched = _through_enrich(handlers, bundle)
    with pytest.raises(StageStoreError, match="identity mismatch"):
        handlers.persist_result(
            {
                "artifact_id": "forged",
                "extraction_run_id": loaded["extraction_run_id"],
                "enrichment_ref": enriched["enrichment_ref"],
                "execution_id": "local-demo-001",
            }
        )


def test_inference_rejects_forged_citation_before_persistence(tmp_path: Path):
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    bundle = _bundle(evidence_root)
    store = LocalStageStore(root=tmp_path / "private", evidence_root=evidence_root)
    handlers = OfflineStepHandlers(
        store=store, providers={"offline-fake": FakeGenAIProvider(_fake_output(reference="fake"))}
    )
    ref = handlers.register_bundle(bundle, execution_id="local-demo-001")
    loaded = handlers.load_evidence({"bundle_ref": ref, "execution_id": "local-demo-001"})
    requested = handlers.build_request(
        {"context_ref": loaded["context_ref"], "execution_id": "local-demo-001"}
    )
    with pytest.raises(ValueError):
        handlers.enrich(
            {
                "request_ref": requested["request_ref"],
                "model_profile": "offline-fake",
                "execution_id": "local-demo-001",
            }
        )
    assert not (store.root / "commits").exists()


def test_failure_audit_contains_only_code_and_owner(system):
    handlers, store, _ = system
    ref = handlers.audit_failure(
        {"execution_id": "local-demo-001", "error_code": "States.TaskFailed"}
    )["audit_ref"]
    stored = store.get(ref, kind="audit", execution_id="local-demo-001")
    assert stored == {"error_code": "States.TaskFailed"}
    with pytest.raises(StageStoreError, match="Invalid error code"):
        handlers.audit_failure(
            {"execution_id": "local-demo-001", "error_code": "Secret\nstacktrace"}
        )


def test_ref_path_traversal_is_rejected(system):
    _, store, _ = system
    with pytest.raises(StageStoreError, match="reference"):
        store.get("bundle:../../etc/passwd", kind="bundle", execution_id="local-demo-001")
    with pytest.raises(StageStoreError, match="execution"):
        store.put("bundle", {}, execution_id="../../../escape")


def test_evidence_root_disallows_external_registration(system, tmp_path: Path):
    handlers, _, _ = system
    other = tmp_path / "outside"
    other.mkdir()
    with pytest.raises(StageStoreError, match="outside"):
        handlers.register_bundle(other, execution_id="local-demo-001")


def test_result_commit_index_key_is_execution_scoped(system):
    handlers, store, bundle = system
    loaded, _, enriched = _through_enrich(handlers, bundle)
    _persist(handlers, loaded, enriched)
    expected_index = hashlib.sha256(b"local-demo-001").hexdigest() + ".json"
    assert (store.root / "commits" / expected_index).is_file()
