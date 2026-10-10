"""Offline handlers matching C02 ASL Lambda payloads; no AWS services used.

Each handler accepts the exact payload shape in kuma_pipeline.asl.json. The
LocalStageStore is injected by the trusted runtime, not read from the event.
This is local integration code, not deployed Lambda infrastructure.
"""

from dataclasses import asdict
from pathlib import Path
from typing import Any

from kuma_secure_knowledge_pipeline.genai_provider import GenAIProvider, enrich_with_provider
from kuma_secure_knowledge_pipeline.genai_request import (
    GenAIRequest,
    build_genai_request,
    validate_genai_request,
)
from kuma_secure_knowledge_pipeline.genai_response import validate_genai_response
from kuma_secure_knowledge_pipeline.orchestration import AnalysisInput, load_analysis_input
from kuma_secure_knowledge_pipeline.stepfunctions_store import (
    LocalStageStore,
    StageStoreError,
    _canonical,
    validate_error_code,
    validate_execution_id,
)


def _event(payload: object, expected: set[str]) -> dict[str, Any]:
    if type(payload) is not dict or set(payload) != expected:
        raise StageStoreError("Invalid stage event schema.")
    return payload


def _text(value: object) -> str:
    if type(value) is not str or not value or len(value) > 256:
        raise StageStoreError("Invalid stage identity.")
    return value


class OfflineStepHandlers:
    """One handler object can simulate AWS task boundaries using durable refs."""

    def __init__(self, *, store: LocalStageStore, providers: dict[str, GenAIProvider]) -> None:
        if not providers or any(
            type(name) is not str or not name or not hasattr(provider, "generate")
            for name, provider in providers.items()
        ):
            raise StageStoreError("Invalid provider registry.")
        self.store = store
        self.providers = dict(providers)

    def register_bundle(self, path: Path, *, execution_id: str) -> str:
        """Only trusted application code registers a filesystem bundle."""
        execution_id = validate_execution_id(execution_id)
        path = self.store.check_bundle_path(path)
        load_analysis_input(path)
        return self.store.put("bundle", {"path": str(path)}, execution_id=execution_id)

    def _load_registered(self, bundle_ref: str, execution_id: str) -> AnalysisInput:
        data = self.store.get(bundle_ref, kind="bundle", execution_id=execution_id)
        if set(data) != {"path"} or type(data["path"]) is not str:
            raise StageStoreError("Invalid bundle registry record.")
        path = self.store.check_bundle_path(Path(data["path"]))
        return load_analysis_input(path)

    def _verified_context(self, context_ref: str, execution_id: str) -> AnalysisInput:
        data = self.store.get(context_ref, kind="context", execution_id=execution_id)
        if set(data) != {"bundle_ref", "analysis"} or type(data["analysis"]) is not dict:
            raise StageStoreError("Invalid context record.")
        context = self._load_registered(data["bundle_ref"], execution_id)
        if _canonical(asdict(context)) != _canonical(data["analysis"]):
            raise StageStoreError("Context differs from source evidence.")
        return context

    def _verified_request(self, request_ref: str, execution_id: str) -> GenAIRequest:
        data = self.store.get(request_ref, kind="request", execution_id=execution_id)
        if set(data) != {"context_ref", "request"} or type(data["request"]) is not dict:
            raise StageStoreError("Invalid request record.")
        expected = build_genai_request(self._verified_context(data["context_ref"], execution_id))
        if _canonical(asdict(expected)) != _canonical(data["request"]):
            raise StageStoreError("Request differs from trusted evidence context.")
        validate_genai_request(expected)
        return expected

    def load_evidence(self, event: object) -> dict[str, str]:
        payload = _event(event, {"bundle_ref", "execution_id"})
        execution_id = validate_execution_id(payload["execution_id"])
        context = self._load_registered(payload["bundle_ref"], execution_id)
        context_ref = self.store.put(
            "context",
            {"bundle_ref": payload["bundle_ref"], "analysis": asdict(context)},
            execution_id=execution_id,
        )
        return {
            "context_ref": context_ref,
            "artifact_id": context.artifact_id,
            "extraction_run_id": context.extraction_run_id,
        }

    def build_request(self, event: object) -> dict[str, str]:
        payload = _event(event, {"context_ref", "execution_id"})
        execution_id = validate_execution_id(payload["execution_id"])
        context = self._verified_context(payload["context_ref"], execution_id)
        request = build_genai_request(context)
        validate_genai_request(request)
        request_ref = self.store.put(
            "request",
            {"context_ref": payload["context_ref"], "request": asdict(request)},
            execution_id=execution_id,
        )
        return {"request_ref": request_ref}

    def enrich(self, event: object) -> dict[str, str]:
        payload = _event(event, {"request_ref", "model_profile", "execution_id"})
        execution_id = validate_execution_id(payload["execution_id"])
        model_profile = _text(payload["model_profile"])
        if model_profile not in self.providers:
            raise StageStoreError("Unapproved model profile.")
        request = self._verified_request(payload["request_ref"], execution_id)
        enrichment = enrich_with_provider(request, provider=self.providers[model_profile])
        enrichment_ref = self.store.put(
            "enrichment",
            {"request_ref": payload["request_ref"], "enrichment": asdict(enrichment)},
            execution_id=execution_id,
        )
        return {"enrichment_ref": enrichment_ref}

    def persist_result(self, event: object) -> dict[str, str]:
        payload = _event(
            event,
            {"artifact_id", "extraction_run_id", "enrichment_ref", "execution_id"},
        )
        execution_id = validate_execution_id(payload["execution_id"])
        enrichment_record = self.store.get(
            payload["enrichment_ref"], kind="enrichment", execution_id=execution_id
        )
        if (
            set(enrichment_record) != {"request_ref", "enrichment"}
            or type(enrichment_record["enrichment"]) is not dict
        ):
            raise StageStoreError("Invalid enrichment record.")
        request = self._verified_request(enrichment_record["request_ref"], execution_id)
        if (
            payload["artifact_id"] != request.artifact_id
            or payload["extraction_run_id"] != request.extraction_run_id
        ):
            raise StageStoreError("Enrichment result identity mismatch.")
        validated = validate_genai_response(enrichment_record["enrichment"], request=request)
        result_ref = self.store.put(
            "result",
            {
                "artifact_id": request.artifact_id,
                "extraction_run_id": request.extraction_run_id,
                "source_sha256": request.source_sha256,
                "request_ref": enrichment_record["request_ref"],
                "enrichment_ref": payload["enrichment_ref"],
                "enrichment": asdict(validated),
            },
            execution_id=execution_id,
        )
        self.store.commit_result(
            execution_id=execution_id,
            result_ref=result_ref,
            artifact_id=request.artifact_id,
            extraction_run_id=request.extraction_run_id,
        )
        return {"result_ref": result_ref, "sha256": result_ref.split(":", 1)[1]}

    def audit_failure(self, event: object) -> dict[str, str]:
        payload = _event(event, {"execution_id", "error_code"})
        execution_id = validate_execution_id(payload["execution_id"])
        error_code = validate_error_code(payload["error_code"])
        audit_ref = self.store.put("audit", {"error_code": error_code}, execution_id=execution_id)
        return {"audit_ref": audit_ref}
