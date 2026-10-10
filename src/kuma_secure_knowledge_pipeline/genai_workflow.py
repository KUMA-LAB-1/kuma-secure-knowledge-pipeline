"""Deterministic local execution of the evidence-to-GenAI workflow."""

from dataclasses import dataclass
from pathlib import Path

from kuma_secure_knowledge_pipeline.genai_provider import (
    GenAIProvider,
    enrich_with_provider,
)
from kuma_secure_knowledge_pipeline.genai_request import (
    GenAIRequestIntegrityError,
    build_genai_request,
)
from kuma_secure_knowledge_pipeline.genai_response import StructuredEnrichment
from kuma_secure_knowledge_pipeline.orchestration import (
    AnalysisInputIntegrityError,
    load_analysis_input,
)


@dataclass(frozen=True, slots=True)
class WorkflowResult:
    """Successful workflow result with a verifiable execution trace."""

    artifact_id: str
    extraction_run_id: str
    source_sha256: str
    provider: str
    operation: str
    states: tuple[str, ...]
    enrichment: StructuredEnrichment


class WorkflowExecutionError(RuntimeError):
    """Fail-closed workflow error with the state that failed."""

    def __init__(self, failed_state: str, states: tuple[str, ...]) -> None:
        super().__init__(f"Workflow failed at {failed_state}.")
        self.failed_state = failed_state
        self.states = (*states, "FAILED")


def run_local_workflow(
    bundle_dir: Path,
    *,
    provider: GenAIProvider,
) -> WorkflowResult:
    """Process an existing OCR bundle through the established contracts."""
    states = ("LOAD_EVIDENCE",)

    load_failure = None

    try:
        context = load_analysis_input(bundle_dir)
    except Exception as exc:
        if isinstance(exc, AnalysisInputIntegrityError):
            load_failure = AnalysisInputIntegrityError("Evidence validation failed.")
        else:
            load_failure = RuntimeError("Evidence loading failed.")

    if load_failure is not None:
        raise WorkflowExecutionError("LOAD_EVIDENCE", states) from load_failure

    states += ("BUILD_REQUEST",)

    build_failure = None

    try:
        request = build_genai_request(context)
    except Exception as exc:
        if isinstance(exc, GenAIRequestIntegrityError):
            build_failure = GenAIRequestIntegrityError("Request validation failed.")
        else:
            build_failure = RuntimeError("Request construction failed.")

    if build_failure is not None:
        raise WorkflowExecutionError("BUILD_REQUEST", states) from build_failure

    states += ("ENRICH",)

    enrich_failure = None

    try:
        enrichment = enrich_with_provider(request, provider=provider)
    except Exception:
        enrich_failure = RuntimeError("GenAI enrichment failed.")

    if enrich_failure is not None:
        raise WorkflowExecutionError("ENRICH", states) from enrich_failure

    return WorkflowResult(
        artifact_id=context.artifact_id,
        extraction_run_id=context.extraction_run_id,
        source_sha256=context.source_sha256,
        provider=context.provider,
        operation=context.operation,
        states=(*states, "SUCCEEDED"),
        enrichment=enrichment,
    )
