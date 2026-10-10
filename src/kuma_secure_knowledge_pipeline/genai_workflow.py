"""Deterministic local execution of the evidence-to-GenAI workflow."""

from dataclasses import dataclass
from pathlib import Path

from kuma_secure_knowledge_pipeline.genai_provider import (
    GenAIProvider,
    enrich_with_provider,
)
from kuma_secure_knowledge_pipeline.genai_request import build_genai_request
from kuma_secure_knowledge_pipeline.genai_response import StructuredEnrichment
from kuma_secure_knowledge_pipeline.orchestration import load_analysis_input


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

    try:
        context = load_analysis_input(bundle_dir)
    except Exception as exc:
        raise WorkflowExecutionError("LOAD_EVIDENCE", states) from exc

    states += ("BUILD_REQUEST",)

    try:
        request = build_genai_request(context)
    except Exception as exc:
        raise WorkflowExecutionError("BUILD_REQUEST", states) from exc

    states += ("ENRICH",)

    try:
        enrichment = enrich_with_provider(request, provider=provider)
    except Exception as exc:
        raise WorkflowExecutionError("ENRICH", states) from exc

    return WorkflowResult(
        artifact_id=context.artifact_id,
        extraction_run_id=context.extraction_run_id,
        source_sha256=context.source_sha256,
        provider=context.provider,
        operation=context.operation,
        states=(*states, "SUCCEEDED"),
        enrichment=enrichment,
    )
