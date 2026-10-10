"""Security regression tests for workflow exception boundaries."""

import traceback
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

import pytest

from kuma_secure_knowledge_pipeline import genai_workflow as workflow
from kuma_secure_knowledge_pipeline.genai_request import (
    GenAIRequestIntegrityError,
)
from kuma_secure_knowledge_pipeline.orchestration import (
    AnalysisInput,
    AnalysisInputIntegrityError,
)

CANARY = "KUMA_SYNTHETIC_WORKFLOW_PRIVATE_CANARY"

CONTEXT = AnalysisInput(
    artifact_id="sha256-" + "a" * 64,
    extraction_run_id="run-workflow-sanitize-001",
    source_sha256="a" * 64,
    provider="tesseract",
    operation="TesseractTSV",
    text="SYNTHETIC EVIDENCE ONLY",
    evidence_block_ids=("tsv-row-1",),
)

STATES = {
    "LOAD_EVIDENCE": ("LOAD_EVIDENCE", "FAILED"),
    "BUILD_REQUEST": ("LOAD_EVIDENCE", "BUILD_REQUEST", "FAILED"),
    "ENRICH": (
        "LOAD_EVIDENCE",
        "BUILD_REQUEST",
        "ENRICH",
        "FAILED",
    ),
}

CAUSE_TYPES = {
    "LOAD_EVIDENCE": AnalysisInputIntegrityError,
    "BUILD_REQUEST": GenAIRequestIntegrityError,
    "ENRICH": RuntimeError,
}


@pytest.mark.parametrize(
    "stage",
    ["LOAD_EVIDENCE", "BUILD_REQUEST", "ENRICH"],
)
def test_workflow_failure_retains_safe_diagnostics_without_private_cause(stage):
    original_error = CAUSE_TYPES[stage](CANARY)

    with ExitStack() as stack:
        if stage == "LOAD_EVIDENCE":
            stack.enter_context(
                patch.object(
                    workflow,
                    "load_analysis_input",
                    side_effect=original_error,
                )
            )
        else:
            stack.enter_context(
                patch.object(
                    workflow,
                    "load_analysis_input",
                    return_value=CONTEXT,
                )
            )

        if stage == "BUILD_REQUEST":
            stack.enter_context(
                patch.object(
                    workflow,
                    "build_genai_request",
                    side_effect=original_error,
                )
            )

        if stage == "ENRICH":
            stack.enter_context(
                patch.object(
                    workflow,
                    "build_genai_request",
                    return_value=object(),
                )
            )
            stack.enter_context(
                patch.object(
                    workflow,
                    "enrich_with_provider",
                    side_effect=original_error,
                )
            )

        with pytest.raises(workflow.WorkflowExecutionError) as caught:
            workflow.run_local_workflow(
                Path("synthetic-path-not-read"),
                provider=object(),
            )

    error = caught.value

    assert error.failed_state == stage
    assert error.states == STATES[stage]

    # Preserve type-level diagnostics, never the source exception.
    assert isinstance(error.__cause__, CAUSE_TYPES[stage])
    assert error.__cause__ is not original_error

    # The original error must not remain reachable through chaining.
    assert error.__context__ is None
    assert error.__cause__.__context__ is None

    formatted = "".join(traceback.format_exception(error))

    assert CANARY not in str(error)
    assert CANARY not in formatted
