"""Regression tests for sensitive JSON exception object retention."""

import traceback

import pytest

from kuma_secure_knowledge_pipeline.genai_json import decode_genai_json
from kuma_secure_knowledge_pipeline.genai_provider import (
    FakeGenAIProvider,
    enrich_with_provider,
)
from kuma_secure_knowledge_pipeline.genai_request import build_genai_request
from kuma_secure_knowledge_pipeline.genai_response import (
    GenAIResponseIntegrityError,
)
from kuma_secure_knowledge_pipeline.orchestration import AnalysisInput

CANARY = "KUMA_SYNTHETIC_JSON_OBJECT_CANARY"
MARKER = CANARY.encode("ascii")


def _request():
    return build_genai_request(
        AnalysisInput(
            artifact_id="sha256-" + "a" * 64,
            extraction_run_id="run-json-sanitize-001",
            source_sha256="a" * 64,
            provider="tesseract",
            operation="TesseractTSV",
            text="SYNTHETIC EVIDENCE ONLY",
            evidence_block_ids=("tsv-row-1",),
        )
    )


def _payload(case: str) -> bytes:
    payloads = {
        "malformed-json": b'{"facts":' + MARKER + b"}",
        "invalid-utf8": b'{"note":"' + MARKER + b'\xff"}',
        "unpaired-surrogate": b'{"note":"' + MARKER + b'\\ud800"}',
    }

    return payloads[case]


@pytest.mark.parametrize(
    "case",
    ["malformed-json", "invalid-utf8", "unpaired-surrogate"],
)
@pytest.mark.parametrize("entrypoint", ["decoder", "provider"])
def test_untrusted_json_failure_does_not_retain_original_payload(
    case: str,
    entrypoint: str,
) -> None:
    raw = _payload(case)

    with pytest.raises(GenAIResponseIntegrityError) as caught:
        if entrypoint == "decoder":
            decode_genai_json(raw)
        else:
            enrich_with_provider(
                _request(),
                provider=FakeGenAIProvider(raw),
            )

    error = caught.value

    # No original parser exception should be retained.
    assert error.__cause__ is None
    assert error.__context__ is None

    # The outward-facing diagnostics must remain sanitized.
    assert CANARY not in str(error)
    assert CANARY not in "".join(traceback.format_exception(error))
