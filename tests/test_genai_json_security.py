"""Adversarial tests for the untrusted GenAI JSON decoding boundary."""

import json

import pytest

from kuma_secure_knowledge_pipeline.genai_json import decode_genai_json
from kuma_secure_knowledge_pipeline.genai_request import build_genai_request
from kuma_secure_knowledge_pipeline.genai_response import (
    GenAIResponseIntegrityError,
    validate_genai_response,
)
from kuma_secure_knowledge_pipeline.orchestration import AnalysisInput


def valid_payload() -> dict[str, object]:
    return {
        "facts": [
            {
                "statement": "A synthetic event was observed",
                "evidence_block_ids": ["tsv-row-2"],
            }
        ],
        "hypotheses": [],
        "missing_evidence": [],
        "recommended_checks": [],
        "incident_confirmed": False,
    }


def test_valid_json_integrates_with_structured_validator() -> None:
    context = AnalysisInput(
        artifact_id="sha256-" + "a" * 64,
        extraction_run_id="run-json-ingress-001",
        source_sha256="a" * 64,
        provider="tesseract",
        operation="TesseractTSV",
        text="SYNTHETIC EVENT",
        evidence_block_ids=("tsv-row-2",),
    )

    request = build_genai_request(context)
    raw = json.dumps(valid_payload()).encode("utf-8")

    parsed = decode_genai_json(raw)
    result = validate_genai_response(parsed, request=request)

    assert result.facts[0].evidence_block_ids == ("tsv-row-2",)
    assert result.incident_confirmed is False


def test_valid_unicode_is_preserved() -> None:
    raw = '{"note": "ação de verificação"}'.encode()

    assert decode_genai_json(raw) == {"note": "ação de verificação"}


def test_valid_json_whitespace_is_accepted() -> None:
    assert decode_genai_json(b'  {"ok": true} \r\n') == {"ok": True}


def test_rejects_non_bytes_input() -> None:
    with pytest.raises(GenAIResponseIntegrityError):
        decode_genai_json(bytearray(b'{"ok": true}'))


def test_rejects_duplicate_top_level_keys() -> None:
    raw = b'{"facts":[],"facts":[],"incident_confirmed":false}'

    with pytest.raises(GenAIResponseIntegrityError):
        decode_genai_json(raw)


def test_rejects_duplicate_nested_keys() -> None:
    raw = b'{"facts":[{"statement":"first","statement":"overridden"}]}'

    with pytest.raises(GenAIResponseIntegrityError):
        decode_genai_json(raw)


@pytest.mark.parametrize(
    "token",
    [
        pytest.param(b"NaN", id="nan"),
        pytest.param(b"Infinity", id="positive-infinity"),
        pytest.param(b"-Infinity", id="negative-infinity"),
    ],
)
def test_rejects_nonfinite_json_constants(token: bytes) -> None:
    raw = b'{"value":' + token + b"}"

    with pytest.raises(GenAIResponseIntegrityError):
        decode_genai_json(raw)


def test_rejects_numeric_exponent_overflow() -> None:
    with pytest.raises(GenAIResponseIntegrityError):
        decode_genai_json(b'{"value":1e309}')


def test_rejects_utf8_bom() -> None:
    raw = b'\xef\xbb\xbf{"ok":true}'

    with pytest.raises(GenAIResponseIntegrityError):
        decode_genai_json(raw)


def test_rejects_oversized_raw_json() -> None:
    raw = b'{"padding":"' + b"x" * (256 * 1024) + b'"}'

    assert len(raw) > 256 * 1024

    with pytest.raises(GenAIResponseIntegrityError):
        decode_genai_json(raw)


def test_rejects_excessive_json_nesting() -> None:
    raw = b"[" * 33 + b"0" + b"]" * 33

    with pytest.raises(GenAIResponseIntegrityError):
        decode_genai_json(raw)


def test_rejects_non_object_json_root() -> None:
    with pytest.raises(GenAIResponseIntegrityError):
        decode_genai_json(b"[]")


def test_invalid_utf8_raises_contract_error() -> None:
    with pytest.raises(GenAIResponseIntegrityError):
        decode_genai_json(b"\xff")


def test_malformed_json_raises_contract_error() -> None:
    with pytest.raises(GenAIResponseIntegrityError):
        decode_genai_json(b'{"facts":')
