"""Adversarial JSON resource and Unicode boundary tests."""

import json

import pytest

from kuma_secure_knowledge_pipeline.genai_json import (
    MAX_GENAI_JSON_DEPTH,
    MAX_GENAI_JSON_UTF8_BYTES,
    decode_genai_json,
)
from kuma_secure_knowledge_pipeline.genai_response import (
    GenAIResponseIntegrityError,
)


def test_accepts_exact_json_byte_limit() -> None:
    prefix = b'{"note":"'
    suffix = b'"}'
    padding = MAX_GENAI_JSON_UTF8_BYTES - len(prefix) - len(suffix)
    raw = prefix + b"x" * padding + suffix

    assert len(raw) == 256 * 1024
    assert len(decode_genai_json(raw)["note"]) == padding


def test_rejects_one_byte_above_json_limit() -> None:
    prefix = b'{"note":"'
    suffix = b'"}'
    padding = MAX_GENAI_JSON_UTF8_BYTES - len(prefix) - len(suffix)
    raw = prefix + b"x" * (padding + 1) + suffix

    assert len(raw) == MAX_GENAI_JSON_UTF8_BYTES + 1

    with pytest.raises(GenAIResponseIntegrityError):
        decode_genai_json(raw)


def test_accepts_exact_json_depth_limit() -> None:
    raw = (
        b'{"note":'
        + b"[" * (MAX_GENAI_JSON_DEPTH - 1)
        + b"0"
        + b"]" * (MAX_GENAI_JSON_DEPTH - 1)
        + b"}"
    )

    assert MAX_GENAI_JSON_DEPTH == 32
    assert isinstance(decode_genai_json(raw)["note"], list)


def test_rejects_one_level_above_depth_limit() -> None:
    raw = b'{"note":' + b"[" * MAX_GENAI_JSON_DEPTH + b"0" + b"]" * MAX_GENAI_JSON_DEPTH + b"}"

    with pytest.raises(GenAIResponseIntegrityError):
        decode_genai_json(raw)


def test_rejects_duplicate_key_using_unicode_escape() -> None:
    raw = b'{"key":1,"\\u006bey":2}'

    with pytest.raises(GenAIResponseIntegrityError):
        decode_genai_json(raw)


def test_accepts_valid_surrogate_pair() -> None:
    raw = b'{"symbol":"\\ud83d\\ude80"}'

    assert decode_genai_json(raw)["symbol"] == "🚀"


def test_quoted_brackets_and_escaped_quotes_are_data() -> None:
    note = '"]} { [ escaped \\" quote"'
    raw = json.dumps({"note": note}).encode()

    assert decode_genai_json(raw)["note"] == note


def test_accepts_128_digit_integer() -> None:
    digits = b"9" * 128
    raw = b'{"value":' + digits + b"}"

    assert len(str(decode_genai_json(raw)["value"])) == 128


def test_rejects_129_digit_integer() -> None:
    digits = b"9" * 129
    raw = b'{"value":' + digits + b"}"

    with pytest.raises(GenAIResponseIntegrityError):
        decode_genai_json(raw)


def test_accepts_finite_scientific_number() -> None:
    result = decode_genai_json(b'{"value":1.25e2}')

    assert result["value"] == 125.0


def test_rejects_nonzero_float_underflow() -> None:
    raw = b'{"value":1e-4000}'

    with pytest.raises(GenAIResponseIntegrityError):
        decode_genai_json(raw)


@pytest.mark.parametrize(
    "raw",
    [
        pytest.param(
            b'{"value":"\\ud800"}',
            id="unpaired-surrogate-in-value",
        ),
        pytest.param(
            b'{"\\ud800":1}',
            id="unpaired-surrogate-in-key",
        ),
    ],
)
def test_rejects_unpaired_unicode_surrogate(raw: bytes) -> None:
    with pytest.raises(GenAIResponseIntegrityError):
        decode_genai_json(raw)
