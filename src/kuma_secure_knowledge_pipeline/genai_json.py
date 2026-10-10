"""JSON ingress boundary for untrusted GenAI provider responses."""

import json
import math
from typing import Any

from kuma_secure_knowledge_pipeline.genai_response import (
    GenAIResponseIntegrityError,
)

MAX_GENAI_JSON_UTF8_BYTES = 256 * 1024
MAX_GENAI_JSON_DEPTH = 32
MAX_GENAI_JSON_INTEGER_DIGITS = 128


def _reject_duplicate_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    """Reject duplicate keys at any JSON object nesting level."""
    result: dict[str, Any] = {}

    for key, value in pairs:
        if key in result:
            raise GenAIResponseIntegrityError("Duplicate JSON object key.")

        result[key] = value

    return result


def _reject_nonfinite_constant(value: str) -> None:
    """Reject non-standard JSON numeric constants."""
    raise GenAIResponseIntegrityError("Non-finite JSON number.")


def _parse_bounded_int(value: str) -> int:
    """Enforce integer resource limits before conversion."""
    digits = value[1:] if value.startswith("-") else value

    if len(digits) > MAX_GENAI_JSON_INTEGER_DIGITS:
        raise GenAIResponseIntegrityError("JSON integer digit limit exceeded.")

    return int(value)


def _parse_finite_float(value: str) -> float:
    """Reject numeric conversions producing NaN or infinity."""
    number = float(value)

    if not math.isfinite(number):
        raise GenAIResponseIntegrityError("Non-finite JSON number.")

    significand = value.lower().split("e", 1)[0]

    if number == 0.0 and any(char in "123456789" for char in significand):
        raise GenAIResponseIntegrityError("Nonzero JSON number underflowed to zero.")

    return number


def _check_json_depth(text: str) -> None:
    """Count JSON containers while ignoring quoted string content."""
    depth = 0
    quoted = False
    escaped = False

    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False

        elif char == '"':
            quoted = True

        elif char in "[{":
            depth += 1

            if depth > MAX_GENAI_JSON_DEPTH:
                raise GenAIResponseIntegrityError("JSON depth limit exceeded.")

        elif char in "]}":
            depth -= 1

            if depth < 0:
                raise GenAIResponseIntegrityError("Malformed JSON structure.")


def _validate_unicode_scalars(value: Any) -> None:
    """Reject unpaired Unicode surrogates in all JSON strings."""
    if type(value) is str:
        try:
            value.encode()
        except UnicodeEncodeError as exc:
            raise GenAIResponseIntegrityError("Invalid Unicode scalar in provider JSON.") from exc

    elif type(value) is dict:
        for key, item in value.items():
            _validate_unicode_scalars(key)
            _validate_unicode_scalars(item)

    elif type(value) is list:
        for item in value:
            _validate_unicode_scalars(item)


def decode_genai_json(raw: bytes) -> dict[str, Any]:
    """Decode a bounded, strict UTF-8 JSON object."""
    if type(raw) is not bytes:
        raise GenAIResponseIntegrityError("Provider response must contain bytes.")

    if len(raw) > MAX_GENAI_JSON_UTF8_BYTES:
        raise GenAIResponseIntegrityError("Provider JSON exceeds byte budget.")

    if raw.startswith(b"\xef\xbb\xbf"):
        raise GenAIResponseIntegrityError("UTF-8 BOM is not allowed.")

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise GenAIResponseIntegrityError("Invalid UTF-8 JSON.") from exc

    _check_json_depth(text)

    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite_constant,
            parse_float=_parse_finite_float,
            parse_int=_parse_bounded_int,
        )
    except GenAIResponseIntegrityError:
        raise
    except (
        json.JSONDecodeError,
        ValueError,
        OverflowError,
        RecursionError,
    ) as exc:
        raise GenAIResponseIntegrityError("Invalid provider JSON.") from exc

    if type(value) is not dict:
        raise GenAIResponseIntegrityError("JSON root must be an object.")

    _validate_unicode_scalars(value)

    return value
