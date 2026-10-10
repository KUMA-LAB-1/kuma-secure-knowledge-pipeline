"""Provider-neutral structured enrichment response contract."""

from dataclasses import dataclass
from typing import Any

from kuma_secure_knowledge_pipeline.genai_request import GenAIRequest


class GenAIResponseIntegrityError(ValueError):
    """A provider response violates its required integrity contract."""


@dataclass(frozen=True, slots=True)
class EvidenceFact:
    statement: str
    evidence_block_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class StructuredEnrichment:
    facts: tuple[EvidenceFact, ...]
    hypotheses: tuple[str, ...]
    missing_evidence: tuple[str, ...]
    recommended_checks: tuple[str, ...]
    incident_confirmed: bool


MAX_RESPONSE_ITEMS = 32
MAX_FACT_CITATIONS = 32
MAX_RESPONSE_TEXT_UTF8_BYTES = 8192
MAX_FACT_STATEMENT_UTF8_BYTES = 4096
MAX_TOTAL_RESPONSE_TEXT_UTF8_BYTES = 65536


def _bounded_text(
    value: object,
    *,
    field: str,
    byte_limit: int,
) -> tuple[str, int]:
    """Validate text without modifying its original contents."""
    if type(value) is not str or not value.strip() or len(value) > byte_limit:
        raise GenAIResponseIntegrityError(f"Invalid {field}.")

    invalid_text_encoding = False

    try:
        size = len(value.encode("utf-8"))
    except UnicodeEncodeError:
        invalid_text_encoding = True

    if invalid_text_encoding:
        raise GenAIResponseIntegrityError(f"Invalid {field} encoding.")

    if size > byte_limit:
        raise GenAIResponseIntegrityError(f"Invalid {field} byte length.")

    return value, size


def validate_genai_response(
    payload: object,
    *,
    request: GenAIRequest,
) -> StructuredEnrichment:
    """Validate bounded enrichment against declared evidence references."""
    if type(request) is not GenAIRequest:
        raise GenAIResponseIntegrityError("Invalid request contract type.")

    authorized_ids = request.evidence_block_ids

    if (
        type(authorized_ids) is not tuple
        or not 1 <= len(authorized_ids) <= 1024
        or any(type(item) is not str or not item for item in authorized_ids)
        or len(set(authorized_ids)) != len(authorized_ids)
    ):
        raise GenAIResponseIntegrityError("Invalid request references.")

    if type(payload) is not dict:
        raise GenAIResponseIntegrityError("Response must be an object.")

    response: dict[str, Any] = payload

    required_fields = {
        "facts",
        "hypotheses",
        "missing_evidence",
        "recommended_checks",
        "incident_confirmed",
    }

    if set(response) != required_fields:
        raise GenAIResponseIntegrityError("Unexpected response schema.")

    confirmed = response["incident_confirmed"]

    if type(confirmed) is not bool or confirmed is not False:
        raise GenAIResponseIntegrityError("Model cannot confirm an incident.")

    for field in (
        "facts",
        "hypotheses",
        "missing_evidence",
        "recommended_checks",
    ):
        values = response[field]

        if type(values) is not list or len(values) > MAX_RESPONSE_ITEMS:
            raise GenAIResponseIntegrityError(f"Invalid {field} collection.")

    allowed = set(authorized_ids)
    total_text_bytes = 0
    facts: list[EvidenceFact] = []

    for item in response["facts"]:
        if type(item) is not dict or set(item) != {"statement", "evidence_block_ids"}:
            raise GenAIResponseIntegrityError("Invalid fact schema.")

        statement, statement_bytes = _bounded_text(
            item["statement"],
            field="fact statement",
            byte_limit=MAX_FACT_STATEMENT_UTF8_BYTES,
        )

        total_text_bytes += statement_bytes

        if total_text_bytes > MAX_TOTAL_RESPONSE_TEXT_UTF8_BYTES:
            raise GenAIResponseIntegrityError("Response text budget exceeded.")

        ids = item["evidence_block_ids"]

        if type(ids) is not list or not 1 <= len(ids) <= MAX_FACT_CITATIONS:
            raise GenAIResponseIntegrityError("Invalid fact citations.")

        seen: set[str] = set()

        for reference in ids:
            if type(reference) is not str or reference not in allowed or reference in seen:
                raise GenAIResponseIntegrityError("Invalid fact citation reference.")

            seen.add(reference)

        facts.append(
            EvidenceFact(
                statement=statement,
                evidence_block_ids=tuple(ids),
            )
        )

    strings: dict[str, tuple[str, ...]] = {}

    for field in (
        "hypotheses",
        "missing_evidence",
        "recommended_checks",
    ):
        entries: list[str] = []

        for entry in response[field]:
            value, size = _bounded_text(
                entry,
                field=field,
                byte_limit=MAX_RESPONSE_TEXT_UTF8_BYTES,
            )

            total_text_bytes += size

            if total_text_bytes > MAX_TOTAL_RESPONSE_TEXT_UTF8_BYTES:
                raise GenAIResponseIntegrityError("Response text budget exceeded.")

            entries.append(value)

        strings[field] = tuple(entries)

    return StructuredEnrichment(
        facts=tuple(facts),
        hypotheses=strings["hypotheses"],
        missing_evidence=strings["missing_evidence"],
        recommended_checks=strings["recommended_checks"],
        incident_confirmed=False,
    )
