"""Provider-neutral GenAI boundary with an offline fake implementation."""

from dataclasses import dataclass, fields, replace
from typing import Protocol

from kuma_secure_knowledge_pipeline.genai_json import decode_genai_json
from kuma_secure_knowledge_pipeline.genai_request import (
    GenAIRequest,
    GenAIRequestIntegrityError,
    validate_genai_request,
)
from kuma_secure_knowledge_pipeline.genai_response import (
    StructuredEnrichment,
    validate_genai_response,
)


class GenAIProviderIntegrityError(ValueError):
    """Invalid request, adapter, or provider output contract."""


class GenAIProviderExecutionError(RuntimeError):
    """A trusted adapter failed while generating a response."""


def _validated_provider_request(request: object) -> GenAIRequest:
    """Enforce request invariants before any provider dispatch."""
    try:
        return validate_genai_request(request)
    except GenAIRequestIntegrityError as exc:
        raise GenAIProviderIntegrityError("Invalid GenAI request.") from exc


def _restore_mutated_request(
    request: GenAIRequest,
    trusted_request: GenAIRequest,
) -> bool:
    """Restore a request changed by a provider before rejecting it."""
    if request == trusted_request:
        return False

    for item in fields(GenAIRequest):
        object.__setattr__(
            request,
            item.name,
            getattr(trusted_request, item.name),
        )

    return True


class GenAIProvider(Protocol):
    """Minimal provider interface, independent of any SDK."""

    def generate(self, request: GenAIRequest) -> bytes:
        """Return provider-generated response bytes."""


@dataclass(frozen=True, slots=True)
class FakeGenAIProvider:
    """Return a predetermined response without network access."""

    response_bytes: bytes

    def __post_init__(self) -> None:
        """Reject invalid scripted output before the fake is used."""
        if type(self.response_bytes) is not bytes:
            raise GenAIProviderIntegrityError("Fake response must be bytes.")

    def generate(self, request: GenAIRequest) -> bytes:
        """Return offline bytes only for a valid request."""
        _validated_provider_request(request)

        return self.response_bytes


def enrich_with_provider(
    request: GenAIRequest,
    *,
    provider: GenAIProvider,
) -> StructuredEnrichment:
    """Enforce request, adapter, and output contracts before parsing."""
    _validated_provider_request(request)
    trusted_request = replace(request)

    generate = getattr(provider, "generate", None)

    if not callable(generate):
        raise GenAIProviderIntegrityError("Provider must implement a callable generate method.")

    try:
        raw = generate(request)
    except Exception as exc:
        if _restore_mutated_request(request, trusted_request):
            raise GenAIProviderIntegrityError("Provider mutated request contract.") from exc
        raise GenAIProviderExecutionError("Provider generation failed.") from exc

    if _restore_mutated_request(request, trusted_request):
        raise GenAIProviderIntegrityError("Provider mutated request contract.")

    if type(raw) is not bytes:
        raise GenAIProviderIntegrityError("Provider output must be bytes.")

    decoded = decode_genai_json(raw)

    return validate_genai_response(decoded, request=trusted_request)
