from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class SourceArtifact:
    """Identity metadata for a source artifact."""

    artifact_id: str
    filename: str
    media_type: str
    sha256: str


@dataclass(frozen=True, slots=True)
class EvidenceReference:
    """Reference from normalized content back to provider evidence."""

    artifact_id: str
    block_id: str
    page: int
    confidence: float


@dataclass(frozen=True, slots=True)
class ExtractionResult:
    """Normalized result produced by a document extraction provider."""

    artifact_id: str
    provider: str
    operation: str
    text: str
    average_confidence: float
    evidence_refs: tuple[EvidenceReference, ...]


@dataclass(frozen=True, slots=True)
class NormalizedDocument:
    """Provider-neutral document representation used by downstream stages."""

    artifact_id: str
    content: str
    evidence_refs: tuple[EvidenceReference, ...]
