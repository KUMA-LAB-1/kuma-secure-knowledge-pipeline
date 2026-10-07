import hashlib
import mimetypes
from pathlib import Path

from kuma_secure_knowledge_pipeline.contracts import SourceArtifact


class InvalidArtifactError(ValueError):
    """Raised when a source artifact violates ingestion requirements."""


class ArtifactIntegrityError(ValueError):
    """Raised when source bytes no longer match their registered SHA-256."""


def sha256_bytes(
    content: bytes,
) -> str:
    return hashlib.sha256(content).hexdigest()


def sha256_file(
    source_path: Path,
) -> str:
    if not source_path.is_file():
        raise InvalidArtifactError("Source artifact does not exist or is not a file.")

    digest = hashlib.sha256()

    with source_path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)

    return digest.hexdigest()


def build_source_artifact(
    source_path: Path,
) -> SourceArtifact:
    if not source_path.is_file():
        raise InvalidArtifactError("Source artifact does not exist or is not a file.")

    if source_path.stat().st_size == 0:
        raise InvalidArtifactError("Source artifact is empty.")

    digest = sha256_file(source_path)

    media_type = mimetypes.guess_type(source_path.name)[0] or "application/octet-stream"

    return SourceArtifact(
        artifact_id=f"sha256-{digest}",
        filename=source_path.name,
        media_type=media_type,
        sha256=digest,
    )


def verify_artifact_bytes(
    content: bytes,
    artifact: SourceArtifact,
) -> None:
    current_sha256 = sha256_bytes(content)

    if current_sha256 != artifact.sha256:
        raise ArtifactIntegrityError("Source artifact SHA-256 does not match registered evidence.")


def verify_artifact_integrity(
    source_path: Path,
    artifact: SourceArtifact,
) -> None:
    current_sha256 = sha256_file(source_path)

    if current_sha256 != artifact.sha256:
        raise ArtifactIntegrityError("Source artifact SHA-256 does not match registered evidence.")
