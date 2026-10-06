import hashlib
import mimetypes
from pathlib import Path

from kuma_secure_knowledge_pipeline.contracts import SourceArtifact


class ArtifactIntegrityError(ValueError):
    """Raised when source bytes no longer match their registered SHA-256."""


def sha256_file(source_path: Path) -> str:
    digest = hashlib.sha256()

    with source_path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)

    return digest.hexdigest()


def build_source_artifact(source_path: Path) -> SourceArtifact:
    digest = sha256_file(source_path)

    media_type = (
        mimetypes.guess_type(source_path.name)[0]
        or "application/octet-stream"
    )

    return SourceArtifact(
        artifact_id=f"sha256-{digest}",
        filename=source_path.name,
        media_type=media_type,
        sha256=digest,
    )


def verify_artifact_integrity(
    source_path: Path,
    artifact: SourceArtifact,
) -> None:
    current_sha256 = sha256_file(source_path)

    if current_sha256 != artifact.sha256:
        raise ArtifactIntegrityError(
            "Source artifact SHA-256 does not match registered evidence."
        )
