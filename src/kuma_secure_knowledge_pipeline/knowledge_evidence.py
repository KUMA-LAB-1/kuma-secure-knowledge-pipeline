"""Bind source bytes to registered artifact and locator identities."""

import re
from dataclasses import dataclass, field
from pathlib import Path

from kuma_secure_knowledge_pipeline.artifacts import verify_artifact_bytes
from kuma_secure_knowledge_pipeline.contracts import SourceArtifact
from kuma_secure_knowledge_pipeline.knowledge_contracts import SourceLocator

_DEFAULT_MAX_BYTES = 16 * 1024 * 1024
_ABSOLUTE_MAX_BYTES = 64 * 1024 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True, slots=True, kw_only=True)
class VerifiedSourceSnapshot:
    """Immutable bytes matched to a registered source and location.

    A matching digest validates content integrity relative to the supplied
    metadata. It does not establish external authenticity or verify that
    the referenced PDF page, image region, or CSV record exists.
    """

    artifact: SourceArtifact
    locator: SourceLocator
    content: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.artifact, SourceArtifact):
            raise ValueError("Invalid source artifact.")

        if not isinstance(self.locator, SourceLocator):
            raise ValueError("Invalid source locator.")

        if type(self.content) is not bytes or not self.content:
            raise ValueError("Invalid source bytes.")

        digest = self.artifact.sha256

        if type(digest) is not str or _SHA256.fullmatch(digest) is None:
            raise ValueError("Invalid artifact SHA-256.")

        if (
            type(self.artifact.artifact_id) is not str
            or self.artifact.artifact_id != f"sha256-{digest}"
        ):
            raise ValueError("Artifact identity mismatch.")

        if (
            self.locator.artifact_id != self.artifact.artifact_id
            or self.locator.source_sha256 != digest
        ):
            raise ValueError("Locator does not match source artifact.")

        verify_artifact_bytes(self.content, self.artifact)


def _reject_redirected_source(path: Path) -> None:
    """Reject symlinks and junctions along the source path."""
    for component in (path, *path.parents):
        try:
            redirected = component.is_symlink() or component.is_junction()
        except OSError as exc:
            raise ValueError("Cannot inspect source path.") from exc

        if redirected:
            raise ValueError("Redirected source path is not allowed.")


def load_verified_source_snapshot(
    *,
    source_path: Path,
    artifact: SourceArtifact,
    locator: SourceLocator,
    max_bytes: int = _DEFAULT_MAX_BYTES,
) -> VerifiedSourceSnapshot:
    """Read once within a byte budget, verify, and retain those exact bytes."""
    if not isinstance(source_path, Path):
        raise ValueError("Invalid source path.")

    if type(max_bytes) is not int or not 1 <= max_bytes <= _ABSOLUTE_MAX_BYTES:
        raise ValueError("Invalid source byte limit.")

    if not isinstance(artifact, SourceArtifact):
        raise ValueError("Invalid source artifact.")

    if not isinstance(locator, SourceLocator):
        raise ValueError("Invalid source locator.")

    if (
        type(artifact.filename) is not str
        or artifact.filename != source_path.name
        or type(artifact.media_type) is not str
        or not artifact.media_type
    ):
        raise ValueError("Source metadata does not match the file.")

    _reject_redirected_source(source_path)

    if not source_path.is_file():
        raise ValueError("Source file does not exist or is not regular.")

    try:
        with source_path.open("rb") as stream:
            content = stream.read(max_bytes + 1)
    except OSError as exc:
        raise ValueError("Cannot read source file.") from exc

    if not content:
        raise ValueError("Source file is empty.")

    if len(content) > max_bytes:
        raise ValueError("Source file exceeds byte limit.")

    return VerifiedSourceSnapshot(
        artifact=artifact,
        locator=locator,
        content=content,
    )
