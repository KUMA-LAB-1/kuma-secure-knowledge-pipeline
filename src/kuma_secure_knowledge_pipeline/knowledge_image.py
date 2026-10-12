"""Resolve regions from verified PNG and JPEG source bytes."""

import math
import warnings
from dataclasses import dataclass
from io import BytesIO

from PIL import Image, ImageFile

from kuma_secure_knowledge_pipeline.knowledge_evidence import VerifiedSourceSnapshot

_MAX_IMAGE_BYTES = 8 * 1024 * 1024
_MAX_IMAGE_PIXELS = 16_000_000
_MAX_DIMENSION = 8192
_SUPPORTED_FORMATS = {
    "PNG": ("image/png", frozenset({".png"})),
    "JPEG": ("image/jpeg", frozenset({".jpg", ".jpeg"})),
}
_SUPPORTED_MODES = frozenset({"1", "L", "LA", "P", "RGB", "RGBA", "CMYK"})


class ImageEvidenceResolutionError(ValueError):
    """Raised when an image region cannot be resolved from verified source bytes."""


@dataclass(frozen=True, slots=True, kw_only=True)
class ResolvedImageRegion:
    """Immutable identity and pixel envelope of an existing image region."""

    artifact_id: str
    source_sha256: str
    image_format: str
    width: int
    height: int
    region: tuple[float, float, float, float]
    pixel_box: tuple[int, int, int, int]


def resolve_image_region(
    snapshot: VerifiedSourceSnapshot,
    *,
    max_pixels: int = 8_000_000,
) -> ResolvedImageRegion:
    """Validate a static PNG/JPEG and resolve a normalized region without cropping."""
    if not isinstance(snapshot, VerifiedSourceSnapshot):
        raise ImageEvidenceResolutionError("Invalid verified source snapshot.")

    if snapshot.locator.kind != "image_region":
        raise ImageEvidenceResolutionError("Source locator is not an image region.")

    if type(max_pixels) is not int or not 1 <= max_pixels <= _MAX_IMAGE_PIXELS:
        raise ImageEvidenceResolutionError("Invalid image pixel limit.")

    content = snapshot.content
    if len(content) > _MAX_IMAGE_BYTES:
        raise ImageEvidenceResolutionError("Image source exceeds byte limit.")

    if content.startswith(b"\x89PNG\r\n\x1a\n"):
        expected_format = "PNG"
    elif content.startswith(b"\xff\xd8\xff"):
        expected_format = "JPEG"
    else:
        raise ImageEvidenceResolutionError("Unsupported image signature.")

    media_type, extensions = _SUPPORTED_FORMATS[expected_format]
    filename = snapshot.artifact.filename
    if (
        type(snapshot.artifact.media_type) is not str
        or snapshot.artifact.media_type != media_type
        or type(filename) is not str
        or not filename.lower().endswith(tuple(extensions))
    ):
        raise ImageEvidenceResolutionError("Image registration does not match content.")

    if ImageFile.LOAD_TRUNCATED_IMAGES:
        raise ImageEvidenceResolutionError("Truncated-image tolerance must be disabled.")

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(BytesIO(content)) as image:
                if image.format != expected_format:
                    raise ImageEvidenceResolutionError("Image format mismatch.")

                width, height = image.size
                if (
                    type(width) is not int
                    or type(height) is not int
                    or not 1 <= width <= _MAX_DIMENSION
                    or not 1 <= height <= _MAX_DIMENSION
                    or width * height > max_pixels
                ):
                    raise ImageEvidenceResolutionError("Image dimensions exceed supported limits.")

                if getattr(image, "n_frames", 1) != 1:
                    raise ImageEvidenceResolutionError(
                        "Animated or multi-frame image is not supported."
                    )

                if image.mode not in _SUPPORTED_MODES:
                    raise ImageEvidenceResolutionError("Image pixel mode is not supported.")

                image.verify()

            with Image.open(BytesIO(content)) as image:
                if image.format != expected_format or image.size != (width, height):
                    raise ImageEvidenceResolutionError(
                        "Image identity changed during verification."
                    )
                if image.getexif().get(274, 1) != 1:
                    raise ImageEvidenceResolutionError("Oriented EXIF image is not supported.")
                image.load()

    except ImageEvidenceResolutionError:
        raise
    except Exception:
        raise ImageEvidenceResolutionError("Cannot validate image structure.") from None

    left, top, right, bottom = snapshot.locator.region
    pixel_box = (
        math.floor(left * width),
        math.floor(top * height),
        math.ceil(right * width),
        math.ceil(bottom * height),
    )

    if (
        not 0 <= pixel_box[0] < pixel_box[2] <= width
        or not 0 <= pixel_box[1] < pixel_box[3] <= height
    ):
        raise ImageEvidenceResolutionError("Image region has no valid pixel area.")

    return ResolvedImageRegion(
        artifact_id=snapshot.artifact.artifact_id,
        source_sha256=snapshot.artifact.sha256,
        image_format=expected_format,
        width=width,
        height=height,
        region=snapshot.locator.region,
        pixel_box=pixel_box,
    )
