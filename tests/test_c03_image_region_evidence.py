"""Image-region evidence tests using synthetic images only."""

from dataclasses import FrozenInstanceError, replace
from io import BytesIO

import pytest
from PIL import Image, ImageFile

from kuma_secure_knowledge_pipeline.artifacts import build_source_artifact
from kuma_secure_knowledge_pipeline.knowledge_contracts import SourceLocator
from kuma_secure_knowledge_pipeline.knowledge_evidence import load_verified_source_snapshot
from kuma_secure_knowledge_pipeline.knowledge_image import (
    ImageEvidenceResolutionError,
    resolve_image_region,
)


def _image(*, format="PNG", size=(16, 12), orientation=None):
    buffer = BytesIO()
    with Image.new("RGB", size, color=(17, 31, 47)) as image:
        if orientation is None:
            image.save(buffer, format=format)
        else:
            exif = Image.Exif()
            exif[274] = orientation
            image.save(buffer, format=format, exif=exif)
    return buffer.getvalue()


def _snapshot(
    tmp_path,
    content=None,
    *,
    filename="synthetic.png",
    region=(0.125, 0.25, 0.75, 0.5),
    media_type=None,
    kind="image_region",
):
    data = _image() if content is None else content
    path = tmp_path / filename
    path.write_bytes(data)
    artifact = build_source_artifact(path)
    if media_type is not None:
        artifact = replace(artifact, media_type=media_type)
    locator_args = {
        "artifact_id": artifact.artifact_id,
        "source_sha256": artifact.sha256,
    }
    if kind == "image_region":
        locator = SourceLocator(**locator_args, kind=kind, region=region)
    else:
        locator = SourceLocator(**locator_args, kind="pdf_page", page=1)
    snapshot = load_verified_source_snapshot(
        source_path=path,
        artifact=artifact,
        locator=locator,
        max_bytes=len(data),
    )
    return path, snapshot


def test_resolves_png_region_and_preserves_identity(tmp_path):
    _, snapshot = _snapshot(tmp_path)
    result = resolve_image_region(snapshot)
    assert result.artifact_id == snapshot.artifact.artifact_id
    assert result.source_sha256 == snapshot.artifact.sha256
    assert result.image_format == "PNG"
    assert result.width == 16
    assert result.height == 12
    assert result.region == (0.125, 0.25, 0.75, 0.5)
    assert result.pixel_box == (2, 3, 12, 6)


@pytest.mark.parametrize("filename", ["synthetic.jpg", "synthetic.jpeg"])
def test_resolves_jpeg_region(tmp_path, filename):
    _, snapshot = _snapshot(tmp_path, _image(format="JPEG"), filename=filename)
    result = resolve_image_region(snapshot)
    assert result.image_format == "JPEG"
    assert result.pixel_box == (2, 3, 12, 6)


def test_resolves_full_image_region(tmp_path):
    _, snapshot = _snapshot(tmp_path, region=(0.0, 0.0, 1.0, 1.0))
    assert resolve_image_region(snapshot).pixel_box == (0, 0, 16, 12)


def test_resolves_subpixel_region_conservatively(tmp_path):
    _, snapshot = _snapshot(tmp_path, region=(0.1, 0.1, 0.101, 0.101))
    assert resolve_image_region(snapshot).pixel_box == (1, 1, 2, 2)


def test_verified_snapshot_survives_source_deletion(tmp_path):
    path, snapshot = _snapshot(tmp_path)
    path.unlink()
    assert resolve_image_region(snapshot).pixel_box == (2, 3, 12, 6)


def test_verified_snapshot_survives_source_replacement(tmp_path):
    path, snapshot = _snapshot(tmp_path)
    path.write_bytes(b"changed content")
    assert resolve_image_region(snapshot).width == 16


def test_rejects_non_snapshot():
    with pytest.raises(ImageEvidenceResolutionError, match="snapshot"):
        resolve_image_region(object())


def test_rejects_wrong_locator_kind(tmp_path):
    _, snapshot = _snapshot(tmp_path, kind="pdf_page")
    with pytest.raises(ImageEvidenceResolutionError, match="locator"):
        resolve_image_region(snapshot)


@pytest.mark.parametrize("bad_limit", [None, True, False, 0, -1, 1.0, "192", 16_000_001])
def test_rejects_invalid_pixel_limits(tmp_path, bad_limit):
    _, snapshot = _snapshot(tmp_path)
    with pytest.raises(ImageEvidenceResolutionError, match="limit"):
        resolve_image_region(snapshot, max_pixels=bad_limit)


def test_rejects_too_many_pixels(tmp_path):
    _, snapshot = _snapshot(tmp_path)
    with pytest.raises(ImageEvidenceResolutionError, match="dimensions"):
        resolve_image_region(snapshot, max_pixels=191)
    assert resolve_image_region(snapshot, max_pixels=192).width == 16


@pytest.mark.parametrize("content", [b"not an image", b"GIF89a", b"<svg/>", b"%PDF-1.7"])
def test_rejects_unsupported_signatures(tmp_path, content):
    _, snapshot = _snapshot(tmp_path, content)
    with pytest.raises(ImageEvidenceResolutionError, match="signature"):
        resolve_image_region(snapshot)


@pytest.mark.parametrize("media_type", ["application/octet-stream", "image/jpeg", "IMAGE/PNG"])
def test_rejects_incompatible_media_registration(tmp_path, media_type):
    _, snapshot = _snapshot(tmp_path, media_type=media_type)
    with pytest.raises(ImageEvidenceResolutionError, match="registration"):
        resolve_image_region(snapshot)


def test_rejects_extension_mismatch(tmp_path):
    _, snapshot = _snapshot(tmp_path, filename="synthetic.jpg", media_type="image/png")
    with pytest.raises(ImageEvidenceResolutionError, match="registration"):
        resolve_image_region(snapshot)


def test_rejects_jpeg_disguised_as_png(tmp_path):
    _, snapshot = _snapshot(tmp_path, _image(format="JPEG"))
    with pytest.raises(ImageEvidenceResolutionError, match="registration"):
        resolve_image_region(snapshot)


@pytest.mark.parametrize("content", [b"\x89PNG\r\n\x1a\ninvalid", _image()[:-10]])
def test_rejects_truncated_png(tmp_path, content):
    _, snapshot = _snapshot(tmp_path, content)
    with pytest.raises(ImageEvidenceResolutionError):
        resolve_image_region(snapshot)


def test_rejects_truncated_jpeg(tmp_path):
    _, snapshot = _snapshot(tmp_path, _image(format="JPEG")[:-20], filename="synthetic.jpg")
    with pytest.raises(ImageEvidenceResolutionError):
        resolve_image_region(snapshot)


def test_rejects_non_identity_exif_orientation(tmp_path):
    _, snapshot = _snapshot(
        tmp_path,
        _image(format="JPEG", orientation=6),
        filename="synthetic.jpg",
    )
    with pytest.raises(ImageEvidenceResolutionError, match="EXIF"):
        resolve_image_region(snapshot)


def test_accepts_identity_exif_orientation(tmp_path):
    _, snapshot = _snapshot(
        tmp_path,
        _image(format="JPEG", orientation=1),
        filename="synthetic.jpg",
    )
    assert resolve_image_region(snapshot).image_format == "JPEG"


def test_rejects_multiframe_png(tmp_path):
    output = BytesIO()
    with (
        Image.new("RGBA", (16, 12), "red") as first,
        Image.new("RGBA", (16, 12), "blue") as second,
    ):
        first.save(
            output,
            format="PNG",
            save_all=True,
            append_images=[second],
            duration=[20, 20],
            loop=0,
        )
    _, snapshot = _snapshot(tmp_path, output.getvalue())
    with pytest.raises(ImageEvidenceResolutionError, match="multi-frame"):
        resolve_image_region(snapshot)


def test_rejects_truncated_tolerance_enabled(tmp_path, monkeypatch):
    _, snapshot = _snapshot(tmp_path)
    monkeypatch.setattr(ImageFile, "LOAD_TRUNCATED_IMAGES", True)
    with pytest.raises(ImageEvidenceResolutionError, match="tolerance"):
        resolve_image_region(snapshot)


def test_rejects_over_byte_limit(tmp_path):
    content = _image() + b" " * (8 * 1024 * 1024)
    _, snapshot = _snapshot(tmp_path, content)
    with pytest.raises(ImageEvidenceResolutionError, match="byte limit"):
        resolve_image_region(snapshot)


def test_result_is_immutable(tmp_path):
    _, snapshot = _snapshot(tmp_path)
    result = resolve_image_region(snapshot)
    with pytest.raises(FrozenInstanceError):
        result.pixel_box = (0, 0, 1, 1)


def test_rejects_declared_decompression_bomb(tmp_path):
    import zlib

    content = bytearray(_image())
    content[16:20] = (100_000).to_bytes(4, "big")
    content[20:24] = (100_000).to_bytes(4, "big")
    content[29:33] = zlib.crc32(content[12:29]).to_bytes(4, "big")
    _, snapshot = _snapshot(tmp_path, bytes(content))
    with pytest.raises(ImageEvidenceResolutionError):
        resolve_image_region(snapshot)
