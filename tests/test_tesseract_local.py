"""Offline Tesseract adapter and evidence tests."""

import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from kuma_secure_knowledge_pipeline.artifacts import (
    ArtifactIntegrityError,
    build_source_artifact,
)
from kuma_secure_knowledge_pipeline.extraction import tesseract_local as ocr
from kuma_secure_knowledge_pipeline.extraction.tesseract import (
    TSV_COLUMNS,
    TesseractResponseError,
)


def _environment(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    source = tmp_path / "fixture.png"
    source.write_bytes(b"\x89PNG\r\n\x1a\nsynthetic-test")

    binary = tmp_path / "tesseract.exe"
    binary.write_bytes(b"synthetic-binary")

    models = tmp_path / "tessdata"
    models.mkdir()
    (models / "por.traineddata").write_bytes(b"synthetic-model")

    return source, binary, models, tmp_path / "evidence"


def _tsv() -> bytes:
    return (
        "\t".join(TSV_COLUMNS)
        + "\n"
        + "5\t1\t1\t1\t1\t1\t0\t0\t10\t10\t98\tFailed\n"
        + "5\t1\t1\t1\t1\t2\t0\t0\t10\t10\t94\tLogins\n"
        + "5\t1\t1\t1\t1\t3\t0\t0\t10\t10\t96\t17\n"
        + "5\t1\t1\t1\t2\t1\t0\t0\t10\t10\t90\tMITRE\n"
        + "5\t1\t1\t1\t2\t2\t0\t0\t10\t10\t92\t71110\n"
    ).encode("utf-8")


def test_local_pipeline_preserves_raw_tsv_and_provenance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, binary, models, output = _environment(tmp_path)
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, _tsv(), b"")

    monkeypatch.setattr(ocr.subprocess, "run", fake_run)

    evidence_dir = ocr.run_local_tesseract_pipeline(
        source_path=source,
        output_root=output,
        binary_path=binary,
        tessdata_dir=models,
        run_id="run-local-001",
    )

    assert {path.name for path in evidence_dir.iterdir()} == {
        "raw-response.json",
        "normalized.json",
        "manifest.json",
        "extracted.txt",
    }

    raw = json.loads((evidence_dir / "raw-response.json").read_text())
    manifest = json.loads((evidence_dir / "manifest.json").read_text())
    normalized = json.loads((evidence_dir / "normalized.json").read_text())

    assert raw["tsv_text"].encode("utf-8") == _tsv()
    assert raw["tsv_sha256"] == hashlib.sha256(_tsv()).hexdigest()
    assert manifest["run"]["provider"] == "tesseract"
    assert manifest["run"]["region"] == "local"
    assert manifest["status"] == "success"
    assert normalized["text"] == "Failed Logins 17\nMITRE 71110"
    assert normalized["evidence_refs"][0]["block_id"] == "tsv-row-2"

    command, kwargs = calls[0]
    assert "tessedit_create_tsv=1" in command
    assert "tessedit_create_txt=0" in command
    assert kwargs["shell"] is False
    assert kwargs["timeout"] == 45


def test_integrity_failure_blocks_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, binary, models, _ = _environment(tmp_path)
    artifact = build_source_artifact(source)
    source.write_bytes(b"\x89PNG\r\n\x1a\nTAMPERED")

    def unexpected_run(*args, **kwargs):
        raise AssertionError("OCR must not run")

    monkeypatch.setattr(ocr.subprocess, "run", unexpected_run)

    with pytest.raises(ArtifactIntegrityError):
        ocr.extract_tesseract_raw(
            artifact=artifact,
            source_path=source,
            binary_path=binary,
            tessdata_dir=models,
        )


def test_invalid_tsv_publishes_classified_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, binary, models, output = _environment(tmp_path)

    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(command, 0, b"plain text\n", b"")

    monkeypatch.setattr(ocr.subprocess, "run", fake_run)

    with pytest.raises(TesseractResponseError):
        ocr.run_local_tesseract_pipeline(
            source_path=source,
            output_root=output,
            binary_path=binary,
            tessdata_dir=models,
            run_id="run-invalid",
        )

    artifact = build_source_artifact(source)
    location = output / artifact.artifact_id / "TesseractTSV"
    evidence_dir = location / "run-invalid"

    manifest = json.loads((evidence_dir / "manifest.json").read_text())
    assert manifest["status"] == "normalization_failed"
    assert (evidence_dir / "raw-response.json").is_file()
    assert not (evidence_dir / "normalized.json").exists()


def test_runtime_failure_retains_fail_closed_reservation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, binary, models, output = _environment(tmp_path)

    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(command, 1, b"", b"internal failure")

    monkeypatch.setattr(ocr.subprocess, "run", fake_run)

    with pytest.raises(ocr.TesseractRuntimeError):
        ocr.run_local_tesseract_pipeline(
            source_path=source,
            output_root=output,
            binary_path=binary,
            tessdata_dir=models,
            run_id="run-runtime-failed",
        )

    artifact = build_source_artifact(source)
    reservation = output / artifact.artifact_id / "TesseractTSV" / ".run-runtime-failed.reservation"
    assert reservation.is_file()
