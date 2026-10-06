import json
from pathlib import Path
from typing import Any

import pytest

from kuma_secure_knowledge_pipeline.runner import (
    run_local_pipeline,
)


class SyntheticTextractClient:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def detect_document_text(
        self,
        **kwargs: Any,
    ) -> dict[str, Any]:
        self.calls.append(kwargs)

        return {
            "Blocks": [
                {
                    "BlockType": "LINE",
                    "Id": "line-001",
                    "Page": 1,
                    "Confidence": 99.4,
                    "Text": "INCIDENT ID: INC-2026-001",
                },
                {
                    "BlockType": "LINE",
                    "Id": "line-002",
                    "Page": 1,
                    "Confidence": 99.1,
                    "Text": "SOURCE IP: 198.51.100.24",
                },
                {
                    "BlockType": "LINE",
                    "Id": "line-003",
                    "Page": 1,
                    "Confidence": 98.9,
                    "Text": "ACCOUNT: analyst-demo",
                },
            ]
        }


@pytest.mark.smoke
def test_local_pipeline_smokey_preserves_evidence_without_secret_leak(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "synthetic-incident.png"

    source.write_bytes(b"\x89PNG\r\n\x1a\nsynthetic-public-security-fixture")

    environment_canary = "KUMA_SMOKE_CANARY_DO_NOT_COPY"

    monkeypatch.setenv(
        "KUMA_SMOKE_ENV_CANARY",
        environment_canary,
    )

    output_root = tmp_path / "evidence"
    client = SyntheticTextractClient()

    evidence_dir = run_local_pipeline(
        source_path=source,
        output_root=output_root,
        client=client,
    )

    assert len(client.calls) == 1

    expected_files = {
        "raw-response.json",
        "normalized.json",
        "manifest.json",
        "extracted.txt",
    }

    assert {path.name for path in evidence_dir.iterdir()} == expected_files

    manifest = json.loads(
        (evidence_dir / "manifest.json").read_text(
            encoding="utf-8",
        )
    )

    assert manifest["source"]["filename"] == ("synthetic-incident.png")

    assert len(manifest["source"]["sha256"]) == 64

    extracted = (evidence_dir / "extracted.txt").read_text(encoding="utf-8")

    assert "INC-2026-001" in extracted
    assert "198.51.100.24" in extracted
    assert "analyst-demo" in extracted

    combined_output = "\n".join(
        path.read_text(
            encoding="utf-8",
        )
        for path in evidence_dir.iterdir()
    )

    # Environment-only data must never be copied into evidence.
    assert environment_canary not in combined_output

    # Local filesystem path must not be embedded in public evidence.
    assert str(source) not in combined_output
