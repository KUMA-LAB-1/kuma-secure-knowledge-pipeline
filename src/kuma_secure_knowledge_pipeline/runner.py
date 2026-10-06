from pathlib import Path

from kuma_secure_knowledge_pipeline.artifacts import (
    build_source_artifact,
)
from kuma_secure_knowledge_pipeline.evidence import (
    write_extraction_evidence,
)
from kuma_secure_knowledge_pipeline.extraction.client import (
    TextractClientProtocol,
    TextractExtractor,
)


def run_local_pipeline(
    *,
    source_path: Path,
    output_root: Path,
    client: TextractClientProtocol,
) -> Path:
    """Run one complete evidence-first local extraction path."""

    artifact = build_source_artifact(
        source_path,
    )

    raw_response, result = TextractExtractor(client).extract(
        artifact=artifact,
        source_path=source_path,
    )

    return write_extraction_evidence(
        output_root=output_root,
        artifact=artifact,
        raw_response=raw_response,
        result=result,
    )
