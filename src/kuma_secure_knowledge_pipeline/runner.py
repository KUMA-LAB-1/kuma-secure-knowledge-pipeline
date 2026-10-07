from pathlib import Path

from kuma_secure_knowledge_pipeline.artifacts import (
    build_source_artifact,
)
from kuma_secure_knowledge_pipeline.contracts import (
    ExtractionProvenance,
)
from kuma_secure_knowledge_pipeline.evidence import (
    reserve_evidence_run,
    write_extraction_evidence,
    write_normalization_failure_evidence,
)
from kuma_secure_knowledge_pipeline.extraction.client import (
    DETECT_DOCUMENT_TEXT_OPERATION,
    TEXTRACT_PROVIDER,
    TextractClientProtocol,
    TextractExtractor,
)
from kuma_secure_knowledge_pipeline.extraction.textract import (
    TextractResponseError,
    normalize_detect_document_text_response,
)
from kuma_secure_knowledge_pipeline.provenance import (
    validate_extraction_provenance,
)

EXPECTED_TEXTRACT_REGION = "us-east-1"


def _validate_textract_provenance(
    provenance: ExtractionProvenance,
) -> None:
    validate_extraction_provenance(provenance)

    if provenance.provider != TEXTRACT_PROVIDER:
        raise ValueError("Textract provenance provider mismatch.")

    if provenance.operation != DETECT_DOCUMENT_TEXT_OPERATION:
        raise ValueError("Textract provenance operation mismatch.")

    if provenance.region != EXPECTED_TEXTRACT_REGION:
        raise ValueError(
            f"Textract provenance region mismatch: expected {EXPECTED_TEXTRACT_REGION}."
        )


def run_local_pipeline(
    *,
    source_path: Path,
    output_root: Path,
    client: TextractClientProtocol,
    provenance: ExtractionProvenance,
) -> Path:
    """Run one complete evidence-first local extraction path."""

    _validate_textract_provenance(
        provenance,
    )

    artifact = build_source_artifact(
        source_path,
    )

    # Reservation is acquired before provider interaction.
    # It remains fail-closed unless durable evidence is published.
    with reserve_evidence_run(
        output_root=output_root,
        artifact_id=artifact.artifact_id,
        operation=provenance.operation,
        run_id=provenance.run_id,
    ) as reservation:
        extractor = TextractExtractor(
            client,
        )

        raw_response = extractor.extract_raw(
            artifact=artifact,
            source_path=source_path,
        )

        try:
            result = normalize_detect_document_text_response(
                artifact_id=artifact.artifact_id,
                response=raw_response,
            )
        except TextractResponseError as exc:
            write_normalization_failure_evidence(
                output_root=output_root,
                artifact=artifact,
                raw_response=raw_response,
                provenance=provenance,
                error_type=type(exc).__name__,
            )

            reservation.resolve()

            raise

        evidence_dir = write_extraction_evidence(
            output_root=output_root,
            artifact=artifact,
            raw_response=raw_response,
            result=result,
            provenance=provenance,
        )

        reservation.resolve()

        return evidence_dir
