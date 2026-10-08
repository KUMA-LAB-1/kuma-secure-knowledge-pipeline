from kuma_secure_knowledge_pipeline.contracts import (
    EvidenceReference,
    ExtractionResult,
    NormalizedDocument,
    SourceArtifact,
)


def test_source_artifact_keeps_identity_and_origin() -> None:
    artifact = SourceArtifact(
        artifact_id="art-001",
        filename="security-report.png",
        media_type="image/png",
        sha256="abc123",
    )

    assert artifact.artifact_id == "art-001"
    assert artifact.filename == "security-report.png"
    assert artifact.media_type == "image/png"
    assert artifact.sha256 == "abc123"


def test_document_contracts_preserve_evidence_reference() -> None:
    reference = EvidenceReference(
        artifact_id="art-001",
        block_id="block-001",
        page=1,
        confidence=99.5,
    )

    extraction = ExtractionResult(
        artifact_id="art-001",
        provider="amazon-textract",
        operation="DetectDocumentText",
        text="SECURITY INCIDENT",
        average_confidence=99.5,
        evidence_refs=(reference,),
    )

    document = NormalizedDocument(
        artifact_id="art-001",
        content=extraction.text,
        evidence_refs=extraction.evidence_refs,
    )

    assert document.content == "SECURITY INCIDENT"
    assert document.evidence_refs[0].block_id == "block-001"
    assert document.evidence_refs[0].confidence == 99.5
