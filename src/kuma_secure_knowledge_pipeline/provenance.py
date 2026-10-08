import re
from datetime import UTC, datetime
from uuid import uuid4

from kuma_secure_knowledge_pipeline.contracts import ExtractionProvenance

_UTC_TIMESTAMP_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def _require_non_empty_text(
    value: str,
    *,
    label: str,
) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty string.")

    return value


def validate_extraction_provenance(
    provenance: ExtractionProvenance,
) -> None:
    """Validate execution provenance before an evidence boundary."""

    _require_non_empty_text(
        provenance.run_id,
        label="run_id",
    )
    _require_non_empty_text(
        provenance.provider,
        label="provider",
    )
    _require_non_empty_text(
        provenance.operation,
        label="operation",
    )
    _require_non_empty_text(
        provenance.region,
        label="region",
    )

    timestamp = _require_non_empty_text(
        provenance.started_at_utc,
        label="started_at_utc",
    )

    if not _UTC_TIMESTAMP_PATTERN.fullmatch(timestamp):
        raise ValueError("started_at_utc must use canonical YYYY-MM-DDTHH:MM:SSZ format.")

    try:
        datetime.strptime(
            timestamp,
            "%Y-%m-%dT%H:%M:%SZ",
        )
    except ValueError as exc:
        raise ValueError("started_at_utc must be a valid canonical UTC timestamp.") from exc


def create_extraction_provenance(
    *,
    provider: str,
    operation: str,
    region: str,
    run_id: str | None = None,
    now: datetime | None = None,
) -> ExtractionProvenance:
    """Create canonical UTC provenance for one extraction execution."""

    provider = _require_non_empty_text(
        provider,
        label="provider",
    )

    operation = _require_non_empty_text(
        operation,
        label="operation",
    )

    region = _require_non_empty_text(
        region,
        label="region",
    )

    current = datetime.now(UTC) if now is None else now

    if current.tzinfo is None or current.utcoffset() is None:
        raise ValueError("now must be timezone-aware.")

    utc_time = current.astimezone(UTC).replace(microsecond=0)

    started_at_utc = utc_time.isoformat().replace("+00:00", "Z")

    effective_run_id = (
        run_id
        if run_id is not None
        else (f"run-{utc_time.strftime('%Y%m%dT%H%M%SZ')}-{uuid4().hex[:12]}")
    )

    provenance = ExtractionProvenance(
        run_id=effective_run_id,
        provider=provider,
        operation=operation,
        region=region,
        started_at_utc=started_at_utc,
    )

    validate_extraction_provenance(provenance)

    return provenance
