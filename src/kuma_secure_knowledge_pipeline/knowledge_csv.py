"""Resolve semantic CSV evidence from verified immutable source bytes."""

import csv
from dataclasses import dataclass
from io import StringIO

from kuma_secure_knowledge_pipeline.knowledge_evidence import (
    VerifiedSourceSnapshot,
)

_CSV_MEDIA_TYPES = frozenset({"text/csv", "application/csv"})
_CSV_DELIMITERS = frozenset({",", ";", "\t", "|"})
_CANONICAL_CSV_FIELD_LIMIT = 131_072


class CsvEvidenceResolutionError(ValueError):
    """Raised when a CSV location cannot be verified against source bytes."""


@dataclass(frozen=True, slots=True, kw_only=True)
class ResolvedCsvRecord:
    """Immutable record resolved from a verified source snapshot.

    Content integrity is inherited from the snapshot. This value object
    does not independently prove the publisher's identity or authenticity.
    """

    artifact_id: str
    source_sha256: str
    record_index: int
    record_id: str
    fields: tuple[tuple[str, str], ...]


def _validate_csv_quote_syntax(content: str, delimiter: str) -> None:
    """Reject ambiguous CSV quoting before semantic resolution.

    Permit RFC-style doubled quotes, quoted delimiters and multiline values.
    Do not accept quotes inside unquoted fields or text after a closing quote.
    """
    state = "start"

    for character in content:
        if state == "start":
            if character == '"':
                state = "quoted"
            elif character != delimiter and character not in "\r\n":
                state = "unquoted"

        elif state == "unquoted":
            if character == '"':
                raise CsvEvidenceResolutionError("Unexpected quote inside an unquoted CSV field.")
            if character == delimiter or character in "\r\n":
                state = "start"

        elif state == "quoted":
            if character == '"':
                state = "after_quote"

        else:
            if character == '"':
                state = "quoted"
            elif character == delimiter or character in "\r\n":
                state = "start"
            else:
                raise CsvEvidenceResolutionError("Unexpected characters after a closing CSV quote.")

    if state == "quoted":
        raise CsvEvidenceResolutionError("Unterminated quoted CSV field.")


def resolve_csv_record(
    snapshot: VerifiedSourceSnapshot,
    *,
    id_column: str = "record_id",
    delimiter: str = ",",
) -> ResolvedCsvRecord:
    """Resolve a one-based logical CSV record using only verified bytes.

    Validate the full CSV, including records after the selected location.
    Preserve values as text; never coerce monetary or numerical fields.
    """
    if not isinstance(snapshot, VerifiedSourceSnapshot):
        raise CsvEvidenceResolutionError("Invalid verified source snapshot.")

    locator = snapshot.locator

    if locator.kind != "csv_row":
        raise CsvEvidenceResolutionError("Source locator is not a CSV row.")

    if (
        snapshot.artifact.media_type not in _CSV_MEDIA_TYPES
        or not snapshot.artifact.filename.lower().endswith(".csv")
    ):
        raise CsvEvidenceResolutionError("Source is not registered as CSV.")

    if type(id_column) is not str or not id_column or id_column.strip() != id_column:
        raise CsvEvidenceResolutionError("Invalid CSV identifier column.")

    if type(delimiter) is not str or delimiter not in _CSV_DELIMITERS:
        raise CsvEvidenceResolutionError("Invalid CSV delimiter.")

    if csv.field_size_limit() != _CANONICAL_CSV_FIELD_LIMIT:
        raise CsvEvidenceResolutionError("CSV field size limit is not configured as required.")

    try:
        decoded = snapshot.content.decode("utf-8-sig")
    except UnicodeError:
        decoded = None

    if decoded is None:
        raise CsvEvidenceResolutionError("CSV content is not valid UTF-8.")

    if "\x00" in decoded:
        raise CsvEvidenceResolutionError("CSV contains NUL characters.")

    _validate_csv_quote_syntax(decoded, delimiter)

    selected_fields: tuple[tuple[str, str], ...] | None = None
    seen_identifiers: set[str] = set()

    try:
        reader = csv.reader(
            StringIO(decoded, newline=""),
            delimiter=delimiter,
            strict=True,
        )

        header = next(reader, None)

        if not header:
            raise CsvEvidenceResolutionError("CSV header is missing.")

        if any(not name or name.strip() != name for name in header):
            raise CsvEvidenceResolutionError("Invalid CSV header field.")

        if len(set(header)) != len(header):
            raise CsvEvidenceResolutionError("Duplicate CSV header fields.")

        if id_column not in header:
            raise CsvEvidenceResolutionError("CSV identifier column is missing.")

        identifier_position = header.index(id_column)

        for record_index, row in enumerate(reader, start=1):
            if len(row) != len(header):
                raise CsvEvidenceResolutionError("CSV record does not match header width.")

            identifier = row[identifier_position]

            if not identifier or identifier.strip() != identifier:
                raise CsvEvidenceResolutionError("CSV record has an invalid identifier.")

            if identifier in seen_identifiers:
                raise CsvEvidenceResolutionError("Duplicate CSV record identifier.")

            seen_identifiers.add(identifier)

            if record_index == locator.record_index:
                if identifier != locator.record_id:
                    raise CsvEvidenceResolutionError(
                        "CSV record identifier does not match locator."
                    )

                selected_fields = tuple(zip(header, row, strict=True))

    except csv.Error as exc:
        raise CsvEvidenceResolutionError("Malformed CSV structure.") from exc

    if selected_fields is None:
        raise CsvEvidenceResolutionError("CSV record index does not exist.")

    return ResolvedCsvRecord(
        artifact_id=snapshot.artifact.artifact_id,
        source_sha256=snapshot.artifact.sha256,
        record_index=locator.record_index,
        record_id=locator.record_id,
        fields=selected_fields,
    )
