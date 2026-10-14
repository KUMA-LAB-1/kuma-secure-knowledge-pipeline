"""Pure, deterministic chunk budget projection shared across consumers."""

MAX_CHUNK_AMPLIFICATION = 8


def project_chunk_allocation(
    *,
    canonical_chars: int,
    max_chars: int,
    overlap_chars: int,
) -> tuple[int, int]:
    """Return projected chunk count and aggregate characters.

    Projection performs no chunk allocation. Callers enforce their
    own validated resource policies before materializing chunks.
    """
    if type(canonical_chars) is not int or canonical_chars < 1:
        raise ValueError("Invalid canonical character count.")

    if type(max_chars) is not int or max_chars < 1:
        raise ValueError("Invalid maximum chunk length.")

    if type(overlap_chars) is not int or not 0 <= overlap_chars < max_chars:
        raise ValueError("Invalid chunk overlap.")

    if canonical_chars <= max_chars:
        return 1, canonical_chars

    stride = max_chars - overlap_chars
    remaining = canonical_chars - max_chars

    required_chunks = 1 + (remaining + stride - 1) // stride
    last_start = (required_chunks - 1) * stride
    last_size = canonical_chars - last_start

    projected_chars = (required_chunks - 1) * max_chars + last_size

    return required_chunks, projected_chars


def within_amplification_budget(
    *,
    canonical_chars: int,
    projected_chars: int,
) -> bool:
    """Apply the shared inclusive amplification boundary."""
    if type(canonical_chars) is not int or canonical_chars < 1:
        raise ValueError("Invalid canonical character count.")

    if type(projected_chars) is not int or projected_chars < 1:
        raise ValueError("Invalid projected character count.")

    return projected_chars <= MAX_CHUNK_AMPLIFICATION * canonical_chars
