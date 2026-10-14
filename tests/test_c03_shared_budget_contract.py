"""Independent security contracts for the shared chunk budget model."""

import pytest

from kuma_secure_knowledge_pipeline.knowledge_budget import (
    MAX_CHUNK_AMPLIFICATION,
    project_chunk_allocation,
    within_amplification_budget,
)


def _enumerate_slices(total, size, overlap):
    """Reference implementation using actual slice positions."""
    stride = size - overlap
    start = 0
    count = 0
    aggregate = 0

    while True:
        end = min(start + size, total)
        count += 1
        aggregate += end - start

        if end == total:
            break

        start += stride

    return count, aggregate


def test_shared_amplification_limit_is_eight():
    assert MAX_CHUNK_AMPLIFICATION == 8


@pytest.mark.parametrize(
    ("canonical", "size", "overlap", "expected"),
    [
        (1, 1, 0, (1, 1)),
        (5, 5, 0, (1, 5)),
        (6, 5, 0, (2, 6)),
        (9, 5, 4, (5, 25)),
        (639, 128, 114, (38, 4857)),
        (639, 128, 115, (41, 5239)),
        (5119, 4096, 4095, (1024, 4194304)),
    ],
)
def test_projection_known_cases(canonical, size, overlap, expected):
    result = project_chunk_allocation(
        canonical_chars=canonical,
        max_chars=size,
        overlap_chars=overlap,
    )
    assert result == expected


def test_projection_matches_independent_enumeration():
    checked = 0

    for total in range(1, 129):
        for size in range(1, 25):
            for overlap in range(size):
                actual = project_chunk_allocation(
                    canonical_chars=total,
                    max_chars=size,
                    overlap_chars=overlap,
                )

                reference = _enumerate_slices(total, size, overlap)

                assert actual == reference, (total, size, overlap, actual, reference)

                checked += 1

    assert checked == 38400


@pytest.mark.parametrize(
    "kwargs",
    [
        {"canonical_chars": 0, "max_chars": 4, "overlap_chars": 0},
        {"canonical_chars": True, "max_chars": 4, "overlap_chars": 0},
        {"canonical_chars": "10", "max_chars": 4, "overlap_chars": 0},
        {"canonical_chars": 10, "max_chars": 0, "overlap_chars": 0},
        {"canonical_chars": 10, "max_chars": False, "overlap_chars": 0},
        {"canonical_chars": 10, "max_chars": 4, "overlap_chars": -1},
        {"canonical_chars": 10, "max_chars": 4, "overlap_chars": 4},
        {"canonical_chars": 10, "max_chars": 4, "overlap_chars": True},
    ],
)
def test_projection_rejects_invalid_inputs(kwargs):
    with pytest.raises(ValueError):
        project_chunk_allocation(**kwargs)


def test_amplification_boundary_is_inclusive():
    assert within_amplification_budget(
        canonical_chars=639,
        projected_chars=4857,
    )

    assert within_amplification_budget(
        canonical_chars=639,
        projected_chars=8 * 639,
    )

    assert not within_amplification_budget(
        canonical_chars=639,
        projected_chars=5239,
    )

    assert not within_amplification_budget(
        canonical_chars=639,
        projected_chars=8 * 639 + 1,
    )


@pytest.mark.parametrize(
    ("canonical", "projected"),
    [
        (0, 8),
        (-1, 8),
        (True, 8),
        ("1", 8),
        (1, 0),
        (1, -1),
        (1, True),
        (1, "8"),
    ],
)
def test_amplification_rejects_invalid_inputs(canonical, projected):
    with pytest.raises(ValueError):
        within_amplification_budget(
            canonical_chars=canonical,
            projected_chars=projected,
        )
