"""Contract tests for bounded knowledge index policies."""

import importlib

import pytest


def _module():
    return importlib.import_module("kuma_secure_knowledge_pipeline.knowledge_index")


def test_index_policy_accepts_explicit_aggregate_budgets():
    module = _module()

    policy = module.IndexPolicy(
        max_chunks=16,
        max_total_chars=4096,
        max_source_bytes=8192,
    )

    assert policy.max_chunks == 16
    assert policy.max_total_chars == 4096
    assert policy.max_source_bytes == 8192


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("max_chunks", 0),
        ("max_chunks", -1),
        ("max_chunks", True),
        ("max_chunks", 1025),
        ("max_total_chars", 0),
        ("max_total_chars", -1),
        ("max_total_chars", True),
        ("max_total_chars", 4 * 1024 * 1024 + 1),
        ("max_source_bytes", 0),
        ("max_source_bytes", -1),
        ("max_source_bytes", True),
        ("max_source_bytes", 16 * 1024 * 1024 + 1),
    ],
)
def test_index_policy_rejects_invalid_budgets(field, invalid):
    module = _module()

    values = {
        "max_chunks": 16,
        "max_total_chars": 4096,
        "max_source_bytes": 8192,
    }

    values[field] = invalid

    with pytest.raises(ValueError):
        module.IndexPolicy(**values)


def test_index_policy_is_immutable():
    module = _module()

    policy = module.IndexPolicy(
        max_chunks=16,
        max_total_chars=4096,
        max_source_bytes=8192,
    )

    with pytest.raises((AttributeError, TypeError)):
        policy.max_chunks = 1024
