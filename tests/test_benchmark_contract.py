from __future__ import annotations

import math

import pytest

from fingerprint_benchmark.contract import CompareOutcome, MethodMetadata, PrepareOutcome, PreparedRepresentation


def test_valid_prepare_and_zero_score_are_distinct_from_failure():
    prepared = PrepareOutcome("ok", PreparedRepresentation(b"x", "format", "1"))
    compared = CompareOutcome("ok", raw_score=0.0)
    assert prepared.representation is not None
    assert compared.raw_score == 0.0


def test_prepare_failure_requires_error_and_no_representation():
    failure = PrepareOutcome("error", error_code="bad_input")
    assert failure.representation is None
    with pytest.raises(ValueError):
        PrepareOutcome("error", PreparedRepresentation(b"x", "f", "1"), error_code="bad")


def test_compare_failure_cannot_have_score():
    with pytest.raises(ValueError):
        CompareOutcome("error", raw_score=0.0, error_code="failed")


@pytest.mark.parametrize("score", [math.inf, -math.inf, math.nan])
def test_success_requires_finite_raw_score(score):
    with pytest.raises(ValueError):
        CompareOutcome("ok", raw_score=score)


def test_metadata_exposes_raw_similarity_only():
    metadata = MethodMetadata("sourceafis", "3.18.1")
    assert vars(metadata) == {
        "method_id": "sourceafis", "method_version": "3.18.1",
        "score_direction": "higher_is_more_similar", "score_semantics": "raw_similarity",
    }
