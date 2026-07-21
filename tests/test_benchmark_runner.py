from __future__ import annotations

import csv
from pathlib import Path

import pytest

from fingerprint_benchmark.contract import CompareOutcome, MethodMetadata, PrepareOutcome, PreparedRepresentation
from fingerprint_benchmark.manifest import read_protocol_manifest
from fingerprint_benchmark.runner import run_manifest, validate_result_bundle


class FakeAdapter:
    metadata = MethodMetadata("sourceafis", "3.18.1")

    def __init__(self, score=0.0, fail_prepare=False, raise_compare=False, timing=1.0):
        self.score, self.fail_prepare, self.raise_compare, self.timing = score, fail_prepare, raise_compare, timing
        self.closed = False

    def prepare(self, path, metadata):
        if self.fail_prepare:
            return PrepareOutcome("error", error_code="prepare_failed", error_message="expected failure", wall_ms=self.timing)
        return PrepareOutcome("ok", PreparedRepresentation(b"template", "sourceafis", "3.18.1"), wall_ms=self.timing, internal_ms=self.timing)

    def compare(self, a, b):
        if self.raise_compare:
            raise RuntimeError("intentional")
        return CompareOutcome("ok", raw_score=self.score, wall_ms=self.timing, internal_ms=self.timing)

    def close(self): self.closed = True


def _rows(bundle):
    with (bundle / "results.csv").open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def test_runner_preserves_pair_metadata_and_zero_score(protocol_factory, tmp_path):
    _, dataset, path = protocol_factory()
    manifest = read_protocol_manifest(path, dataset)
    adapter = FakeAdapter(score=0.0)
    bundle = run_manifest(manifest=manifest, adapter=adapter, output_root=tmp_path / "out", provenance={}, replace=False)
    row = _rows(bundle)[0]
    assert row["subject_id_a"] == "A" and row["subject_id_b"] == "B"
    assert row["comparison_kind"] == "plain_self" and row["raw_score"] == "0.0"
    assert row["status"] == "ok" and not row["error_code"]
    assert adapter.closed


def test_runner_preserves_failure_without_zero_score(protocol_factory, tmp_path):
    _, dataset, path = protocol_factory()
    bundle = run_manifest(manifest=read_protocol_manifest(path, dataset), adapter=FakeAdapter(fail_prepare=True), output_root=tmp_path / "out", provenance={}, replace=False)
    row = _rows(bundle)[0]
    assert row["status"] == "prepare_a_failure"
    assert row["raw_score"] == "" and row["error_code"] == "prepare_failed"


def test_failed_run_publishes_no_partial_bundle(protocol_factory, tmp_path):
    _, dataset, path = protocol_factory()
    adapter = FakeAdapter(raise_compare=True)
    output = tmp_path / "out"
    with pytest.raises(RuntimeError, match="intentional"):
        run_manifest(manifest=read_protocol_manifest(path, dataset), adapter=adapter, output_root=output, provenance={})
    assert not list(output.glob("*"))
    assert adapter.closed


def test_existing_valid_bundle_is_reused_and_adapter_closed(protocol_factory, tmp_path):
    _, dataset, path = protocol_factory()
    manifest = read_protocol_manifest(path, dataset)
    first = run_manifest(manifest=manifest, adapter=FakeAdapter(1.0), output_root=tmp_path / "out", provenance={})
    adapter = FakeAdapter(2.0)
    second = run_manifest(manifest=manifest, adapter=adapter, output_root=tmp_path / "out", provenance={})
    assert first == second and _rows(second)[0]["raw_score"] == "1.0" and adapter.closed


def test_replace_is_explicit(protocol_factory, tmp_path):
    _, dataset, path = protocol_factory()
    manifest = read_protocol_manifest(path, dataset)
    first = run_manifest(manifest=manifest, adapter=FakeAdapter(1.0), output_root=tmp_path / "out", provenance={})
    second = run_manifest(manifest=manifest, adapter=FakeAdapter(2.0), output_root=tmp_path / "out", provenance={}, replace=True)
    assert first == second and _rows(second)[0]["raw_score"] == "2.0"


def test_score_payload_hash_excludes_timings(protocol_factory, tmp_path):
    _, dataset, path = protocol_factory()
    manifest = read_protocol_manifest(path, dataset)
    one = run_manifest(manifest=manifest, adapter=FakeAdapter(1.0, timing=1), output_root=tmp_path / "one", provenance={})
    two = run_manifest(manifest=manifest, adapter=FakeAdapter(1.0, timing=99), output_root=tmp_path / "two", provenance={})
    assert _rows(one)[0]["score_payload_sha256"] == _rows(two)[0]["score_payload_sha256"]


def test_bundle_validator_detects_tampering(protocol_factory, tmp_path):
    _, dataset, path = protocol_factory()
    bundle = run_manifest(manifest=read_protocol_manifest(path, dataset), adapter=FakeAdapter(), output_root=tmp_path / "out", provenance={})
    assert validate_result_bundle(bundle)["valid"]
    with (bundle / "results.csv").open("a", encoding="utf-8") as handle:
        handle.write("tampered\n")
    with pytest.raises(ValueError, match="checksum"):
        validate_result_bundle(bundle)
