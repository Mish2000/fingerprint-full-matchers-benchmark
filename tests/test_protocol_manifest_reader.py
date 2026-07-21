from __future__ import annotations

import json
from pathlib import Path

import pytest

from fingerprint_benchmark.manifest import MANIFEST_COLUMNS, ManifestValidationError, read_protocol_manifest


def test_reads_locked_schema_and_preserves_both_subjects(protocol_factory):
    _, dataset, manifest = protocol_factory()
    loaded = read_protocol_manifest(manifest, dataset)
    assert loaded.records[0].subject_id_a == "A"
    assert loaded.records[0].subject_id_b == "B"
    assert loaded.records[0].comparison_kind == "plain_self"


def test_rejects_wrong_header(protocol_factory):
    _, dataset, manifest = protocol_factory(header=MANIFEST_COLUMNS[:-1])
    with pytest.raises(ManifestValidationError, match="24-column"):
        read_protocol_manifest(manifest, dataset)


def test_rejects_absolute_path(protocol_factory):
    _, dataset, manifest = protocol_factory(relative_path="C:/escape.bin")
    with pytest.raises(ManifestValidationError, match="release"):
        read_protocol_manifest(manifest, dataset)


def test_rejects_escaping_path(protocol_factory):
    _, dataset, manifest = protocol_factory(relative_path="sd300b/../escape.bin")
    with pytest.raises(ManifestValidationError, match="unsafe"):
        read_protocol_manifest(manifest, dataset)


def test_rejects_wrong_ppi(protocol_factory):
    _, dataset, manifest = protocol_factory(ppi=2000)
    with pytest.raises(ManifestValidationError, match="PPI"):
        read_protocol_manifest(manifest, dataset)


def test_rejects_manifest_changed_after_lock(protocol_factory):
    _, dataset, manifest = protocol_factory()
    manifest.write_text(manifest.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    with pytest.raises(ManifestValidationError, match="checksum mismatch"):
        read_protocol_manifest(manifest, dataset)
