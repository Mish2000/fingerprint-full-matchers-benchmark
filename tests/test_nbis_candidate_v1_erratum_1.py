"""Dataset- and archive-independent tests for NBIS candidate erratum 1."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ROOT = REPOSITORY_ROOT / "audits" / "nbis_candidate_v1_erratum_1"


def _load_module(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, REPOSITORY_ROOT / relative)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


identity = _load_module("nbis_source_tree_identity_v2", "tools/recompute_nbis_source_tree_identity_v2.py")
validator = _load_module(
    "validate_nbis_candidate_v1_erratum_1", "tools/validate_nbis_candidate_v1_erratum_1.py"
)


def _zip(tmp_path: Path, entries: list[tuple[str, bytes]]) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    path = tmp_path / "sample.zip"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, payload in entries:
            archive.writestr(name, payload)
    return path


def _valid_zip(tmp_path: Path) -> Path:
    return _zip(tmp_path, [("Rel_5.0.0/a.txt", b"alpha"), ("Rel_5.0.0/z.bin", b"omega")])


def _documents() -> dict[str, object]:
    return {
        name: json.loads((PACKAGE_ROOT / name).read_text(encoding="utf-8"))
        for name in validator.JSON_FILES
    }


def test_archive_hash_mismatch_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(identity.IdentityError, match="archive SHA-256 mismatch"):
        identity.compute_identity(_valid_zip(tmp_path), "0" * 64)


def test_wrong_top_level_directory_is_rejected(tmp_path: Path) -> None:
    archive = _zip(tmp_path, [("wrong/a.txt", b"x")])
    with pytest.raises(identity.IdentityError, match="exactly one top-level"):
        identity.compute_identity(archive)


def test_multiple_top_level_directories_are_rejected(tmp_path: Path) -> None:
    archive = _zip(tmp_path, [("Rel_5.0.0/a", b"x"), ("other/b", b"y")])
    with pytest.raises(identity.IdentityError, match="exactly one top-level"):
        identity.compute_identity(archive)


def test_entry_outside_required_prefix_is_rejected(tmp_path: Path) -> None:
    archive = _zip(tmp_path, [("Rel_5.0.0/a", b"x"), ("orphan", b"y")])
    with pytest.raises(identity.IdentityError):
        identity.compute_identity(archive)


def test_path_traversal_is_rejected(tmp_path: Path) -> None:
    archive = _zip(tmp_path, [("Rel_5.0.0/../escape", b"x")])
    with pytest.raises(identity.IdentityError, match="traversal"):
        identity.compute_identity(archive)


def test_absolute_posix_path_is_rejected(tmp_path: Path) -> None:
    archive = _zip(tmp_path, [("/Rel_5.0.0/a", b"x")])
    with pytest.raises(identity.IdentityError, match="absolute"):
        identity.compute_identity(archive)


def test_drive_prefixed_path_is_rejected(tmp_path: Path) -> None:
    archive = _zip(tmp_path, [("C:/Rel_5.0.0/a", b"x")])
    with pytest.raises(identity.IdentityError, match="drive-prefixed"):
        identity.compute_identity(archive)


def test_backslash_separator_is_rejected() -> None:
    with pytest.raises(identity.IdentityError, match="backslash"):
        identity._safe_relative_path("Rel_5.0.0\\a")


def test_duplicate_normalized_path_is_rejected(tmp_path: Path) -> None:
    archive = _zip(tmp_path, [("Rel_5.0.0/a/./b", b"x"), ("Rel_5.0.0/a/b", b"y")])
    with pytest.raises(identity.IdentityError, match="duplicate normalized"):
        identity.compute_identity(archive)


def test_directory_entries_are_not_counted(tmp_path: Path) -> None:
    archive = _zip(tmp_path, [("Rel_5.0.0/", b""), ("Rel_5.0.0/a", b"x")])
    summary, _ = identity.compute_identity(archive)
    assert summary["file_count"] == 1


def test_manifest_strips_exact_top_level_prefix(tmp_path: Path) -> None:
    _, manifest = identity.compute_identity(_valid_zip(tmp_path))
    assert b"Rel_5.0.0/" not in manifest
    assert manifest.endswith(b"z.bin\n")


def test_layout_hash_includes_top_level_prefix(tmp_path: Path) -> None:
    summary, manifest = identity.compute_identity(_valid_zip(tmp_path))
    assert summary["archive_layout_tree_sha256"] != hashlib.sha256(manifest).hexdigest()


def test_manifest_uses_two_ascii_space_separators(tmp_path: Path) -> None:
    _, manifest = identity.compute_identity(_valid_zip(tmp_path))
    fields = manifest.splitlines()[0].split(b"  ")
    assert len(fields) == 3


def test_manifest_field_order_is_hash_size_path(tmp_path: Path) -> None:
    _, manifest = identity.compute_identity(_valid_zip(tmp_path))
    digest, size, path = manifest.splitlines()[0].split(b"  ")
    assert len(digest) == 64
    assert size == b"5"
    assert path == b"a.txt"


def test_manifest_has_exactly_one_final_newline_per_record(tmp_path: Path) -> None:
    summary, manifest = identity.compute_identity(_valid_zip(tmp_path))
    assert manifest.endswith(b"\n")
    assert manifest.count(b"\n") == summary["file_count"]
    assert not manifest.endswith(b"\n\n")


def test_crlf_changes_tree_identity(tmp_path: Path) -> None:
    summary, manifest = identity.compute_identity(_valid_zip(tmp_path))
    assert hashlib.sha256(manifest.replace(b"\n", b"\r\n")).hexdigest() != summary[
        "canonical_release_root_tree_sha256"
    ]


def test_missing_final_newline_changes_tree_identity(tmp_path: Path) -> None:
    summary, manifest = identity.compute_identity(_valid_zip(tmp_path))
    assert hashlib.sha256(manifest.rstrip(b"\n")).hexdigest() != summary[
        "canonical_release_root_tree_sha256"
    ]


def test_manifest_uses_ordinal_case_sensitive_sorting(tmp_path: Path) -> None:
    archive = _zip(tmp_path, [("Rel_5.0.0/a", b"a"), ("Rel_5.0.0/B", b"b")])
    _, manifest = identity.compute_identity(archive)
    assert [line.split(b"  ")[2] for line in manifest.splitlines()] == [b"B", b"a"]


def test_zip_entry_order_does_not_change_identity(tmp_path: Path) -> None:
    first = _zip(tmp_path / "first", [("Rel_5.0.0/a", b"a"), ("Rel_5.0.0/b", b"b")])
    second = _zip(tmp_path / "second", [("Rel_5.0.0/b", b"b"), ("Rel_5.0.0/a", b"a")])
    assert identity.compute_identity(first)[1] == identity.compute_identity(second)[1]


def test_recomputation_is_deterministic(tmp_path: Path) -> None:
    archive = _valid_zip(tmp_path)
    assert identity.compute_identity(archive) == identity.compute_identity(archive)


def test_file_content_hash_uses_uncompressed_bytes(tmp_path: Path) -> None:
    archive = _zip(tmp_path, [("Rel_5.0.0/a", b"payload")])
    _, manifest = identity.compute_identity(archive)
    assert manifest.startswith(hashlib.sha256(b"payload").hexdigest().encode("ascii"))


def test_subtree_identity_removes_component_prefix(tmp_path: Path) -> None:
    archive = _zip(tmp_path, [("Rel_5.0.0/mindtct/a", b"x"), ("Rel_5.0.0/other", b"y")])
    summary, _ = identity.compute_identity(archive)
    record = identity.FileRecord(hashlib.sha256(b"x").hexdigest(), 1, "a")
    assert summary["mindtct_subtree"] == {"file_count": 1, "sha256": identity.tree_sha256([record])}


def test_empty_component_subtree_has_sha256_of_empty_payload(tmp_path: Path) -> None:
    summary, _ = identity.compute_identity(_valid_zip(tmp_path))
    assert summary["bozorth3_subtree"] == {
        "file_count": 0, "sha256": hashlib.sha256(b"").hexdigest()
    }


def test_summary_does_not_record_archive_absolute_path(tmp_path: Path) -> None:
    summary, _ = identity.compute_identity(_valid_zip(tmp_path))
    assert summary["archive"]["filename"] == "sample.zip"
    assert str(tmp_path) not in json.dumps(summary)


def test_package_records_official_file_count() -> None:
    assert _documents()["corrected_source_identity.json"]["file_count"] == 3879


def test_package_records_canonical_tree_hash() -> None:
    assert _documents()["corrected_source_identity.json"][
        "canonical_release_root_tree_sha256"
    ] == validator.CANONICAL_TREE_SHA256


def test_package_records_layout_tree_hash_as_diagnostic() -> None:
    document = _documents()["erratum.json"]
    assert document["archive_layout_diagnostic_value"] == validator.LAYOUT_TREE_SHA256
    assert document["corrected_value"] != document["archive_layout_diagnostic_value"]


def test_package_preserves_mindtct_subtree_hash() -> None:
    assert _documents()["corrected_source_identity.json"][
        "mindtct_subtree_sha256"
    ] == validator.MINDTCT_TREE_SHA256


def test_package_preserves_bozorth3_subtree_hash() -> None:
    assert _documents()["corrected_source_identity.json"][
        "bozorth3_subtree_sha256"
    ] == validator.BOZORTH3_TREE_SHA256


def test_original_hash_is_marked_non_reproducible() -> None:
    document = _documents()["erratum.json"]
    assert document["original_value"] == validator.NON_REPRODUCIBLE_V1_HASH
    assert document["original_value_status"] == "NON_REPRODUCIBLE"


def test_original_hash_root_cause_is_not_invented() -> None:
    assert _documents()["erratum.json"]["original_hash_root_cause"] == "NOT_RECOVERED"


def test_original_hash_cannot_be_an_accepted_alias() -> None:
    documents = _documents()
    documents["corrected_source_identity.json"][
        "canonical_release_root_tree_sha256"
    ] = validator.NON_REPRODUCIBLE_V1_HASH
    assert any("accepted identity" in error for error in validator.validate_semantics(documents))


def test_scientific_verdict_is_unchanged() -> None:
    impact = _documents()["impact_assessment.json"]
    assert impact["audit_verdict"] == impact["original_audit_verdict"]
    assert impact["verdict_changed"] is False


def test_all_four_prerequisites_remain_unresolved() -> None:
    prerequisites = _documents()["impact_assessment.json"]["remaining_prerequisites"]
    assert {item["prerequisite_id"] for item in prerequisites} == validator.PREREQUISITES
    assert {item["status"] for item in prerequisites} == {"UNRESOLVED"}


def test_reconciliation_records_only_path_scope_difference() -> None:
    differences = _documents()["reconciliation_summary.json"]["differences"]
    assert differences == {"content": 0, "extra": 0, "missing": 0, "path_only": 3879, "size": 0}


def test_reconciliation_contains_exactly_four_results() -> None:
    assert len(_documents()["reconciliation_summary.json"]["results"]) == 4


def test_independent_reproductions_agree() -> None:
    document = _documents()["corrected_source_identity.json"]
    assert document["independent_methods_agree"] is True
    assert document["zip_direct_reproduction"] == document["clean_extraction_reproduction"]


def test_external_registry_contains_exactly_seven_files() -> None:
    evidence = _documents()["external_evidence_registry.json"]["evidence"]
    assert len(evidence) == 7
    assert {item["filename"] for item in evidence} == set(validator.EXTERNAL_EVIDENCE)


def test_external_registry_has_no_absolute_paths() -> None:
    evidence = _documents()["external_evidence_registry.json"]["evidence"]
    assert all(item["absolute_path_recorded"] is False for item in evidence)
    assert validator.validate_content_safety(_documents()) == []


def test_external_registry_locks_hashes_and_sizes() -> None:
    evidence = _documents()["external_evidence_registry.json"]["evidence"]
    actual = {item["filename"]: (item["label"], item["bytes"], item["sha256"]) for item in evidence}
    assert actual == validator.EXTERNAL_EVIDENCE


def test_original_audit_tag_is_unchanged() -> None:
    result = subprocess.run(
        ["git", "rev-parse", "nbis-candidate-audit-v1^{commit}"], cwd=REPOSITORY_ROOT,
        check=True, capture_output=True, text=True, encoding="utf-8",
    )
    assert result.stdout.strip() == validator.ORIGINAL_AUDIT_COMMIT


def test_original_audit_files_are_unchanged() -> None:
    assert validator.validate_original_audit_immutability(REPOSITORY_ROOT) == []


def test_no_archive_or_binary_is_tracked() -> None:
    errors = validator.validate_tracked_artifacts(REPOSITORY_ROOT)
    assert not [error for error in errors if "archive/binary/image" in error]


def test_no_full_source_manifest_is_tracked() -> None:
    errors = validator.validate_tracked_artifacts(REPOSITORY_ROOT)
    assert not [error for error in errors if "full source manifest" in error]


def test_no_nbis_source_tree_is_tracked() -> None:
    errors = validator.validate_tracked_artifacts(REPOSITORY_ROOT)
    assert not [error for error in errors if "NBIS source tree" in error]


def test_package_json_is_canonical() -> None:
    for name in validator.JSON_FILES:
        path = PACKAGE_ROOT / name
        assert path.read_bytes() == validator.canonical_json_bytes(json.loads(path.read_text(encoding="utf-8")))


def test_erratum_lock_matches_package_and_code() -> None:
    assert not [error for error in validator.validate_package(REPOSITORY_ROOT) if "lock" in error]


def test_sha256sums_matches_package() -> None:
    assert not [error for error in validator.validate_package(REPOSITORY_ROOT) if "SHA256SUMS" in error]


def test_validator_accepts_complete_package() -> None:
    assert validator.validate_package(REPOSITORY_ROOT) == []


def test_ci_validation_requires_no_archive_or_dataset() -> None:
    report = _documents()["erratum_validation_report.json"]
    assert report["ci_mode"] == {
        "archive_required": False, "dataset_required": False,
        "network_required": False, "wsl_required": False,
    }


def test_ci_invokes_erratum_validator_and_tests() -> None:
    workflow = (REPOSITORY_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "validate_nbis_candidate_v1_erratum_1.py" in workflow
    assert "test_nbis_candidate_v1_erratum_1.py" in workflow


def test_recompute_tool_has_no_extraction_call() -> None:
    source = (REPOSITORY_ROOT / "tools" / "recompute_nbis_source_tree_identity_v2.py").read_text(
        encoding="utf-8"
    )
    assert ".extract(" not in source
    assert ".extractall(" not in source


def test_validator_has_no_network_or_archive_opening() -> None:
    source = (REPOSITORY_ROOT / "tools" / "validate_nbis_candidate_v1_erratum_1.py").read_text(
        encoding="utf-8"
    )
    assert "urllib" not in source
    assert "zipfile" not in source


def test_validator_is_read_only() -> None:
    source = (REPOSITORY_ROOT / "tools" / "validate_nbis_candidate_v1_erratum_1.py").read_text(
        encoding="utf-8"
    )
    for mutation in ("write_bytes(", "write_text(", "unlink(", "mkdir(", "rmdir("):
        assert mutation not in source


def test_validation_rejects_changed_verdict() -> None:
    documents = copy.deepcopy(_documents())
    documents["impact_assessment.json"]["verdict_changed"] = True
    assert "impact assessment mismatch: verdict_changed" in validator.validate_semantics(documents)


def test_validation_rejects_resolved_prerequisite() -> None:
    documents = copy.deepcopy(_documents())
    documents["impact_assessment.json"]["remaining_prerequisites"][0]["status"] = "RESOLVED"
    assert "remaining prerequisite set/status mismatch" in validator.validate_semantics(documents)


def test_validation_rejects_absolute_evidence_path() -> None:
    documents = copy.deepcopy(_documents())
    documents["external_evidence_registry.json"]["evidence"][0]["filename"] = "C:/private/report.json"
    assert any("absolute local path" in error for error in validator.validate_semantics(documents))


def test_validation_rejects_dataset_material() -> None:
    documents = copy.deepcopy(_documents())
    documents["impact_assessment.json"]["raw_scores"] = [1]
    assert any("dataset/image/score material" in error for error in validator.validate_semantics(documents))
