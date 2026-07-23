from __future__ import annotations

import ast
import copy
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ROOT = REPOSITORY_ROOT / "audits" / "nbis_candidate_v1"
VALIDATOR_PATH = REPOSITORY_ROOT / "tools" / "validate_nbis_candidate_audit_v1.py"
SPEC = importlib.util.spec_from_file_location("validate_nbis_candidate_audit_v1", VALIDATOR_PATH)
assert SPEC is not None and SPEC.loader is not None
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


@pytest.fixture
def documents() -> dict[str, object]:
    return copy.deepcopy(validator.load_documents(PACKAGE_ROOT))


def semantic_errors(documents: dict[str, object]) -> list[str]:
    return validator.validate_semantics(documents)


def test_01_official_nbis_identity_is_accepted(documents: dict[str, object]) -> None:
    assert semantic_errors(documents) == []


def test_02_fork_is_rejected(documents: dict[str, object]) -> None:
    documents["candidate_identity.json"]["candidate"]["fork_used"] = True
    assert any("fork_used" in error for error in semantic_errors(documents))


def test_03_non_5_0_0_release_is_rejected(documents: dict[str, object]) -> None:
    documents["candidate_identity.json"]["candidate"]["release"] = "5.0.1"
    assert any("release" in error for error in semantic_errors(documents))


def test_04_modified_source_is_rejected(documents: dict[str, object]) -> None:
    documents["source_archive.json"]["source_modified"] = True
    assert any("modified source" in error for error in semantic_errors(documents))


def test_05_acquired_source_requires_archive_hash(documents: dict[str, object]) -> None:
    documents["source_archive.json"]["archive_sha256"] = None
    assert any("archive lacks" in error for error in semantic_errors(documents))


def test_06_missing_mindtct_evidence_is_rejected(documents: dict[str, object]) -> None:
    del documents["source_archive.json"]["source_subtrees"]["mindtct"]
    assert any("MINDTCT" in error for error in semantic_errors(documents))


def test_07_missing_bozorth3_evidence_is_rejected(documents: dict[str, object]) -> None:
    del documents["source_archive.json"]["source_subtrees"]["bozorth3"]
    assert any("BOZORTH3" in error for error in semantic_errors(documents))


def test_08_direct_png_support_requires_evidence(documents: dict[str, object]) -> None:
    documents["input_format_audit.json"]["evidence"] = []
    assert any("PNG support lacks evidence" in error for error in semantic_errors(documents))


def test_09_lossless_conversion_requires_pixel_hash_equality(documents: dict[str, object]) -> None:
    audit = documents["input_format_audit.json"]
    audit["MINDTCT_direct_PNG_support"] = False
    audit["conversion_required"] = True
    audit["conversion_lossless"] = True
    audit["pixel_equivalence_verified"] = False
    assert any("pixel hash equality" in error for error in semantic_errors(documents))


def test_10_lossy_conversion_is_rejected(documents: dict[str, object]) -> None:
    documents["input_format_audit.json"]["prohibited_preprocessing"]["lossy_conversion"] = True
    assert any("lossy_conversion" in error for error in semantic_errors(documents))


def test_11_inversion_is_rejected(documents: dict[str, object]) -> None:
    documents["input_format_audit.json"]["prohibited_preprocessing"]["inversion"] = True
    assert any("inversion" in error for error in semantic_errors(documents))


def test_12_enhancement_is_rejected(documents: dict[str, object]) -> None:
    documents["input_format_audit.json"]["prohibited_preprocessing"]["enhancement"] = True
    assert any("enhancement" in error for error in semantic_errors(documents))


def test_13_crop_is_rejected(documents: dict[str, object]) -> None:
    documents["input_format_audit.json"]["prohibited_preprocessing"]["crop"] = True
    assert any("crop" in error for error in semantic_errors(documents))


def test_14_generic_resize_is_rejected(documents: dict[str, object]) -> None:
    documents["input_format_audit.json"]["prohibited_preprocessing"]["generic_resize"] = True
    assert any("generic_resize" in error for error in semantic_errors(documents))


def test_15_1000_ppi_record_is_required(documents: dict[str, object]) -> None:
    del documents["resolution_policy_audit.json"]["records"]["sd300b_1000_ppi"]
    assert any("sd300b_1000_ppi" in error for error in semantic_errors(documents))


def test_16_2000_ppi_record_is_required(documents: dict[str, object]) -> None:
    del documents["resolution_policy_audit.json"]["records"]["sd300c_2000_ppi"]
    assert any("sd300c_2000_ppi" in error for error in semantic_errors(documents))


def test_17_1000_ppi_guidance_does_not_prove_2000_ppi(documents: dict[str, object]) -> None:
    records = documents["resolution_policy_audit.json"]["records"]
    records["sd300c_2000_ppi"]["inferred_from_1000_guidance"] = True
    assert any("inferred" in error for error in semantic_errors(documents))


def test_18_2000_ppi_cascade_without_source_is_rejected(documents: dict[str, object]) -> None:
    audit = documents["resolution_policy_audit.json"]
    audit["cascade_2000_to_1000_to_500_approved"] = True
    audit["official_cascade_source_present"] = False
    assert any("cascade lacks" in error for error in semantic_errors(documents))


def test_19_suitable_without_2000_path_is_rejected(documents: dict[str, object]) -> None:
    documents["candidate_identity.json"]["candidate_verdict"] = "SUITABLE"
    assert any("SUITABLE does not meet" in error for error in semantic_errors(documents))


def test_20_suitable_without_successful_build_is_rejected(documents: dict[str, object]) -> None:
    documents["candidate_identity.json"]["candidate_verdict"] = "SUITABLE"
    records = documents["resolution_policy_audit.json"]["records"]
    records["sd300b_1000_ppi"]["canonical_pipeline_available"] = True
    records["sd300c_2000_ppi"]["canonical_pipeline_available"] = True
    assert any("SUITABLE does not meet" in error for error in semantic_errors(documents))


def test_21_suitable_without_full_image_to_score_path_is_rejected(documents: dict[str, object]) -> None:
    documents["candidate_identity.json"]["candidate_verdict"] = "SUITABLE"
    documents["pipeline_contract.json"]["prepare_operations"] = []
    errors = semantic_errors(documents)
    assert any("image-to-score" in error or "SUITABLE does not meet" in error for error in errors)


def test_22_suitable_with_prerequisites_requires_blocker(documents: dict[str, object]) -> None:
    documents["risks_and_open_questions.json"]["blocking_prerequisites"] = []
    assert any("lacks a blocking prerequisite" in error for error in semantic_errors(documents))


def test_23_not_suitable_requires_rationale(documents: dict[str, object]) -> None:
    documents["candidate_identity.json"]["candidate_verdict"] = "NOT_SUITABLE"
    assert any("lacks blocking rationale" in error for error in semantic_errors(documents))


def test_24_committed_raw_score_field_is_rejected(documents: dict[str, object]) -> None:
    documents["determinism_probe.json"]["raw_score"] = 123
    assert any("raw_score" in error for error in semantic_errors(documents))


def test_25_threshold_field_is_rejected(documents: dict[str, object]) -> None:
    documents["pipeline_contract.json"]["threshold"] = 40
    assert any("threshold" in error for error in semantic_errors(documents))


def test_26_decision_field_is_rejected(documents: dict[str, object]) -> None:
    documents["pipeline_contract.json"]["decision"] = "same"
    assert any("decision" in error for error in semantic_errors(documents))


def test_27_cohort_subject_is_rejected(documents: dict[str, object]) -> None:
    documents["determinism_probe.json"]["cohort_subjects"] = ["00002000"]
    assert any("cohort subject" in error for error in semantic_errors(documents))


def test_28_fixture_other_than_00001000_is_rejected(documents: dict[str, object]) -> None:
    documents["determinism_probe.json"]["fixture_id"] = "00001001"
    assert any("fixture identity" in error for error in semantic_errors(documents))


def test_29_fallback_is_rejected(documents: dict[str, object]) -> None:
    documents["determinism_probe.json"]["fallback_subject_used"] = True
    assert any("fallback_subject_used" in error for error in semantic_errors(documents))


def test_30_third_party_binary_is_rejected(documents: dict[str, object]) -> None:
    documents["build_audit.json"]["third_party_binary_used"] = True
    assert any("third-party binary" in error for error in semantic_errors(documents))


def test_31_nbis_net_is_rejected(documents: dict[str, object]) -> None:
    documents["build_audit.json"]["build_reproducibility_assessment"] = "Use NBIS.Net"
    assert any("NBIS.Net" in error for error in semantic_errors(documents))


def test_32_source_archive_tracked_state_is_rejected(documents: dict[str, object]) -> None:
    documents["source_archive.json"]["tracked_in_git"] = True
    assert any("recorded as tracked" in error for error in semantic_errors(documents))


def test_33_executable_tracked_state_is_rejected(documents: dict[str, object]) -> None:
    documents["audit_lock.json"]["artifact_tracking"]["binary_tracked"] = True
    assert any("binary_tracked" in error for error in semantic_errors(documents))


def test_34_image_tracked_state_is_rejected(documents: dict[str, object]) -> None:
    documents["audit_lock.json"]["artifact_tracking"]["image_tracked"] = True
    assert any("image_tracked" in error for error in semantic_errors(documents))


def test_35_minutiae_tracked_state_is_rejected(documents: dict[str, object]) -> None:
    documents["audit_lock.json"]["artifact_tracking"]["minutiae_tracked"] = True
    assert any("minutiae_tracked" in error for error in semantic_errors(documents))


def test_36_absolute_path_is_rejected(documents: dict[str, object]) -> None:
    documents["build_audit.json"]["commands_normalized"] = ["C" + ":" + "\\local\\build"]
    assert any("absolute local path" in error for error in semantic_errors(documents))


def test_37_username_field_is_rejected(documents: dict[str, object]) -> None:
    documents["build_environment_inventory.json"]["username"] = "alice"
    assert any("username/hostname" in error for error in semantic_errors(documents))


def test_38_hostname_field_is_rejected(documents: dict[str, object]) -> None:
    documents["build_environment_inventory.json"]["hostname"] = "DESKTOP-ABC123"
    assert any("username/hostname" in error for error in semantic_errors(documents))


def test_39_lock_validation_passes_for_published_package() -> None:
    assert validator.validate_package(REPOSITORY_ROOT) == []


def test_40_sha256sums_covers_every_package_file_except_itself() -> None:
    checksums, errors = validator._parse_checksums(PACKAGE_ROOT / "SHA256SUMS.txt")
    assert errors == []
    assert set(checksums) == set(validator.PACKAGE_FILES) - {"SHA256SUMS.txt"}


def test_41_canonical_json_is_deterministic() -> None:
    first = {"z": [3, 2, 1], "a": {"y": True, "x": None}}
    second = {"a": {"x": None, "y": True}, "z": [3, 2, 1]}
    assert validator.canonical_json_bytes(first) == validator.canonical_json_bytes(second)


def test_42_protected_tree_validation_matches_lock() -> None:
    lock = validator.load_documents(PACKAGE_ROOT)["audit_lock.json"]
    for relative, expected in lock["protected_area_tree_hashes"].items():
        assert validator.tree_identity(REPOSITORY_ROOT / relative) == expected


def test_43_ci_mode_does_not_require_nbis_source() -> None:
    report = validator.load_documents(PACKAGE_ROOT)["audit_validation_report.json"]
    assert report["ci_mode"]["source_tree_required"] is False
    assert report["ci_mode"]["dataset_required"] is False


def test_44_ci_mode_does_not_execute_nbis() -> None:
    report = validator.load_documents(PACKAGE_ROOT)["audit_validation_report.json"]
    assert report["ci_mode"]["executes_mindtct"] is False
    assert report["ci_mode"]["executes_bozorth3"] is False


def test_45_validator_does_not_modify_files() -> None:
    before = {
        path.relative_to(REPOSITORY_ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in PACKAGE_ROOT.iterdir() if path.is_file()
    }
    validator.validate_package(REPOSITORY_ROOT)
    after = {
        path.relative_to(REPOSITORY_ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in PACKAGE_ROOT.iterdir() if path.is_file()
    }
    assert after == before


def test_46_validator_uses_only_standard_library_imports() -> None:
    tree = ast.parse(VALIDATOR_PATH.read_text(encoding="utf-8"))
    imports = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imports.update(
        (node.module or "").split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    )
    assert not imports - {
        "__future__", "argparse", "hashlib", "json", "re", "sys", "pathlib", "typing", "urllib"
    }


def test_47_validator_has_no_process_or_network_coupling() -> None:
    source = VALIDATOR_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    assert not imported.intersection({"subprocess", "socket", "http", "requests"})
    assert "urlopen(" not in source


def test_48_package_contains_no_prohibited_artifact_suffix() -> None:
    assert not {
        path.suffix.casefold() for path in PACKAGE_ROOT.iterdir() if path.is_file()
    }.intersection(validator.FORBIDDEN_PACKAGE_SUFFIXES)
