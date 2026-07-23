"""Synthetic, WSL-free tests for the NBIS build environment freeze v1."""

from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
H1 = "1" * 64
H2 = "2" * 64
H3 = "3" * 64


def _load(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, REPOSITORY_ROOT / relative)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


validator = _load("validate_nbis_build_environment_v1_tests", "tools/validate_nbis_build_environment_v1.py")
freeze = _load("freeze_nbis_build_environment_v1_tests", "tools/freeze_nbis_build_environment_v1.py")


def _common() -> dict[str, object]:
    return {"freeze_id": validator.FREEZE_ID, "freeze_version": validator.FREEZE_VERSION}


def _valid_documents() -> dict[str, dict[str, object]]:
    common = _common()
    executable = {
        "architecture": "x86-64", "build_a_sha256": H1, "build_b_sha256": H1,
        "bytes": 100, "canonical_relative_path": "bin/mindtct", "canonical_sha256": H1,
        "dependencies_sha256": H2, "file_type": "ELF 64-bit LSB executable",
        "freeze_id": validator.FREEZE_ID, "freeze_version": validator.FREEZE_VERSION,
        "interpreter": "/lib64/ld-linux-x86-64.so.2", "linked_library_identities": {"ldd_normalized_sha256": H2},
        "nbis_release": "5.0.0", "rodata_sha256": H2, "text_sha256": H3,
    }
    builds = {}
    for build_id in ("BUILD_A", "BUILD_B"):
        builds[build_id] = {
            "bozorth3_built": True, "exit_status": 0, "installed_file_count": 10,
            "mindtct_built": True, "source_modified": False,
            "source_tree_sha256_after": validator.SOURCE_TREE_SHA256,
            "source_tree_sha256_before": validator.SOURCE_TREE_SHA256,
            "stderr_sha256": H1, "stdout_sha256": H2, "warning_count": 0,
        }
    reproducible = {
        "binary_hashes_equal": True, "canonical_executable_sha256": H1,
        "cli_payload_equal": True, "dynamic_dependencies_equal": True,
        "rodata_section_equal": True, "symbols_equal": True, "text_section_equal": True,
        "variance_algorithmically_relevant": False, "variance_description": "none",
    }
    return {
        "environment_plan.json": {
            **common,
            "archive_layout_identity_is_diagnostic_only": True,
            "audit_baselines": {
                "candidate_audit": {"commit": validator.AUDIT_COMMIT, "tag": validator.AUDIT_TAG},
                "provenance_erratum": {"commit": validator.ERRATUM_COMMIT, "tag": validator.ERRATUM_TAG},
            },
            "biometric_input_allowed": False, "build_count": 2,
            "distribution": {"architecture": "x86_64", "family": "Ubuntu", "release": "24.04 LTS", "wsl_generation": 2},
            "environment_id": "wsl2_ubuntu_24_04_lts_x86_64", "fixture_probe_allowed": False,
            "official_archive": {"filename": "nbis_v5_0_0.zip", "sha256": validator.ARCHIVE_SHA256, "size_bytes": validator.ARCHIVE_SIZE},
            "prerequisite_id": validator.PREREQUISITE_ID,
            "source_identity": {
                "algorithm_id": validator.SOURCE_ALGORITHM,
                "archive_layout_diagnostic_sha256": validator.ARCHIVE_LAYOUT_SHA256,
                "canonical_release_root_sha256": validator.SOURCE_TREE_SHA256, "file_count": 3879,
            },
            "source_modifications_allowed": False,
        },
        "system_change_summary.json": {
            **common,
            "cygwin_installed_by_task": False, "distribution_created_by_task": True,
            "distribution_installed": True, "distribution_name": "NBIS-BUILD-V1",
            "docker_installed_by_task": False, "host_compiler_installed_by_task": False,
            "persistent_path_modified": False, "reboot_performed_by_task": False,
            "reboot_required": False, "virtual_machine_platform_available": True, "wsl_enabled": True,
        },
        "distribution_provenance.json": {
            **common,
            "acquisition_method": "official_canonical_wsl_image_from_file", "architecture": "x86_64",
            "bootstrap_rootfs_bytes": 100, "bootstrap_rootfs_sha256": validator.UBUNTU_WSL_SHA256,
            "distribution": "Ubuntu", "export_sha256": H2, "export_size_bytes": 200,
            "official_image_filename": validator.UBUNTU_WSL_FILENAME,
            "official_image_sha256sums_url": validator.UBUNTU_WSL_SHA256SUMS_URL,
            "official_image_url": validator.UBUNTU_WSL_URL,
            "publisher": "Canonical", "release": "24.04 LTS",
            "restore_verification_status": "PASS", "rootfs_export_freezes_userspace": True,
            "wsl2_kernel_host_provided": True, "wsl_generation": 2,
            "wsl_kernel_version": "6.18.33.2-2", "wsl_version": "2.7.10.0",
        },
        "toolchain_manifest.json": {
            **common,
            "architecture": "x86_64", "locale": "C", "timezone": "UTC", "umask": "022",
            "gcc": {"identity": "/usr/bin/gcc", "package": "gcc", "version": "gcc 13.3.0"},
            "cc": {"identity": "/usr/bin/cc", "package": "gcc", "version": "gcc 13.3.0"},
            "gnu_make": {"identity": "/usr/bin/make", "is_gnu": True, "package": "make", "version": "GNU Make 4.3"},
            "bash": {"identity": "/usr/bin/bash", "package": "bash", "version": "GNU bash 5.2"},
            "libc": {"identity": "GNU C Library", "package": "libc6", "version": "2.39"},
            "binutils": {"identity": "/usr/bin/readelf", "package": "binutils", "version": "2.42"},
        },
        "package_manifest.json": {
            **common,
            "apt_mark_manual_sha256": H1, "apt_source_files_sha256": H2,
            "downloaded_deb_used": False, "dpkg_query_sha256": H3, "dpkg_status_sha256": H1,
            "installed_manual_packages": [{"name": "build-essential", "origin": "official Ubuntu repository", "version": "12.10ubuntu1"}],
            "official_ubuntu_repositories_only": True, "ppa_used": False, "third_party_repository_used": False,
        },
        "build_commands.json": {
            **common,
            "build_ids": ["BUILD_A", "BUILD_B"], "custom_flags_used": False,
            "environment": {"LANG": "C", "LC_ALL": "C", "TZ": "UTC", "umask": "022"},
            "normalized_command_sequence": [
                "./setup.sh <INSTALL_ROOT> --without-X11 --without-OPENJP2 --64",
                "make config", "make it", "make install LIBNBIS=no",
            ],
            "official_instruction_source": "INSTALL_LINUX_MACOSX.txt", "source_modified": False,
            "working_directory_placeholders": ["<BUILD_A_ROOT>", "<BUILD_B_ROOT>", "<CANONICAL_INSTALL_ROOT>", "<WSL_SOURCE_ROOT>"],
        },
        "build_results.json": {**common, "build_count": 2, "builds": builds, "canonical_build_selected": "BUILD_A"},
        "executable_manifest.json": {
            **common,
            "executables": {
                "mindtct": executable,
                "bozorth3": {**executable, "canonical_relative_path": "bin/bozorth3"},
            },
        },
        "reproducibility_report.json": {
            **common,
            "algorithmically_relevant_variance": False,
            "executables": {"mindtct": reproducible, "bozorth3": reproducible},
            "status": "EXACT_BINARY_REPRODUCIBILITY",
        },
        "export_receipt.json": {
            **common,
            "canonical_executable_sha256": {"mindtct": H1, "bozorth3": H1},
            "export_sha256": H2, "export_size_bytes": 200,
            "restore_verification_status": "PASS", "stored_outside_git": True,
        },
        "prerequisite_resolution.json": {
            **common,
            "prerequisite_id": validator.PREREQUISITE_ID,
            "remaining_gates": list(validator.REMAINING_GATES),
            "resolution_criterion": {
                "biometric_input_processed": False, "bozorth3_built": True,
                "clean_rebuild_completed": True, "executable_identity_recorded": True,
                "export_created": True, "frozen_environment_defined": True,
                "mindtct_built": True, "official_archive_verified": True,
                "restore_verified": True, "source_modified": False,
            },
            "status": "RESOLVED",
        },
        "environment_validation_report.json": {
            **common,
            "archive_valid": True, "build_a_passed": True, "build_b_passed": True,
            "bozorth3_built": True, "canonical_install_valid": True,
            "dataset_accessed": False, "distribution_official": True, "errors": [],
            "export_valid": True, "external_receipts": [], "fingerprint_images_read": False,
            "mindtct_built": True, "packages_pinned": True, "reproducibility_accepted": True,
            "restore_valid": True, "scores_generated": False, "source_trees_valid": True,
            "source_unchanged": True, "threshold_used": False, "toolchain_pinned": True, "valid": True,
        },
    }


def _errors(documents: dict[str, dict[str, object]]) -> list[str]:
    return validator.validate_semantics(documents)


def _mutate(document: str, path: tuple[str, ...], value: object) -> list[str]:
    documents = copy.deepcopy(_valid_documents())
    target: object = documents[document]
    for key in path[:-1]:
        target = target[key]  # type: ignore[index]
    target[path[-1]] = value  # type: ignore[index]
    return _errors(documents)


def _tracked_errors(tmp_path: Path, filename: str) -> list[str]:
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    path = tmp_path / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"artifact")
    subprocess.run(["git", "add", "--", filename], cwd=tmp_path, check=True)
    return validator.validate_tracked_artifacts(tmp_path)


def test_valid_environment_documents_are_accepted() -> None:
    assert _errors(_valid_documents()) == []


def test_correct_archive_hash_is_accepted() -> None:
    assert not [error for error in _errors(_valid_documents()) if "archive identity" in error]


def test_wrong_archive_hash_is_rejected() -> None:
    assert "official archive identity mismatch" in _mutate("environment_plan.json", ("official_archive", "sha256"), H1)


def test_wrong_source_tree_hash_is_rejected() -> None:
    assert "corrected source identity mismatch" in _mutate("environment_plan.json", ("source_identity", "canonical_release_root_sha256"), H1)


def test_source_modified_true_is_rejected() -> None:
    assert "build command policy mismatch" in _mutate("build_commands.json", ("source_modified",), True)


def test_third_party_rootfs_is_rejected() -> None:
    assert "distribution provenance mismatch: publisher" in _mutate("distribution_provenance.json", ("publisher",), "Third Party")


def test_wrong_official_wsl_image_hash_is_rejected() -> None:
    assert "official Ubuntu WSL image identity mismatch" in _mutate("distribution_provenance.json", ("bootstrap_rootfs_sha256",), H1)


def test_alias_bootstrap_acquisition_is_rejected() -> None:
    assert "distribution provenance mismatch: acquisition_method" in _mutate(
        "distribution_provenance.json", ("acquisition_method",), "official_wsl_alias_bootstrap_export_import"
    )


def test_orchestrator_uses_pinned_direct_canonical_wsl_image() -> None:
    source = (REPOSITORY_ROOT / "tools" / "freeze_nbis_build_environment_v1.py").read_text(encoding="utf-8")
    assert "official_canonical_wsl_image_from_file" in source
    assert "--from-file" in source
    assert '"--exec", "bash", "-lc", script' in source
    assert validator.UBUNTU_WSL_FILENAME in source
    assert validator.UBUNTU_WSL_SHA256 in source
    assert "official_wsl_alias_bootstrap_export_import" not in source


def test_non_ubuntu_2404_is_rejected() -> None:
    assert "distribution provenance mismatch: release" in _mutate("distribution_provenance.json", ("release",), "26.04 LTS")


def test_wsl1_is_rejected() -> None:
    assert "distribution provenance mismatch: wsl_generation" in _mutate("distribution_provenance.json", ("wsl_generation",), 1)


def test_wrong_architecture_is_rejected() -> None:
    assert "distribution provenance mismatch: architecture" in _mutate("distribution_provenance.json", ("architecture",), "aarch64")


def test_missing_toolchain_is_rejected() -> None:
    documents = _valid_documents()
    del documents["toolchain_manifest.json"]["gcc"]
    assert "missing toolchain identity/version: gcc" in _errors(documents)


def test_missing_compiler_version_is_rejected() -> None:
    assert "missing toolchain identity/version: gcc" in _mutate("toolchain_manifest.json", ("gcc", "version"), "")


def test_non_gnu_make_requires_rejection() -> None:
    assert "Make is not recorded as GNU Make" in _mutate("toolchain_manifest.json", ("gnu_make", "is_gnu"), False)


def test_third_party_apt_repository_is_rejected() -> None:
    assert "package source is not official Ubuntu only" in _mutate("package_manifest.json", ("official_ubuntu_repositories_only",), False)


def test_ppa_is_rejected() -> None:
    assert "third-party package acquisition is prohibited" in _mutate("package_manifest.json", ("ppa_used",), True)


def test_downloaded_deb_is_rejected() -> None:
    assert "third-party package acquisition is prohibited" in _mutate("package_manifest.json", ("downloaded_deb_used",), True)


def test_package_without_version_is_rejected() -> None:
    assert "package manifest lacks pinned package versions" in _mutate("package_manifest.json", ("installed_manual_packages",), [{"name": "make", "version": ""}])


def test_missing_build_a_is_rejected() -> None:
    documents = _valid_documents()
    del documents["build_results.json"]["builds"]["BUILD_A"]  # type: ignore[index]
    assert any("BUILD_A" in error for error in _errors(documents))


def test_missing_build_b_is_rejected() -> None:
    documents = _valid_documents()
    del documents["build_results.json"]["builds"]["BUILD_B"]  # type: ignore[index]
    assert any("BUILD_B" in error for error in _errors(documents))


def test_changed_post_build_source_hash_is_rejected() -> None:
    assert "BUILD_A mismatch: source_tree_sha256_after" in _mutate("build_results.json", ("builds", "BUILD_A", "source_tree_sha256_after"), H1)


def test_missing_mindtct_build_is_rejected() -> None:
    assert "BUILD_A mismatch: mindtct_built" in _mutate("build_results.json", ("builds", "BUILD_A", "mindtct_built"), False)


def test_missing_bozorth3_build_is_rejected() -> None:
    assert "BUILD_B mismatch: bozorth3_built" in _mutate("build_results.json", ("builds", "BUILD_B", "bozorth3_built"), False)


def test_missing_executable_hash_is_rejected() -> None:
    assert "executable hash missing: mindtct:canonical_sha256" in _mutate("executable_manifest.json", ("executables", "mindtct", "canonical_sha256"), None)


def test_differing_text_section_is_rejected() -> None:
    documents = _valid_documents()
    documents["reproducibility_report.json"]["status"] = "CONTROLLED_VARIANCE"
    documents["reproducibility_report.json"]["executables"]["mindtct"]["binary_hashes_equal"] = False  # type: ignore[index]
    documents["reproducibility_report.json"]["executables"]["mindtct"]["text_section_equal"] = False  # type: ignore[index]
    assert any("text_section_equal" in error for error in _errors(documents))


def test_differing_rodata_section_is_rejected() -> None:
    documents = _valid_documents()
    documents["reproducibility_report.json"]["status"] = "CONTROLLED_VARIANCE"
    documents["reproducibility_report.json"]["executables"]["mindtct"]["rodata_section_equal"] = False  # type: ignore[index]
    assert any("rodata_section_equal" in error for error in _errors(documents))


def test_differing_dependencies_are_rejected() -> None:
    documents = _valid_documents()
    documents["reproducibility_report.json"]["status"] = "CONTROLLED_VARIANCE"
    documents["reproducibility_report.json"]["executables"]["bozorth3"]["dynamic_dependencies_equal"] = False  # type: ignore[index]
    assert any("dynamic_dependencies_equal" in error for error in _errors(documents))


def test_controlled_build_id_variance_is_accepted() -> None:
    documents = _valid_documents()
    documents["reproducibility_report.json"]["status"] = "CONTROLLED_VARIANCE"
    for item in documents["reproducibility_report.json"]["executables"].values():  # type: ignore[union-attr]
        item["binary_hashes_equal"] = False
        item["variance_description"] = "build ID only"
    assert _errors(documents) == []


def test_algorithmically_relevant_variance_is_rejected() -> None:
    assert any("algorithmically relevant" in error for error in _mutate("reproducibility_report.json", ("executables", "mindtct", "variance_algorithmically_relevant"), True))


def test_missing_export_hash_is_rejected() -> None:
    assert "export receipt is incomplete" in _mutate("export_receipt.json", ("export_sha256",), None)


def test_restore_failure_is_rejected() -> None:
    assert "restore verification did not pass" in _mutate("export_receipt.json", ("restore_verification_status",), "FAIL")


def test_fingerprint_image_access_is_rejected() -> None:
    assert "prohibited evidence state: fingerprint_images_read" in _mutate("environment_validation_report.json", ("fingerprint_images_read",), True)


def test_dataset_access_is_rejected() -> None:
    assert "prohibited evidence state: dataset_accessed" in _mutate("environment_validation_report.json", ("dataset_accessed",), True)


def test_fixture_id_is_rejected() -> None:
    documents = _valid_documents()
    documents["environment_validation_report.json"]["fixture_id"] = "00001000"
    assert any("biometric/dataset/score" in error for error in _errors(documents))


def test_score_field_is_rejected() -> None:
    documents = _valid_documents()
    documents["environment_validation_report.json"]["score"] = 42
    assert any("biometric/dataset/score" in error for error in _errors(documents))


def test_threshold_field_is_rejected() -> None:
    documents = _valid_documents()
    documents["environment_validation_report.json"]["threshold"] = 1
    assert any("biometric/dataset/score" in error for error in _errors(documents))


def test_source_archive_tracked_is_rejected(tmp_path: Path) -> None:
    assert any("artifact tracked" in error for error in _tracked_errors(tmp_path, "nbis.zip"))


def test_rootfs_export_tracked_is_rejected(tmp_path: Path) -> None:
    assert any("artifact tracked" in error for error in _tracked_errors(tmp_path, "rootfs.tar"))


def test_executable_tracked_is_rejected(tmp_path: Path) -> None:
    assert any("artifact tracked" in error for error in _tracked_errors(tmp_path, "mindtct.exe"))


def test_library_tracked_is_rejected(tmp_path: Path) -> None:
    assert any("artifact tracked" in error for error in _tracked_errors(tmp_path, "libnbis.so"))


def test_absolute_local_path_is_rejected() -> None:
    documents = _valid_documents()
    documents["environment_validation_report.json"]["receipt_location"] = "C:/private/receipt.json"
    assert any("absolute local path" in error for error in _errors(documents))


def test_username_field_is_rejected() -> None:
    documents = _valid_documents()
    documents["environment_validation_report.json"]["username"] = "local-user"
    assert any("username/hostname" in error for error in _errors(documents))


def test_hostname_value_is_rejected() -> None:
    documents = _valid_documents()
    documents["environment_validation_report.json"]["machine"] = "DESKTOP-ABC123"
    assert any("hostname-like" in error for error in _errors(documents))


def test_lock_record_hash_can_be_verified(tmp_path: Path) -> None:
    path = tmp_path / "payload.json"
    path.write_bytes(b"payload\n")
    record = {"bytes": path.stat().st_size, "sha256": validator.file_sha256(path)}
    assert record == {"bytes": 8, "sha256": "d4e4877bac978b7952f0d544fc52ebff5411d351d129f1f056fa43f11da9af2b"}


def test_sha256sums_parser_accepts_sorted_records(tmp_path: Path) -> None:
    path = tmp_path / "SHA256SUMS.txt"
    path.write_text(f"{H1}  a.json\n{H2}  b.json\n", encoding="utf-8")
    checksums, errors = validator._parse_checksums(path)
    assert errors == [] and checksums == {"a.json": H1, "b.json": H2}


def test_sha256sums_parser_rejects_unsorted_records(tmp_path: Path) -> None:
    path = tmp_path / "SHA256SUMS.txt"
    path.write_text(f"{H2}  b.json\n{H1}  a.json\n", encoding="utf-8")
    _, errors = validator._parse_checksums(path)
    assert "SHA256SUMS.txt is not sorted" in errors


def test_protected_tree_identity_changes_with_content(tmp_path: Path) -> None:
    path = tmp_path / "area"
    path.mkdir()
    (path / "item").write_text("first", encoding="utf-8")
    before = validator.tree_identity(path)
    (path / "item").write_text("second", encoding="utf-8")
    assert validator.tree_identity(path) != before


def test_ci_invokes_environment_tests_without_wsl() -> None:
    workflow = (REPOSITORY_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "test_nbis_build_environment_v1.py" in workflow
    assert "wsl.exe" not in workflow


def test_ci_validator_is_conditional_on_package() -> None:
    workflow = (REPOSITORY_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "validate_nbis_build_environment_v1.py" in workflow
    assert "if [ -d environments/nbis_build_environment_v1 ]" in workflow


def test_validator_does_not_invoke_wsl_or_nbis() -> None:
    source = (REPOSITORY_ROOT / "tools" / "validate_nbis_build_environment_v1.py").read_text(encoding="utf-8")
    assert "wsl.exe" not in source
    assert "mindtct'" not in source and "bozorth3'" not in source


def test_validator_has_no_file_mutation_calls() -> None:
    source = (REPOSITORY_ROOT / "tools" / "validate_nbis_build_environment_v1.py").read_text(encoding="utf-8")
    for mutation in ("write_bytes(", "write_text(", "unlink(", "mkdir(", "rmdir("):
        assert mutation not in source


def test_unresolved_cannot_be_reported_as_resolved() -> None:
    assert "build environment prerequisite is not RESOLVED" in _mutate("prerequisite_resolution.json", ("status",), "UNRESOLVED")


def test_remaining_gates_stay_unresolved() -> None:
    assert _valid_documents()["prerequisite_resolution.json"]["remaining_gates"] == list(validator.REMAINING_GATES)


def test_wrong_remaining_gate_set_is_rejected() -> None:
    assert "prerequisite resolution criteria/gates mismatch" in _mutate("prerequisite_resolution.json", ("remaining_gates",), [])


def test_old_non_reproducible_hash_is_rejected_everywhere() -> None:
    documents = _valid_documents()
    documents["environment_validation_report.json"]["legacy"] = validator.PROHIBITED_V1_HASH
    assert any("non-reproducible v1" in error for error in _errors(documents))


def test_corrected_algorithm_and_hash_are_fixed_in_orchestrator() -> None:
    assert freeze.SOURCE_ALGORITHM == validator.SOURCE_ALGORITHM
    assert freeze.SOURCE_TREE_SHA256 == validator.SOURCE_TREE_SHA256


def test_both_provenance_tags_are_fixed_in_orchestrator() -> None:
    assert (freeze.AUDIT_TAG, freeze.AUDIT_COMMIT) == (validator.AUDIT_TAG, validator.AUDIT_COMMIT)
    assert (freeze.ERRATUM_TAG, freeze.ERRATUM_COMMIT) == (validator.ERRATUM_TAG, validator.ERRATUM_COMMIT)


@pytest.mark.parametrize("flag", ["--image", "--fixture", "--dataset", "--manifest", "--subject", "--threshold", "--score", "--decision", "--source-url", "--source-version", "--patch"])
def test_prohibited_cli_flags_are_not_accepted(flag: str) -> None:
    with pytest.raises(SystemExit):
        freeze._parser().parse_args([
            "--workspace-root", "external-workspace",
            "--archive", "nbis_v5_0_0.zip",
            flag, "value",
        ])


def test_phase_values_are_exactly_the_authorized_set() -> None:
    assert freeze.PHASES == ("preflight", "install-wsl", "configure", "build", "export", "restore-check", "package", "all")


def test_two_clean_builds_are_fixed() -> None:
    assert _valid_documents()["environment_plan.json"]["build_count"] == 2


def test_pinned_package_lookup_is_pipefail_safe() -> None:
    script = freeze.package_version_script()
    assert "binutils build-essential file unzip" in script
    assert "Candidate:/ {print $2; exit}" not in script


def test_biometric_and_fixture_execution_are_disabled() -> None:
    plan = _valid_documents()["environment_plan.json"]
    assert plan["biometric_input_allowed"] is False
    assert plan["fixture_probe_allowed"] is False
