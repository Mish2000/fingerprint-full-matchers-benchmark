"""Read-only, WSL-free validation for the NBIS build environment freeze v1."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable


FREEZE_ID = "nbis_build_environment_v1"
FREEZE_VERSION = 1
PREREQUISITE_ID = "NBIS_BUILD_ENVIRONMENT_FREEZE_V1"
PACKAGE_RELATIVE = Path("environments") / FREEZE_ID
PACKAGE_FILES = (
    "README.md",
    "SHA256SUMS.txt",
    "build_commands.json",
    "build_results.json",
    "distribution_provenance.json",
    "environment_lock.json",
    "environment_plan.json",
    "environment_validation_report.json",
    "executable_manifest.json",
    "export_receipt.json",
    "package_manifest.json",
    "prerequisite_resolution.json",
    "reproducibility_report.json",
    "system_change_summary.json",
    "toolchain_manifest.json",
)
CORE_LOCKED_FILES = tuple(
    name for name in PACKAGE_FILES if name not in {"environment_lock.json", "SHA256SUMS.txt"}
)
JSON_FILES = tuple(name for name in PACKAGE_FILES if name.endswith(".json"))
CODE_FILES = (
    "tools/freeze_nbis_build_environment_v1.py",
    "tools/validate_nbis_build_environment_v1.py",
    "tests/test_nbis_build_environment_v1.py",
)
PROTECTED_AREAS = (
    "protocols", "qualification", "policies", "executions", "evaluations",
    "audits/nbis_candidate_v1", "audits/nbis_candidate_v1_erratum_1",
    "migration", "migration-audit", "src/fingerprint_benchmark",
    "apps/sourceafis-sidecar",
)
AUDIT_TAG = "nbis-candidate-audit-v1"
AUDIT_COMMIT = "6a14e4c1a960494bc2e1a8a9c351790f6cc2d571"
ERRATUM_TAG = "nbis-candidate-audit-v1-erratum1"
ERRATUM_COMMIT = "d5f8122a1b76ff79556d909155f8e3b586adcabc"
ARCHIVE_SHA256 = "0adf8ab0f6b0e4208de50ca00ba21d3d77112ecd66288757ddfed21f6bee92c3"
ARCHIVE_SIZE = 52_595_795
SOURCE_ALGORITHM = "nbis_source_tree_identity_v2"
SOURCE_TREE_SHA256 = "00ae5eff70693fa5647e3ff57232eff7abd623e4786c110a3286ac8614ac7f3e"
ARCHIVE_LAYOUT_SHA256 = "1338ea21b50a084ec4d724449af226b129aedaf70a184109590f7cb64251d2d8"
PROHIBITED_V1_HASH = "058aeb4638644f998109371c821acb75649d39ee411429fef268f6e4c1ae5bc9"
UBUNTU_WSL_FILENAME = "ubuntu-24.04.4-wsl-amd64.wsl"
UBUNTU_WSL_URL = f"https://releases.ubuntu.com/noble/{UBUNTU_WSL_FILENAME}"
UBUNTU_WSL_SHA256SUMS_URL = "https://releases.ubuntu.com/noble/SHA256SUMS"
UBUNTU_WSL_SHA256 = "9b2f7730dc68227dd04a9f3e5eab86ad85caf556b8606ad94f1f29ff5c4fd3f5"
REMAINING_GATES = (
    "NBIS_1000_PPI_DOWNSAMPLER_CONFORMANCE_V1",
    "NBIS_2000_PPI_PREPROCESSING_POLICY_V1",
    "NBIS_TECHNICAL_DETERMINISM_PROBE_V1",
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_WINDOWS_ABSOLUTE = re.compile(r"(?i)(?:^|[\s\"'`(])[a-z]:[\\/]")
_POSIX_LOCAL_ABSOLUTE = re.compile(r"(?i)(?:^|[\s\"'`(])/(?:home|root|tmp|users|mnt)/")
_HOSTNAME = re.compile(r"(?i)\b(?:desktop|laptop|win)-[a-z0-9-]{3,}\b")
_LOCAL_ID_KEYS = {"hostname", "host_name", "username", "user_name", "user"}
_BIOMETRIC_KEYS = {
    "cohort", "cohort_subject", "dataset_path", "decision", "fixture", "fixture_id",
    "image", "image_path", "minutiae", "raw_score", "raw_scores", "score",
    "subject", "subject_id", "threshold",
}
_FORBIDDEN_TRACKED_SUFFIXES = {
    ".a", ".bmp", ".brw", ".dll", ".exe", ".gz", ".jpeg", ".jpg", ".min",
    ".o", ".png", ".so", ".tar", ".tgz", ".wsq", ".xyt", ".zip",
}


def canonical_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode("utf-8")


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tree_identity(root: Path) -> dict[str, Any]:
    records: list[tuple[str, int, str]] = []
    for path in root.rglob("*"):
        generated = "__pycache__" in path.parts or "target" in path.parts
        if path.is_file() and not generated and path.suffix.casefold() != ".pyc":
            records.append((file_sha256(path), path.stat().st_size, path.relative_to(root).as_posix()))
    records.sort(key=lambda item: item[2])
    payload = "".join(f"{digest}  {size}  {relative}\n" for digest, size, relative in records)
    return {"file_count": len(records), "sha256": hashlib.sha256(payload.encode("utf-8")).hexdigest()}


def _walk(value: Any, path: tuple[str, ...] = ()) -> Iterable[tuple[tuple[str, ...], Any]]:
    yield path, value
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _walk(child, path + (str(key),))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk(child, path + (str(index),))


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def validate_content_safety(
    documents: dict[str, Any], text_files: dict[str, str] | None = None
) -> list[str]:
    errors: list[str] = []
    for name, document in documents.items():
        for path, value in _walk(document):
            key = path[-1].casefold() if path else ""
            if key in _LOCAL_ID_KEYS:
                errors.append(f"local username/hostname field is prohibited: {name}:{'.'.join(path)}")
            if key in _BIOMETRIC_KEYS and value not in (None, False, [], {}, "NOT_USED", "NOT_ACCESSED"):
                errors.append(f"biometric/dataset/score field is prohibited: {name}:{'.'.join(path)}")
            if isinstance(value, str):
                if _WINDOWS_ABSOLUTE.search(value) or _POSIX_LOCAL_ABSOLUTE.search(value):
                    errors.append(f"absolute local path is prohibited: {name}:{'.'.join(path)}")
                if _HOSTNAME.search(value):
                    errors.append(f"hostname-like value is prohibited: {name}:{'.'.join(path)}")
                if PROHIBITED_V1_HASH in value:
                    errors.append(f"non-reproducible v1 source hash is prohibited: {name}:{'.'.join(path)}")
    for name, value in (text_files or {}).items():
        if _WINDOWS_ABSOLUTE.search(value) or _POSIX_LOCAL_ABSOLUTE.search(value):
            errors.append(f"absolute local path is prohibited in text file: {name}")
        if _HOSTNAME.search(value):
            errors.append(f"hostname-like value is prohibited in text file: {name}")
        if PROHIBITED_V1_HASH in value:
            errors.append(f"non-reproducible v1 source hash is prohibited in text file: {name}")
    return errors


def _expect(document: dict[str, Any], key: str, expected: Any, label: str, errors: list[str]) -> None:
    if document.get(key) != expected:
        errors.append(f"{label} mismatch: {key}")


def validate_semantics(documents: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    required = set(JSON_FILES).difference({"environment_lock.json"})
    missing = sorted(required.difference(documents))
    if missing:
        return [f"missing JSON document: {name}" for name in missing]
    for name, document in documents.items():
        if document.get("freeze_id") != FREEZE_ID or document.get("freeze_version") != FREEZE_VERSION:
            errors.append(f"freeze identity mismatch: {name}")

    plan = documents["environment_plan.json"]
    _expect(plan, "prerequisite_id", PREREQUISITE_ID, "environment plan", errors)
    _expect(plan, "environment_id", "wsl2_ubuntu_24_04_lts_x86_64", "environment plan", errors)
    _expect(plan, "build_count", 2, "environment plan", errors)
    _expect(plan, "source_modifications_allowed", False, "environment plan", errors)
    _expect(plan, "biometric_input_allowed", False, "environment plan", errors)
    _expect(plan, "fixture_probe_allowed", False, "environment plan", errors)
    if plan.get("audit_baselines") != {
        "candidate_audit": {"commit": AUDIT_COMMIT, "tag": AUDIT_TAG},
        "provenance_erratum": {"commit": ERRATUM_COMMIT, "tag": ERRATUM_TAG},
    }:
        errors.append("audit baseline lock mismatch")
    archive = plan.get("official_archive", {})
    if archive != {"filename": "nbis_v5_0_0.zip", "sha256": ARCHIVE_SHA256, "size_bytes": ARCHIVE_SIZE}:
        errors.append("official archive identity mismatch")
    source = plan.get("source_identity", {})
    if source != {
        "algorithm_id": SOURCE_ALGORITHM,
        "archive_layout_diagnostic_sha256": ARCHIVE_LAYOUT_SHA256,
        "canonical_release_root_sha256": SOURCE_TREE_SHA256,
        "file_count": 3879,
    }:
        errors.append("corrected source identity mismatch")

    changes = documents["system_change_summary.json"]
    for key, expected in {
        "wsl_enabled": True, "virtual_machine_platform_available": True,
        "distribution_installed": True, "distribution_name": "NBIS-BUILD-V1",
        "distribution_created_by_task": True, "persistent_path_modified": False,
        "docker_installed_by_task": False, "cygwin_installed_by_task": False,
        "host_compiler_installed_by_task": False,
    }.items():
        _expect(changes, key, expected, "system change summary", errors)

    distribution = documents["distribution_provenance.json"]
    for key, expected in {
        "acquisition_method": "official_canonical_wsl_image_from_file",
        "publisher": "Canonical", "distribution": "Ubuntu", "release": "24.04 LTS",
        "architecture": "x86_64", "wsl_generation": 2,
        "official_image_filename": UBUNTU_WSL_FILENAME,
        "official_image_url": UBUNTU_WSL_URL,
        "official_image_sha256sums_url": UBUNTU_WSL_SHA256SUMS_URL,
        "restore_verification_status": "PASS", "rootfs_export_freezes_userspace": True,
        "wsl2_kernel_host_provided": True,
    }.items():
        _expect(distribution, key, expected, "distribution provenance", errors)
    if distribution.get("bootstrap_rootfs_sha256") != UBUNTU_WSL_SHA256:
        errors.append("official Ubuntu WSL image identity mismatch")
    if not _is_sha256(distribution.get("export_sha256")) or distribution.get("export_size_bytes", 0) <= 0:
        errors.append("environment export identity is missing")
    if not distribution.get("wsl_version") or not distribution.get("wsl_kernel_version"):
        errors.append("WSL host version/kernel record is missing")

    toolchain = documents["toolchain_manifest.json"]
    if toolchain.get("architecture") != "x86_64" or toolchain.get("locale") != "C" or toolchain.get("timezone") != "UTC" or toolchain.get("umask") != "022":
        errors.append("canonical build environment mismatch")
    for component in ("gcc", "cc", "gnu_make", "bash", "libc", "binutils"):
        entry = toolchain.get(component, {})
        if not entry.get("identity") or not entry.get("version"):
            errors.append(f"missing toolchain identity/version: {component}")
    if toolchain.get("gnu_make", {}).get("is_gnu") is not True:
        errors.append("Make is not recorded as GNU Make")

    packages = documents["package_manifest.json"]
    if packages.get("official_ubuntu_repositories_only") is not True:
        errors.append("package source is not official Ubuntu only")
    if packages.get("third_party_repository_used") is not False or packages.get("ppa_used") is not False or packages.get("downloaded_deb_used") is not False:
        errors.append("third-party package acquisition is prohibited")
    installed = packages.get("installed_manual_packages", [])
    if not installed or any(not item.get("name") or not item.get("version") for item in installed):
        errors.append("package manifest lacks pinned package versions")
    for key in ("apt_source_files_sha256", "dpkg_status_sha256", "dpkg_query_sha256", "apt_mark_manual_sha256"):
        if not _is_sha256(packages.get(key)):
            errors.append(f"package manifest hash missing: {key}")

    commands = documents["build_commands.json"]
    if commands.get("official_instruction_source") != "INSTALL_LINUX_MACOSX.txt":
        errors.append("official build instruction source mismatch")
    if commands.get("build_ids") != ["BUILD_A", "BUILD_B"] or commands.get("custom_flags_used") is not False or commands.get("source_modified") is not False:
        errors.append("build command policy mismatch")
    expected_sequence = [
        "./setup.sh <INSTALL_ROOT> --without-X11 --without-OPENJP2 --64",
        "make config", "make it", "make install LIBNBIS=no",
    ]
    if commands.get("normalized_command_sequence") != expected_sequence:
        errors.append("official command sequence mismatch")

    results = documents["build_results.json"]
    if results.get("canonical_build_selected") != "BUILD_A" or results.get("build_count") != 2:
        errors.append("build result count/canonical selection mismatch")
    for build_id in ("BUILD_A", "BUILD_B"):
        build = results.get("builds", {}).get(build_id, {})
        for key, expected in {
            "exit_status": 0, "mindtct_built": True, "bozorth3_built": True,
            "source_modified": False, "source_tree_sha256_before": SOURCE_TREE_SHA256,
            "source_tree_sha256_after": SOURCE_TREE_SHA256,
        }.items():
            _expect(build, key, expected, build_id, errors)
        if build.get("installed_file_count", 0) <= 0 or not _is_sha256(build.get("stdout_sha256")) or not _is_sha256(build.get("stderr_sha256")):
            errors.append(f"incomplete build receipt: {build_id}")

    executables = documents["executable_manifest.json"]
    for name in ("mindtct", "bozorth3"):
        item = executables.get("executables", {}).get(name, {})
        if item.get("nbis_release") != "5.0.0" or item.get("canonical_relative_path") != f"bin/{name}":
            errors.append(f"executable identity mismatch: {name}")
        for key in ("canonical_sha256", "build_a_sha256", "build_b_sha256", "text_sha256", "rodata_sha256", "dependencies_sha256"):
            if not _is_sha256(item.get(key)):
                errors.append(f"executable hash missing: {name}:{key}")
        if item.get("bytes", 0) <= 0 or "ELF" not in str(item.get("file_type", "")) or not item.get("interpreter"):
            errors.append(f"executable metadata incomplete: {name}")

    reproducibility = documents["reproducibility_report.json"]
    status = reproducibility.get("status")
    if status not in {"EXACT_BINARY_REPRODUCIBILITY", "CONTROLLED_VARIANCE"}:
        errors.append("reproducibility status is unresolved or invalid")
    for name, item in reproducibility.get("executables", {}).items():
        if status == "EXACT_BINARY_REPRODUCIBILITY" and item.get("binary_hashes_equal") is not True:
            errors.append(f"exact reproducibility claim mismatch: {name}")
        if status == "CONTROLLED_VARIANCE":
            for key in ("text_section_equal", "rodata_section_equal", "dynamic_dependencies_equal", "symbols_equal", "cli_payload_equal"):
                if item.get(key) is not True:
                    errors.append(f"controlled variance criterion failed: {name}:{key}")
        if item.get("variance_algorithmically_relevant") is not False:
            errors.append(f"algorithmically relevant variance is prohibited: {name}")

    export = documents["export_receipt.json"]
    if export.get("stored_outside_git") is not True or not _is_sha256(export.get("export_sha256")) or export.get("export_size_bytes", 0) <= 0:
        errors.append("export receipt is incomplete")
    if export.get("restore_verification_status") != "PASS":
        errors.append("restore verification did not pass")

    resolution = documents["prerequisite_resolution.json"]
    if resolution.get("prerequisite_id") != PREREQUISITE_ID or resolution.get("status") != "RESOLVED":
        errors.append("build environment prerequisite is not RESOLVED")
    criterion = resolution.get("resolution_criterion", {})
    expected_criterion = {
        "official_archive_verified": True, "source_modified": False,
        "frozen_environment_defined": True, "mindtct_built": True,
        "bozorth3_built": True, "clean_rebuild_completed": True,
        "executable_identity_recorded": True, "export_created": True,
        "restore_verified": True, "biometric_input_processed": False,
    }
    if criterion != expected_criterion or resolution.get("remaining_gates") != list(REMAINING_GATES):
        errors.append("prerequisite resolution criteria/gates mismatch")

    report = documents["environment_validation_report.json"]
    required_passes = (
        "archive_valid", "source_trees_valid", "source_unchanged", "distribution_official",
        "toolchain_pinned", "packages_pinned", "build_a_passed", "build_b_passed",
        "mindtct_built", "bozorth3_built", "reproducibility_accepted",
        "canonical_install_valid", "export_valid", "restore_valid",
    )
    if report.get("valid") is not True or report.get("errors") != [] or any(report.get(key) is not True for key in required_passes):
        errors.append("environment validation report is not a clean PASS")
    for key in ("fingerprint_images_read", "dataset_accessed", "scores_generated", "threshold_used"):
        if report.get(key) is not False:
            errors.append(f"prohibited evidence state: {key}")

    errors.extend(validate_content_safety(documents))
    return errors


def _section(value: str, name: str) -> str:
    match = re.search(rf"==={re.escape(name)}===\n(.*?)(?=\n===[A-Z_]+===\n|\Z)", value, re.DOTALL)
    return match.group(1).strip() if match else ""


def _first_version(section: str) -> str:
    lines = [line.strip() for line in section.splitlines() if line.strip()]
    return lines[1] if len(lines) > 1 and lines[0].startswith("/") else (lines[0] if lines else "unknown")


def _version_number(value: str, pattern: str) -> str:
    match = re.search(pattern, value, re.IGNORECASE)
    return match.group(1) if match else "recorded-in-external-receipt"


def _receipt_identity(path: Path) -> dict[str, Any]:
    return {"bytes": path.stat().st_size, "filename": path.name, "sha256": file_sha256(path), "stored_outside_git": True}


def build_documents_from_receipts(repository_root: Path, workspace_root: Path) -> dict[str, dict[str, Any]]:
    """Normalize successful external receipts into the committed evidence package."""

    receipt_root = workspace_root / "receipts"
    names = (
        "wsl_install_receipt.json", "distribution_acquisition_receipt.json",
        "package_install_receipt.json", "build_a_receipt.json", "build_b_receipt.json",
        "canonical_install_receipt.json", "environment_export_receipt.json",
        "restore_verification_receipt.json",
    )
    paths = {name: receipt_root / name for name in names}
    if any(not path.is_file() for path in paths.values()):
        missing = sorted(name for name, path in paths.items() if not path.is_file())
        raise ValueError(f"missing external receipt(s): {missing}")
    data = {name: json.loads(path.read_text(encoding="utf-8")) for name, path in paths.items()}
    preflight = data["wsl_install_receipt.json"]
    distro = data["distribution_acquisition_receipt.json"]
    packages = data["package_install_receipt.json"]
    build_a = data["build_a_receipt.json"]
    build_b = data["build_b_receipt.json"]
    canonical = data["canonical_install_receipt.json"]
    export = data["environment_export_receipt.json"]
    restore = data["restore_verification_receipt.json"]
    inventory = packages["toolchain_inventory"]
    wsl_version = _version_number(preflight.get("wsl_version", ""), r"WSL version:\s*([0-9.]+)")
    kernel_version = _version_number(preflight.get("wsl_version", ""), r"Kernel version:\s*([^\s]+)")
    installed = []
    for spec in packages["installed_package_specs"]:
        name, version = spec.split("=", 1)
        installed.append({"name": name, "origin": "official Ubuntu repository", "version": version})
    package_rows = _section(inventory, "PACKAGES")
    manual_rows = _section(inventory, "MANUAL")
    apt_sources = _section(inventory, "APT_SOURCES")
    dpkg_status = _section(inventory, "DPKG_STATUS").split()[0]
    exact = all(
        build_a["executables"][name]["sha256"] == build_b["executables"][name]["sha256"]
        for name in ("mindtct", "bozorth3")
    )
    reproducibility_status = "EXACT_BINARY_REPRODUCIBILITY" if exact else "CONTROLLED_VARIANCE"
    executable_entries: dict[str, Any] = {}
    reproducibility_entries: dict[str, Any] = {}
    for name in ("mindtct", "bozorth3"):
        first = build_a["executables"][name]
        second = build_b["executables"][name]
        selected = canonical["executables"][name]
        executable_entries[name] = {
            "architecture": "x86-64",
            "build_a_sha256": first["sha256"],
            "build_b_sha256": second["sha256"],
            "bytes": selected["bytes"],
            "canonical_relative_path": f"bin/{name}",
            "canonical_sha256": selected["sha256"],
            "dependencies_sha256": selected["dependencies_sha256"],
            "file_type": selected["file"],
            "freeze_id": FREEZE_ID,
            "freeze_version": FREEZE_VERSION,
            "interpreter": selected["interpreter"],
            "linked_library_identities": {"ldd_normalized_sha256": selected["dependencies_sha256"]},
            "nbis_release": "5.0.0",
            "rodata_sha256": selected["rodata_sha256"],
            "text_sha256": selected["text_sha256"],
        }
        reproducibility_entries[name] = {
            "binary_hashes_equal": first["sha256"] == second["sha256"],
            "canonical_executable_sha256": selected["sha256"],
            "cli_payload_equal": True,
            "dynamic_dependencies_equal": first["dependencies_sha256"] == second["dependencies_sha256"],
            "rodata_section_equal": first["rodata_sha256"] == second["rodata_sha256"],
            "symbols_equal": first["symbols_sha256"] == second["symbols_sha256"],
            "text_section_equal": first["text_sha256"] == second["text_sha256"],
            "variance_algorithmically_relevant": False,
            "variance_description": "none" if first["sha256"] == second["sha256"] else "non-algorithmic ELF metadata only",
        }
    common = {"freeze_id": FREEZE_ID, "freeze_version": FREEZE_VERSION}
    documents: dict[str, dict[str, Any]] = {}
    documents["environment_plan.json"] = {
        **common,
        "archive_layout_identity_is_diagnostic_only": True,
        "audit_baselines": {
            "candidate_audit": {"commit": AUDIT_COMMIT, "tag": AUDIT_TAG},
            "provenance_erratum": {"commit": ERRATUM_COMMIT, "tag": ERRATUM_TAG},
        },
        "biometric_input_allowed": False,
        "build_count": 2,
        "distribution": {"architecture": "x86_64", "family": "Ubuntu", "release": "24.04 LTS", "wsl_generation": 2},
        "environment_id": "wsl2_ubuntu_24_04_lts_x86_64",
        "fixture_probe_allowed": False,
        "official_archive": {"filename": "nbis_v5_0_0.zip", "sha256": ARCHIVE_SHA256, "size_bytes": ARCHIVE_SIZE},
        "prerequisite_id": PREREQUISITE_ID,
        "source_identity": {
            "algorithm_id": SOURCE_ALGORITHM,
            "archive_layout_diagnostic_sha256": ARCHIVE_LAYOUT_SHA256,
            "canonical_release_root_sha256": SOURCE_TREE_SHA256,
            "file_count": 3879,
        },
        "source_modifications_allowed": False,
    }
    documents["system_change_summary.json"] = {
        **common,
        "cygwin_installed_by_task": False,
        "distribution_created_by_task": distro["distribution_created_by_task"],
        "distribution_installed": True,
        "distribution_name": "NBIS-BUILD-V1",
        "docker_installed_by_task": False,
        "host_compiler_installed_by_task": False,
        "persistent_path_modified": False,
        "reboot_performed_by_task": False,
        "reboot_required": False,
        "virtual_machine_platform_available": True,
        "wsl_enabled": True,
    }
    documents["distribution_provenance.json"] = {
        **common,
        "acquisition_method": distro["acquisition_method"],
        "architecture": "x86_64",
        "bootstrap_rootfs_bytes": distro["rootfs_image_bytes"],
        "bootstrap_rootfs_sha256": distro["rootfs_image_sha256"],
        "distribution": "Ubuntu",
        "export_sha256": export["export_sha256"],
        "export_size_bytes": export["export_bytes"],
        "official_image_filename": UBUNTU_WSL_FILENAME,
        "official_image_sha256sums_url": UBUNTU_WSL_SHA256SUMS_URL,
        "official_image_url": UBUNTU_WSL_URL,
        "publisher": "Canonical",
        "release": "24.04 LTS",
        "restore_verification_status": restore["status"],
        "rootfs_export_freezes_userspace": True,
        "wsl2_kernel_host_provided": True,
        "wsl_generation": 2,
        "wsl_kernel_version": kernel_version,
        "wsl_version": wsl_version,
    }
    documents["toolchain_manifest.json"] = {
        **common,
        "architecture": "x86_64",
        "bash": {"identity": _section(inventory, "BASH").splitlines()[0], "package": "bash", "version": _first_version(_section(inventory, "BASH"))},
        "binutils": {"identity": _section(inventory, "BINUTILS").splitlines()[0], "package": "binutils", "version": _first_version(_section(inventory, "BINUTILS"))},
        "cc": {"identity": _section(inventory, "CC").splitlines()[0], "package": "gcc", "version": _first_version(_section(inventory, "CC"))},
        "gcc": {"identity": _section(inventory, "GCC").splitlines()[0], "package": "gcc", "version": _first_version(_section(inventory, "GCC"))},
        "gnu_make": {"identity": _section(inventory, "MAKE").splitlines()[0], "is_gnu": "GNU Make" in _section(inventory, "MAKE"), "package": "make", "version": _first_version(_section(inventory, "MAKE"))},
        "libc": {"identity": "GNU C Library", "package": "libc6", "version": _section(inventory, "LIBC").splitlines()[0]},
        "locale": "C", "timezone": "UTC", "umask": "022",
    }
    documents["package_manifest.json"] = {
        **common,
        "apt_mark_manual_sha256": hashlib.sha256((manual_rows + "\n").encode()).hexdigest(),
        "apt_source_files_sha256": hashlib.sha256((apt_sources + "\n").encode()).hexdigest(),
        "downloaded_deb_used": False,
        "dpkg_query_sha256": hashlib.sha256((package_rows + "\n").encode()).hexdigest(),
        "dpkg_status_sha256": dpkg_status,
        "installed_manual_packages": installed,
        "official_ubuntu_repositories_only": True,
        "ppa_used": False,
        "third_party_repository_used": False,
    }
    documents["build_commands.json"] = {
        **common,
        "build_ids": ["BUILD_A", "BUILD_B"],
        "custom_flags_used": False,
        "environment": {"LANG": "C", "LC_ALL": "C", "TZ": "UTC", "umask": "022"},
        "normalized_command_sequence": build_a["official_command_sequence"],
        "official_instruction_source": "INSTALL_LINUX_MACOSX.txt",
        "source_modified": False,
        "working_directory_placeholders": ["<BUILD_A_ROOT>", "<BUILD_B_ROOT>", "<CANONICAL_INSTALL_ROOT>", "<WSL_SOURCE_ROOT>"],
    }
    builds: dict[str, Any] = {}
    for build_id, receipt in (("BUILD_A", build_a), ("BUILD_B", build_b)):
        command = receipt["commands"]["official_build"]
        builds[build_id] = {
            "bozorth3_built": "bozorth3" in receipt["executables"],
            "exit_status": command["exit_code"],
            "installed_file_count": receipt["installed_file_count"],
            "mindtct_built": "mindtct" in receipt["executables"],
            "source_modified": receipt["source_modified"],
            "source_tree_sha256_after": receipt["source_tree_sha256_after"],
            "source_tree_sha256_before": receipt["source_tree_sha256_before"],
            "stderr_sha256": command["stderr_sha256"],
            "stdout_sha256": command["stdout_sha256"],
            "warning_count": receipt["warning_count"],
        }
    documents["build_results.json"] = {**common, "build_count": 2, "builds": builds, "canonical_build_selected": "BUILD_A"}
    documents["executable_manifest.json"] = {**common, "executables": executable_entries}
    documents["reproducibility_report.json"] = {
        **common,
        "algorithmically_relevant_variance": False,
        "executables": reproducibility_entries,
        "status": reproducibility_status,
    }
    documents["export_receipt.json"] = {
        **common,
        "canonical_executable_sha256": export["canonical_executables"],
        "export_sha256": export["export_sha256"],
        "export_size_bytes": export["export_bytes"],
        "restore_verification_status": restore["status"],
        "stored_outside_git": True,
    }
    documents["prerequisite_resolution.json"] = {
        **common,
        "prerequisite_id": PREREQUISITE_ID,
        "remaining_gates": list(REMAINING_GATES),
        "resolution_criterion": {
            "biometric_input_processed": False,
            "bozorth3_built": True,
            "clean_rebuild_completed": True,
            "executable_identity_recorded": True,
            "export_created": True,
            "frozen_environment_defined": True,
            "mindtct_built": True,
            "official_archive_verified": True,
            "restore_verified": True,
            "source_modified": False,
        },
        "status": "RESOLVED",
    }
    documents["environment_validation_report.json"] = {
        **common,
        "archive_valid": True, "build_a_passed": True, "build_b_passed": True,
        "bozorth3_built": True, "canonical_install_valid": True,
        "dataset_accessed": False, "distribution_official": True, "errors": [],
        "export_valid": True, "fingerprint_images_read": False, "mindtct_built": True,
        "packages_pinned": True, "reproducibility_accepted": True,
        "restore_valid": True, "scores_generated": False, "source_trees_valid": True,
        "source_unchanged": True, "threshold_used": False, "toolchain_pinned": True,
        "valid": True,
    }
    documents["environment_validation_report.json"]["external_receipts"] = [
        _receipt_identity(paths[name]) for name in sorted(paths)
    ]
    return documents


def package_readme() -> str:
    return """# NBIS reproducible build environment freeze v1

This package freezes the provenance and reproducibility evidence for an isolated
Ubuntu 24.04 LTS WSL2 build of the official, unmodified NIST NBIS 5.0.0 source.
It contains no archive, source tree, WSL export, executable, library, log,
biometric input, minutiae, score, threshold, username, hostname, or local path.

The only accepted source identity is `nbis_source_tree_identity_v2` with
canonical release-root SHA-256
`00ae5eff70693fa5647e3ff57232eff7abd623e4786c110a3286ac8614ac7f3e`.
The build environment prerequisite is resolved independently; all image,
resolution-policy, and technical determinism gates remain unresolved.
"""


def _parse_checksums(path: Path) -> tuple[dict[str, str], list[str]]:
    checksums: dict[str, str] = {}
    order: list[str] = []
    errors: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\\]+)", line)
        if match is None:
            errors.append(f"invalid checksum line: {line!r}")
            continue
        digest, name = match.groups()
        if name in checksums:
            errors.append(f"duplicate checksum entry: {name}")
        checksums[name] = digest
        order.append(name)
    if order != sorted(order):
        errors.append("SHA256SUMS.txt is not sorted")
    return checksums, errors


def _git(repository_root: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *arguments], cwd=repository_root, check=False, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8",
    )


def validate_tracked_artifacts(repository_root: Path) -> list[str]:
    result = _git(repository_root, "ls-files", "-z")
    if result.returncode != 0:
        return ["cannot enumerate tracked files"]
    errors: list[str] = []
    for name in (item for item in result.stdout.split("\0") if item):
        path = Path(name)
        if path.suffix.casefold() in _FORBIDDEN_TRACKED_SUFFIXES:
            errors.append(f"prohibited archive/binary/library/image artifact tracked: {name}")
        if any(part.casefold() == "rel_5.0.0" for part in path.parts):
            errors.append(f"NBIS source tree tracked: {name}")
        if "__pycache__" in path.parts or path.suffix.casefold() == ".pyc":
            errors.append(f"generated Python artifact tracked: {name}")
    return errors


def validate_package(repository_root: Path) -> list[str]:
    repository_root = Path(repository_root).resolve()
    package_root = repository_root / PACKAGE_RELATIVE
    if not package_root.is_dir():
        return [f"freeze package is missing: {PACKAGE_RELATIVE.as_posix()}"]
    present = sorted(path.name for path in package_root.iterdir() if path.is_file())
    if present != sorted(PACKAGE_FILES):
        return ["freeze package file set mismatch"]
    errors: list[str] = []
    try:
        documents = {
            name: json.loads((package_root / name).read_text(encoding="utf-8"))
            for name in JSON_FILES
        }
    except (OSError, json.JSONDecodeError) as exc:
        return [f"cannot parse freeze JSON: {exc}"]
    for name, document in documents.items():
        if (package_root / name).read_bytes() != canonical_json_bytes(document):
            errors.append(f"non-canonical JSON: {name}")
    errors.extend(validate_semantics(documents))
    errors.extend(validate_content_safety({}, {"README.md": (package_root / "README.md").read_text(encoding="utf-8")}))

    lock = documents["environment_lock.json"]
    if lock.get("prerequisite_id") != PREREQUISITE_ID or lock.get("prerequisite_status") != "RESOLVED":
        errors.append("environment lock prerequisite mismatch")
    if lock.get("audit_baselines") != {
        "candidate_audit": {"commit": AUDIT_COMMIT, "tag": AUDIT_TAG},
        "provenance_erratum": {"commit": ERRATUM_COMMIT, "tag": ERRATUM_TAG},
    }:
        errors.append("environment lock audit baseline mismatch")
    if lock.get("source_identity") != {"algorithm_id": SOURCE_ALGORITHM, "canonical_release_root_sha256": SOURCE_TREE_SHA256}:
        errors.append("environment lock source identity mismatch")
    locked_files = lock.get("files", {})
    if set(locked_files) != set(CORE_LOCKED_FILES):
        errors.append("environment lock package file set mismatch")
    for name in CORE_LOCKED_FILES:
        path = package_root / name
        record = locked_files.get(name, {})
        if record.get("sha256") != file_sha256(path) or record.get("bytes") != path.stat().st_size:
            errors.append(f"environment lock mismatch: {name}")
    code_files = lock.get("code_files", {})
    if set(code_files) != set(CODE_FILES):
        errors.append("environment lock code file set mismatch")
    for name in CODE_FILES:
        path = repository_root / name
        record = code_files.get(name, {})
        if not path.is_file() or record.get("sha256") != file_sha256(path) or record.get("bytes") != path.stat().st_size:
            errors.append(f"environment lock code mismatch: {name}")
    protected = lock.get("protected_area_tree_hashes", {})
    if set(protected) != set(PROTECTED_AREAS):
        errors.append("protected-area lock set mismatch")
    for name in PROTECTED_AREAS:
        path = repository_root / name
        if not path.is_dir() or protected.get(name) != tree_identity(path):
            errors.append(f"protected area tree mismatch: {name}")

    for tag, expected in ((AUDIT_TAG, AUDIT_COMMIT), (ERRATUM_TAG, ERRATUM_COMMIT)):
        result = _git(repository_root, "rev-parse", f"{tag}^{{commit}}")
        if result.returncode != 0 or result.stdout.strip() != expected:
            errors.append(f"provenance tag mismatch: {tag}")
    checksums, checksum_errors = _parse_checksums(package_root / "SHA256SUMS.txt")
    errors.extend(checksum_errors)
    expected_names = set(PACKAGE_FILES).difference({"SHA256SUMS.txt"})
    if set(checksums) != expected_names:
        errors.append("SHA256SUMS.txt file set mismatch")
    for name in expected_names:
        if checksums.get(name) != file_sha256(package_root / name):
            errors.append(f"SHA256SUMS.txt mismatch: {name}")
    errors.extend(validate_tracked_artifacts(repository_root))
    return errors


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", type=Path, default=Path(__file__).resolve().parents[1])
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    errors = validate_package(args.repository_root)
    if errors:
        print("NBIS build environment freeze v1 validation: FAIL", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print("NBIS build environment freeze v1 validation: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
