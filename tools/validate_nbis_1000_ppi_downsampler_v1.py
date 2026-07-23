"""Read-only validation for the NBIS 1000 PPI downsampler audit v1.

The validator is standard-library only, network-independent, dataset-independent,
and does not invoke WSL or any NBIS executable.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse


AUDIT_ID = "nbis_1000_ppi_downsampler_v1"
PREREQUISITE_ID = "NBIS_1000_PPI_DOWNSAMPLER_CONFORMANCE_V1"
PACKAGE_RELATIVE = Path("preprocessing") / AUDIT_ID
PACKAGE_FILES = (
    "README.md",
    "SHA256SUMS.txt",
    "audit_plan.json",
    "certification_status.json",
    "conformance_results.json",
    "determinism_results.json",
    "implementation_identity.json",
    "isolation_incidents.json",
    "official_sources.json",
    "preprocessing_lock.json",
    "prerequisite_resolution.json",
    "reference_implementation_audit.json",
    "risks_and_open_questions.json",
    "specification_matrix.json",
    "synthetic_vectors.json",
    "validation_report.json",
)
JSON_FILES = tuple(name for name in PACKAGE_FILES if name.endswith(".json"))
CONTENT_FILES = tuple(
    name for name in PACKAGE_FILES if name not in {"preprocessing_lock.json", "SHA256SUMS.txt"}
)
CHECKSUM_FILES = tuple(name for name in PACKAGE_FILES if name != "SHA256SUMS.txt")
BASE_TAGS = {
    "nbis-candidate-audit-v1": "6a14e4c1a960494bc2e1a8a9c351790f6cc2d571",
    "nbis-candidate-audit-v1-erratum1": "d5f8122a1b76ff79556d909155f8e3b586adcabc",
    "nbis-build-environment-v1": "1cf80004da1be06cd626c2a60535a7d104648360",
}
SOURCE_ALGORITHM = "nbis_source_tree_identity_v2"
SOURCE_TREE_SHA256 = "00ae5eff70693fa5647e3ff57232eff7abd623e4786c110a3286ac8614ac7f3e"
EXECUTABLE_HASHES = {
    "mindtct": "8b08c10d0f6e2c6250a9254224e0b7258e6eab60a28a1c48095618c0af7e4d33",
    "bozorth3": "b0fd7639307c2aee939fd48de3f79bbec3d14bc4d525223407d213a68caaac7a",
}
PROHIBITED_OLD_HASH = "058aeb4638644f998109371c821acb75649d39ee411429fef268f6e4c1ae5bc9"
EXPECTED_REPORTS = {"NISTIR 7839", "NIST SP 500-289", "NIST SP 500-306"}
ALLOWED_SPEC_STATUSES = {
    "EXPLICIT", "DERIVED_UNAMBIGUOUSLY", "INFORMATIVE_ONLY", "CONFLICTING", "NOT_SPECIFIED",
}
AMBIGUOUS_SPEC_STATUSES = {"INFORMATIVE_ONLY", "CONFLICTING", "NOT_SPECIFIED"}
PIXEL_SEMANTIC_FIELDS = (
    "gaussian_sigma",
    "filter_radius",
    "kernel_dimensions",
    "coefficient_generation_formula",
    "kernel_separability",
    "normalization_rule",
    "coefficient_precision",
    "numeric_representation",
    "accumulation_precision",
    "intermediate_rounding",
    "output_rounding",
    "clipping_or_saturation",
    "border_extension_rule",
    "corner_handling",
    "repeated_edge_vs_reflection",
    "mirrored_pixel_semantics",
    "decimation_order",
    "row_parity",
    "column_parity",
    "coordinate_origin",
    "filter_before_decimation",
    "output_width",
    "output_height",
    "even_input_dimensions",
    "odd_input_dimensions",
    "input_smaller_than_kernel",
    "accepted_bit_depth",
    "accepted_color_model",
    "output_bit_depth",
    "output_ppi_metadata",
    "png_metadata_treatment",
    "alpha_channel_treatment",
    "compression_scope",
    "jpeg2000_relationship",
    "conformance_metric",
    "conformance_tolerance",
    "certification_submission_procedure",
    "certification_pathway_availability",
)
CRITICAL_PIXEL_SEMANTICS = {
    "coefficient_precision",
    "normalization_rule",
    "border_extension_rule",
    "output_rounding",
    "clipping_or_saturation",
    "row_parity",
    "column_parity",
    "odd_input_dimensions",
}
REQUIRED_VECTOR_PURPOSES = {
    "all_zeros", "all_255", "constant_mid_gray", "impulse_center",
    "impulse_top_left", "impulse_top_right", "impulse_bottom_left", "impulse_bottom_right",
    "impulse_adjacent_top", "impulse_adjacent_bottom", "impulse_adjacent_left",
    "impulse_adjacent_right", "horizontal_gradient", "vertical_gradient",
    "two_dimensional_gradient", "horizontal_alternating_stripes",
    "vertical_alternating_stripes", "checkerboard", "isolated_zero_in_255",
    "isolated_255_in_zero", "clipping_sensitive", "rounding_half_sensitive",
    "kernel_sized_9x9", "smaller_than_kernel", "even_width_even_height",
    "odd_width_odd_height", "even_width_odd_height", "odd_width_even_height",
    "dimensions_1_through_12", "deterministic_pseudorandom", "parity_sensitive",
    "border_sensitive",
}
REQUIRED_SEEDS = [0, 1, 7839, 500289, 500306]
PROTECTED_AREAS = (
    "audits/nbis_candidate_v1",
    "audits/nbis_candidate_v1_erratum_1",
    "environments/nbis_build_environment_v1",
    "protocols",
    "qualification",
    "policies",
    "executions",
    "evaluations",
    "migration",
    "migration-audit",
    "apps/sourceafis-sidecar",
)
FORBIDDEN_TRACKED_SUFFIXES = {
    ".7z", ".a", ".bmp", ".brw", ".dll", ".exe", ".gz", ".jpeg", ".jpg",
    ".min", ".pdf", ".png", ".so", ".tar", ".tgz", ".tif", ".tiff", ".wsq",
    ".xyt", ".zip",
}
FORBIDDEN_DEPENDENCIES = {"cv2", "opencv", "pillow", "pil", "scipy", "numpy", "skimage"}
CODE_FILES = (
    ".github/workflows/ci.yml",
    "docs/nbis_1000_ppi_downsampler_v1.md",
    "tests/test_nbis_1000_ppi_downsampler_v1.py",
    "tools/audit_nbis_1000_ppi_downsampler_v1.py",
    "tools/run_nbis_1000_ppi_downsampler_tests_v1.py",
    "tools/validate_nbis_1000_ppi_downsampler_v1.py",
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_WINDOWS_ABSOLUTE = re.compile(r"(?i)(?:^|[\s\"'`(])[a-z]:[\\/]")
_POSIX_LOCAL_ABSOLUTE = re.compile(r"(?i)(?:^|[\s\"'`(])/(?:home|root|tmp|users|mnt)/")
_HOSTNAME_VALUE = re.compile(r"(?i)\b(?:desktop|laptop|win)-[a-z0-9-]{3,}\b")
_FORBIDDEN_PATH_TEXT = re.compile(r"(?i)fingerprint-datasets[\\/]nist")
_FORBIDDEN_SUBJECT = re.compile(r"(?<!\d)00001000(?!\d)")


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


def validate_content_safety(documents: dict[str, Any], text_files: dict[str, str] | None = None) -> list[str]:
    errors: list[str] = []
    forbidden_value_keys = {
        "fixture_id", "fingerprint_image", "minutiae", "raw_score", "raw_scores", "score",
        "threshold", "decision", "fmr", "fnmr", "roc", "eer",
    }
    local_identity_keys = {"hostname", "host_name", "username", "user_name", "user"}
    for name, document in documents.items():
        for path, value in _walk(document):
            key = path[-1].casefold() if path else ""
            if key in local_identity_keys:
                errors.append(f"local username/hostname field is prohibited: {name}:{'.'.join(path)}")
            if key in forbidden_value_keys and value not in (None, False, [], {}, "NOT_USED", "NOT_PERFORMED"):
                errors.append(f"biometric/matcher result field is prohibited: {name}:{'.'.join(path)}")
            if isinstance(value, str):
                if _WINDOWS_ABSOLUTE.search(value) or _POSIX_LOCAL_ABSOLUTE.search(value):
                    errors.append(f"absolute local path is prohibited: {name}:{'.'.join(path)}")
                if _HOSTNAME_VALUE.search(value):
                    errors.append(f"hostname-like value is prohibited: {name}:{'.'.join(path)}")
                if _FORBIDDEN_PATH_TEXT.search(value):
                    errors.append(f"dataset path is prohibited: {name}:{'.'.join(path)}")
                if _FORBIDDEN_SUBJECT.search(value):
                    errors.append(f"subject identifier is prohibited: {name}:{'.'.join(path)}")
                if PROHIBITED_OLD_HASH in value:
                    errors.append(f"prohibited legacy source hash is used: {name}:{'.'.join(path)}")
    for name, content in (text_files or {}).items():
        if _WINDOWS_ABSOLUTE.search(content) or _POSIX_LOCAL_ABSOLUTE.search(content):
            errors.append(f"absolute local path is prohibited in text file: {name}")
        if _HOSTNAME_VALUE.search(content):
            errors.append(f"hostname-like value is prohibited in text file: {name}")
        if _FORBIDDEN_PATH_TEXT.search(content) or _FORBIDDEN_SUBJECT.search(content):
            errors.append(f"dataset or subject material is prohibited in text file: {name}")
        if PROHIBITED_OLD_HASH in content:
            errors.append(f"prohibited legacy source hash is used in text file: {name}")
    return errors


def validate_semantics(documents: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    missing = sorted(set(JSON_FILES).difference(documents))
    if missing:
        return [f"missing JSON document: {name}" for name in missing]
    for name, document in documents.items():
        if document.get("audit_id") != AUDIT_ID:
            errors.append(f"audit_id mismatch: {name}")
        if document.get("prerequisite_id") != PREREQUISITE_ID:
            errors.append(f"prerequisite_id mismatch: {name}")

    plan = documents["audit_plan.json"]
    if plan.get("audit_version") != 1:
        errors.append("audit plan version mismatch")
    if plan.get("official_source_policy") != "NIST_OFFICIAL_ONLY":
        errors.append("official-source-only policy is not fixed")
    for flag in ("biometric_input_allowed", "dataset_access_allowed", "matcher_execution_allowed"):
        if plan.get(flag) is not False:
            errors.append(f"prohibited audit-plan permission: {flag}")
    if plan.get("fixed_random_seeds") != REQUIRED_SEEDS or plan.get("fresh_process_repetitions") != 3:
        errors.append("determinism plan mismatch")
    if set(plan.get("pixel_semantic_fields", [])) != set(PIXEL_SEMANTIC_FIELDS):
        errors.append("audit plan pixel-semantic field set mismatch")

    sources = documents["official_sources.json"]
    source_entries = sources.get("documents", [])
    if {entry.get("report_number") for entry in source_entries if isinstance(entry, dict)} != EXPECTED_REPORTS:
        errors.append("required NIST document set mismatch")
    required_source_fields = {
        "official_url", "resolved_url", "retrieval_utc", "title", "report_number",
        "publication_date", "file_size_bytes", "sha256", "page_count",
        "relevant_pages_sections", "normative_status", "official", "publisher",
    }
    for entry in source_entries:
        if not isinstance(entry, dict) or required_source_fields.difference(entry):
            errors.append("official source metadata is incomplete")
            continue
        host = urlparse(str(entry.get("official_url", ""))).hostname or ""
        resolved_host = urlparse(str(entry.get("resolved_url", ""))).hostname or ""
        if entry.get("official") is not True or not host.endswith("nist.gov") or not resolved_host.endswith("nist.gov"):
            errors.append(f"non-official source provenance: {entry.get('report_number')}")
        if entry.get("publisher") != "National Institute of Standards and Technology":
            errors.append(f"source publisher mismatch: {entry.get('report_number')}")
        if not _is_sha256(entry.get("sha256")) or not isinstance(entry.get("file_size_bytes"), int):
            errors.append(f"source identity is incomplete: {entry.get('report_number')}")
        if not isinstance(entry.get("page_count"), int) or entry.get("page_count", 0) < 1:
            errors.append(f"source page count is invalid: {entry.get('report_number')}")
        if not entry.get("relevant_pages_sections"):
            errors.append(f"source page/section evidence is missing: {entry.get('report_number')}")

    matrix = documents["specification_matrix.json"]
    fields = matrix.get("fields", {})
    if set(fields) != set(PIXEL_SEMANTIC_FIELDS):
        errors.append("specification matrix field set mismatch")
    required_evidence_fields = {
        "value", "status", "source", "page", "section", "normative_level",
        "ambiguity", "resolved", "normative_text_summary", "confidence",
        "implementation_consequence",
    }
    for field_name, record in fields.items():
        if not isinstance(record, dict) or required_evidence_fields.difference(record):
            errors.append(f"specification evidence is incomplete: {field_name}")
            continue
        if record.get("status") not in ALLOWED_SPEC_STATUSES:
            errors.append(f"invalid specification status: {field_name}")
        if record.get("status") in AMBIGUOUS_SPEC_STATUSES and record.get("resolved") is True:
            errors.append(f"ambiguous field is falsely marked resolved: {field_name}")

    reference = documents["reference_implementation_audit.json"]
    for required_bool in (
        "official_reference_searched", "official_reference_found", "used_as_oracle",
        "execution_performed", "synthetic_input_only", "third_party_oracle_used",
    ):
        if not isinstance(reference.get(required_bool), bool):
            errors.append(f"reference audit boolean is missing: {required_bool}")
    if reference.get("official_reference_searched") is not True:
        errors.append("official reference search was not completed")
    if reference.get("third_party_oracle_used") is not False:
        errors.append("third-party oracle is prohibited")
    if reference.get("used_as_oracle") is True:
        if reference.get("official_reference_found") is not True:
            errors.append("reference oracle used without an official reference")
        if reference.get("official_publisher") != "National Institute of Standards and Technology":
            errors.append("reference oracle publisher is not NIST")
        if not _is_sha256(reference.get("hash")):
            errors.append("official reference oracle identity is not locked")
    if reference.get("execution_performed") is True and reference.get("synthetic_input_only") is not True:
        errors.append("reference execution used non-synthetic input")

    resolution = documents["prerequisite_resolution.json"]
    status = resolution.get("status")
    if status not in {"RESOLVED", "UNRESOLVED"}:
        errors.append("prerequisite status is invalid")
    task_status = resolution.get("task_status")
    if task_status != "PASS":
        errors.append("task status is not PASS")
    ambiguous_critical = sorted(
        name for name in CRITICAL_PIXEL_SEMANTICS
        if fields.get(name, {}).get("status") in AMBIGUOUS_SPEC_STATUSES
        or fields.get(name, {}).get("resolved") is not True
    )
    if status == "RESOLVED" and ambiguous_critical and reference.get("used_as_oracle") is not True:
        errors.append("unresolved critical pixel semantics block RESOLVED")
    if status == "UNRESOLVED" and not ambiguous_critical:
        errors.append("UNRESOLVED lacks an unresolved critical pixel semantic")
    if sorted(resolution.get("unresolved_pixel_semantics", [])) != ambiguous_critical:
        errors.append("unresolved pixel-semantic list mismatch")

    identity = documents["implementation_identity.json"]
    if status == "UNRESOLVED":
        if identity.get("canonical_implementation_selected") is not False:
            errors.append("canonical implementation is prohibited for UNRESOLVED")
        if identity.get("source_file_sha256") is not None or identity.get("reference_implementation_sha256") is not None:
            errors.append("UNRESOLVED package contains implementation identities")
    else:
        if identity.get("canonical_implementation_selected") is not True:
            errors.append("RESOLVED lacks a canonical implementation")
        for field in (
            "implementation_id", "implementation_version", "source_file_sha256",
            "reference_implementation_sha256", "input_contract", "output_contract",
            "coefficient_identity", "border_rule", "parity_rule", "dimension_rule",
            "rounding_rule", "clipping_rule", "dependencies",
        ):
            if field not in identity or identity.get(field) in (None, ""):
                errors.append(f"resolved implementation identity is incomplete: {field}")
        for field in ("source_file_sha256", "reference_implementation_sha256"):
            if not _is_sha256(identity.get(field)):
                errors.append(f"resolved implementation hash is invalid: {field}")
        dependencies = {str(value).casefold() for value in identity.get("dependencies", [])}
        if dependencies.intersection(FORBIDDEN_DEPENDENCIES):
            errors.append("forbidden image-processing dependency is selected")

    vectors = documents["synthetic_vectors.json"]
    if vectors.get("synthetic_only") is not True or vectors.get("dataset_accessed") is not False:
        errors.append("synthetic-vector isolation is not satisfied")
    if vectors.get("fixed_seeds") != REQUIRED_SEEDS:
        errors.append("synthetic-vector seeds mismatch")
    vector_records = vectors.get("vectors", [])
    purposes = {record.get("purpose") for record in vector_records if isinstance(record, dict)}
    if not REQUIRED_VECTOR_PURPOSES.issubset(purposes):
        errors.append("synthetic-vector purpose coverage is incomplete")
    for record in vector_records:
        required = {"vector_id", "purpose", "width", "height", "input_matrix", "expected_output_matrix", "expected_source"}
        if not isinstance(record, dict) or required.difference(record):
            errors.append("synthetic vector record is incomplete")
            continue
        rows = record.get("input_matrix")
        width, height = record.get("width"), record.get("height")
        if not isinstance(rows, list) or len(rows) != height or any(not isinstance(row, list) or len(row) != width for row in rows):
            errors.append(f"synthetic vector dimensions mismatch: {record.get('vector_id')}")
        values = [value for row in rows if isinstance(row, list) for value in row]
        if any(not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 255 for value in values):
            errors.append(f"synthetic vector is not u8: {record.get('vector_id')}")
        if status == "RESOLVED" and record.get("expected_source") not in {
            "OFFICIAL_NIST_REFERENCE", "INDEPENDENT_IMPLEMENTATION_AGREEMENT", "HAND_DERIVED_EXACT_CASE",
        }:
            errors.append(f"resolved vector lacks an admissible expected source: {record.get('vector_id')}")
        if status == "UNRESOLVED" and record.get("expected_output_matrix") is not None:
            errors.append(f"unresolved vector contains a canonical expected output: {record.get('vector_id')}")

    conformance = documents["conformance_results.json"]
    for field in (
        "border_discriminating_tests_present", "parity_discriminating_tests_present",
        "odd_even_dimension_tests_present", "rounding_sensitive_tests_present",
        "clipping_sensitive_tests_present",
    ):
        if conformance.get(field) is not True:
            errors.append(f"required diagnostic test design is missing: {field}")
    if status == "UNRESOLVED" and conformance.get("execution_status") != "NOT_EXECUTED_UNRESOLVED_SPEC":
        errors.append("UNRESOLVED conformance execution status mismatch")
    if status == "RESOLVED" and conformance.get("overall_status") != "PASS":
        errors.append("RESOLVED conformance suite did not pass")

    determinism = documents["determinism_results.json"]
    if determinism.get("required_fresh_process_repetitions") != 3:
        errors.append("three-repetition determinism requirement mismatch")
    if status == "RESOLVED":
        if determinism.get("overall_status") != "PASS" or determinism.get("windows_ci_equality") != "PASS":
            errors.append("RESOLVED lacks Windows/CI determinism evidence")
    elif determinism.get("execution_performed") is not False:
        errors.append("UNRESOLVED package performed canonical determinism execution")

    certification = documents["certification_status.json"]
    if certification.get("sp_500_306_reviewed") is not True:
        errors.append("SP 500-306 review is missing")
    if certification.get("submission_performed") is not False or certification.get("certification_received") is not False:
        errors.append("unsupported NIST submission/certification claim")
    if certification.get("claim_permitted") != "LOCAL_CONFORMANCE_ONLY":
        errors.append("certification claim boundary is invalid")

    incidents = documents["isolation_incidents.json"]
    expected_incident = {
        "attempt_id": "nbis_1000_ppi_downsampler_v1_attempt_1",
        "status": "FAIL",
        "cause": "unrestricted pytest collection executed a dataset-backed protocol test",
        "dataset_accessed": True,
        "dataset_modified": False,
        "matcher_invoked": False,
        "scores_generated": False,
        "results_discarded": True,
        "used_as_audit_evidence": False,
    }
    records = incidents.get("incidents")
    if records != [expected_incident]:
        errors.append("attempt-1 isolation incident record mismatch")
    if incidents.get("current_attempt_id") != "nbis_1000_ppi_downsampler_v1_attempt_2":
        errors.append("current controlled-restart attempt identity mismatch")

    report = documents["validation_report.json"]
    if report.get("valid") is not True or report.get("errors") != [] or report.get("task_status") != "PASS":
        errors.append("validation report is not a clean PASS")
    for safety_flag in (
        "fingerprint_images_accessed", "dataset_accessed", "fixture_processed",
        "mindtct_invoked_on_image", "bozorth3_invoked", "scores_generated", "threshold_used",
    ):
        if report.get(safety_flag) is not False:
            errors.append(f"prohibited validation evidence state: {safety_flag}")

    errors.extend(validate_content_safety(documents))
    return errors


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


def _git_output(repository_root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments], cwd=repository_root, check=True, capture_output=True,
        text=True, encoding="utf-8",
    )
    return result.stdout.strip()


def validate_baseline_tags(repository_root: Path) -> list[str]:
    errors: list[str] = []
    for tag, expected in BASE_TAGS.items():
        try:
            actual = _git_output(repository_root, "rev-list", "-n", "1", tag)
        except (OSError, subprocess.CalledProcessError) as exc:
            errors.append(f"cannot resolve baseline tag {tag}: {exc}")
            continue
        if actual != expected:
            errors.append(f"baseline tag mismatch: {tag}")
    return errors


def validate_protected_trees(repository_root: Path, lock: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    recorded = lock.get("protected_area_tree_hashes", {})
    if set(recorded) != set(PROTECTED_AREAS):
        return ["protected-area lock set mismatch"]
    for relative in PROTECTED_AREAS:
        root = repository_root / Path(relative)
        if not root.is_dir() or tree_identity(root) != recorded.get(relative):
            errors.append(f"protected tree identity mismatch: {relative}")
    return errors


def validate_tracked_artifacts(repository_root: Path) -> list[str]:
    errors: list[str] = []
    try:
        tracked = _git_output(repository_root, "ls-files").splitlines()
    except (OSError, subprocess.CalledProcessError) as exc:
        return [f"cannot enumerate tracked files: {exc}"]
    for relative in tracked:
        path = Path(relative)
        if path.suffix.casefold() in FORBIDDEN_TRACKED_SUFFIXES:
            errors.append(f"prohibited binary/archive/PDF/image artifact is tracked: {relative}")
    return errors


def validate_package(repository_root: Path) -> list[str]:
    repository_root = Path(repository_root).resolve()
    package_root = repository_root / PACKAGE_RELATIVE
    if not package_root.is_dir():
        return [f"audit package is missing: {PACKAGE_RELATIVE.as_posix()}"]
    present = sorted(path.name for path in package_root.iterdir() if path.is_file())
    errors: list[str] = []
    if present != sorted(PACKAGE_FILES):
        return ["audit package file set mismatch"]
    try:
        documents = {
            name: json.loads((package_root / name).read_text(encoding="utf-8"))
            for name in JSON_FILES
        }
    except (OSError, json.JSONDecodeError) as exc:
        return [f"cannot parse audit JSON: {exc}"]
    for name, document in documents.items():
        if (package_root / name).read_bytes() != canonical_json_bytes(document):
            errors.append(f"non-canonical JSON: {name}")
    errors.extend(validate_semantics(documents))
    errors.extend(validate_content_safety({}, {
        "README.md": (package_root / "README.md").read_text(encoding="utf-8"),
    }))

    lock = documents["preprocessing_lock.json"]
    if lock.get("source_identity") != {"algorithm": SOURCE_ALGORITHM, "sha256": SOURCE_TREE_SHA256}:
        errors.append("source identity v2 mismatch")
    if lock.get("executable_identities") != EXECUTABLE_HASHES:
        errors.append("frozen executable identities mismatch")
    if lock.get("baseline_tags") != {
        tag: {"commit": commit, "tag": tag} for tag, commit in BASE_TAGS.items()
    }:
        errors.append("baseline tag lock mismatch")
    file_records = lock.get("files", {})
    if set(file_records) != set(CONTENT_FILES):
        errors.append("preprocessing lock file set mismatch")
    else:
        for name in CONTENT_FILES:
            path = package_root / name
            expected = {"bytes": path.stat().st_size, "sha256": file_sha256(path)}
            if file_records.get(name) != expected:
                errors.append(f"preprocessing lock mismatch: {name}")
    code_records = lock.get("audit_code_files", {})
    if set(code_records) != set(CODE_FILES):
        errors.append("audit code lock file set mismatch")
    else:
        for relative in CODE_FILES:
            path = repository_root / Path(relative)
            expected = {"bytes": path.stat().st_size, "sha256": file_sha256(path)}
            if code_records.get(relative) != expected:
                errors.append(f"audit code lock mismatch: {relative}")
    errors.extend(validate_protected_trees(repository_root, lock))

    checksums, checksum_errors = _parse_checksums(package_root / "SHA256SUMS.txt")
    errors.extend(checksum_errors)
    if set(checksums) != set(CHECKSUM_FILES):
        errors.append("SHA256SUMS.txt file set mismatch")
    else:
        for name in CHECKSUM_FILES:
            if checksums.get(name) != file_sha256(package_root / name):
                errors.append(f"SHA256SUMS.txt mismatch: {name}")

    status = documents["prerequisite_resolution.json"].get("status")
    canonical = repository_root / "tools" / "nbis_downsample_1000_to_500_v1.py"
    independent = repository_root / "tools" / "nbis_downsample_1000_to_500_reference_v1.py"
    if status == "UNRESOLVED" and (canonical.exists() or independent.exists()):
        errors.append("canonical/reference implementation files are prohibited for UNRESOLVED")
    if status == "RESOLVED" and (not canonical.is_file() or not independent.is_file()):
        errors.append("resolved implementation files are missing")

    errors.extend(validate_baseline_tags(repository_root))
    errors.extend(validate_tracked_artifacts(repository_root))
    return errors


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", type=Path, default=Path(__file__).resolve().parents[1])
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    errors = validate_package(arguments.repository_root)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        print("NBIS 1000 PPI downsampler audit validation: FAIL", file=sys.stderr)
        return 1
    print("NBIS 1000 PPI downsampler audit validation: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
