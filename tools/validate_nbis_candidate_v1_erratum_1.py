"""Read-only, archive-independent validation for NBIS candidate erratum 1.

This validator uses only the Python standard library.  It does not download,
extract, build, or execute NBIS and does not read datasets or matcher outputs.
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


ERRATUM_ID = "nbis_candidate_v1_erratum_1"
ERRATUM_VERSION = 1
PACKAGE_RELATIVE = Path("audits") / ERRATUM_ID
PACKAGE_FILES = (
    "README.md",
    "SHA256SUMS.txt",
    "corrected_source_identity.json",
    "erratum.json",
    "erratum_lock.json",
    "erratum_validation_report.json",
    "external_evidence_registry.json",
    "impact_assessment.json",
    "reconciliation_summary.json",
)
CORE_LOCKED_FILES = tuple(
    name for name in PACKAGE_FILES if name not in {"erratum_lock.json", "SHA256SUMS.txt"}
)
JSON_FILES = tuple(name for name in PACKAGE_FILES if name.endswith(".json"))
CODE_FILES = (
    "tools/recompute_nbis_source_tree_identity_v2.py",
    "tools/validate_nbis_candidate_v1_erratum_1.py",
    "tests/test_nbis_candidate_v1_erratum_1.py",
)
ORIGINAL_AUDIT_PATHS = (
    "audits/nbis_candidate_v1",
    "tools/validate_nbis_candidate_audit_v1.py",
    "tests/test_nbis_candidate_audit_v1.py",
)
ORIGINAL_AUDIT_COMMIT = "6a14e4c1a960494bc2e1a8a9c351790f6cc2d571"
ORIGINAL_AUDIT_TAG = "nbis-candidate-audit-v1"
ARCHIVE_SHA256 = "0adf8ab0f6b0e4208de50ca00ba21d3d77112ecd66288757ddfed21f6bee92c3"
ARCHIVE_SIZE = 52_595_795
FILE_COUNT = 3_879
CANONICAL_TREE_SHA256 = "00ae5eff70693fa5647e3ff57232eff7abd623e4786c110a3286ac8614ac7f3e"
LAYOUT_TREE_SHA256 = "1338ea21b50a084ec4d724449af226b129aedaf70a184109590f7cb64251d2d8"
MINDTCT_TREE_SHA256 = "6271302a7a049102d7cc0fa078d2d393cbd3647d6cc59c037bf71d915e51ed2f"
BOZORTH3_TREE_SHA256 = "ae2ac6cefee221a62716d941498d64e06e39eb60716936243459756cb5cb1ef8"
NON_REPRODUCIBLE_V1_HASH = "058aeb4638644f998109371c821acb75649d39ee411429fef268f6e4c1ae5bc9"
PREREQUISITES = {
    "NBIS_BUILD_ENVIRONMENT_FREEZE_V1",
    "NBIS_1000_PPI_DOWNSAMPLER_CONFORMANCE_V1",
    "NBIS_2000_PPI_PREPROCESSING_POLICY_V1",
    "NBIS_TECHNICAL_DETERMINISM_PROBE_V1",
}
EXTERNAL_EVIDENCE = {
    "reconciliation-report.json": (
        "reconciliation_report", 5287,
        "c66dd63e5002b3457c1ea8e984d3f2a3633402ae34331d6a21bf2ddaff79feef",
    ),
    "diff-summary.json": (
        "diff_summary", 5487,
        "28177cbed1a6f2da80862e5c4718f3fb31366b26b143f8f3dcc7e910cd36225d",
    ),
    "first-20-path-only-differences.txt": (
        "first_20_path_only_differences", 4367,
        "0a010207fd3282b5dcb30b50d42dfbee3ad5bde326e523eaa8543c32f2abdd98",
    ),
    "zip-direct-prefix-included.manifest.txt": (
        "zip_direct_prefix_included_manifest", 528891, LAYOUT_TREE_SHA256,
    ),
    "zip-direct-prefix-stripped.manifest.txt": (
        "zip_direct_prefix_stripped_manifest", 490101, CANONICAL_TREE_SHA256,
    ),
    "clean-extraction-parent-root.manifest.txt": (
        "clean_extraction_parent_root_manifest", 528891, LAYOUT_TREE_SHA256,
    ),
    "clean-extraction-rel-root.manifest.txt": (
        "clean_extraction_rel_root_manifest", 490101, CANONICAL_TREE_SHA256,
    ),
}
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_WINDOWS_ABSOLUTE = re.compile(r"(?i)(?:^|[\s\"'`(])[a-z]:[\\/]")
_POSIX_LOCAL_ABSOLUTE = re.compile(r"(?i)(?:^|[\s\"'`(])/(?:home|root|tmp|users|mnt)/")
_HOSTNAME_VALUE = re.compile(r"(?i)\b(?:desktop|laptop|win)-[a-z0-9-]{3,}\b")
_LOCAL_ID_KEYS = {"hostname", "host_name", "username", "user_name", "user"}
_FORBIDDEN_DATA_KEYS = {
    "cohort_subject", "cohort_subject_id", "image_path", "image_paths",
    "minutiae", "raw_score", "raw_scores", "score_payload", "threshold",
}
_FORBIDDEN_TRACKED_SUFFIXES = {
    ".a", ".bmp", ".brw", ".dll", ".exe", ".gz", ".jpeg", ".jpg",
    ".min", ".o", ".png", ".so", ".tar", ".tgz", ".wsq", ".xyt", ".zip",
}


def canonical_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode("utf-8")


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _walk(value: Any, path: tuple[str, ...] = ()) -> Iterable[tuple[tuple[str, ...], Any]]:
    yield path, value
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _walk(child, path + (str(key),))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk(child, path + (str(index),))


def validate_content_safety(
    documents: dict[str, Any], text_files: dict[str, str] | None = None
) -> list[str]:
    errors: list[str] = []
    for name, document in documents.items():
        for path, value in _walk(document):
            key = path[-1].casefold() if path else ""
            if key in _LOCAL_ID_KEYS:
                errors.append(f"local username/hostname field is prohibited: {name}:{'.'.join(path)}")
            if key in _FORBIDDEN_DATA_KEYS and value not in (None, False, [], {}):
                errors.append(f"dataset/image/score material is prohibited: {name}:{'.'.join(path)}")
            if isinstance(value, str):
                if _WINDOWS_ABSOLUTE.search(value) or _POSIX_LOCAL_ABSOLUTE.search(value):
                    errors.append(f"absolute local path is prohibited: {name}:{'.'.join(path)}")
                if _HOSTNAME_VALUE.search(value):
                    errors.append(f"hostname-like value is prohibited: {name}:{'.'.join(path)}")
    for name, value in (text_files or {}).items():
        if _WINDOWS_ABSOLUTE.search(value) or _POSIX_LOCAL_ABSOLUTE.search(value):
            errors.append(f"absolute local path is prohibited in text file: {name}")
        if _HOSTNAME_VALUE.search(value):
            errors.append(f"hostname-like value is prohibited in text file: {name}")
    return errors


def _expect(document: dict[str, Any], key: str, expected: Any, label: str, errors: list[str]) -> None:
    if document.get(key) != expected:
        errors.append(f"{label} mismatch: {key}")


def validate_semantics(documents: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    required = set(JSON_FILES).difference({"erratum_lock.json"})
    missing = sorted(required.difference(documents))
    if missing:
        return [f"missing JSON document: {name}" for name in missing]
    for name, document in documents.items():
        if document.get("erratum_id") != ERRATUM_ID or document.get("erratum_version") != ERRATUM_VERSION:
            errors.append(f"erratum identity mismatch: {name}")

    erratum = documents["erratum.json"]
    expected_erratum = {
        "affected_field": "source_tree_sha256",
        "archive_layout_diagnostic_value": LAYOUT_TREE_SHA256,
        "canonical_algorithm_id": "nbis_source_tree_identity_v2",
        "corrected_value": CANONICAL_TREE_SHA256,
        "future_use_of_original_value_prohibited": True,
        "original_audit_commit": ORIGINAL_AUDIT_COMMIT,
        "original_audit_id": "nbis_candidate_v1",
        "original_audit_tag": ORIGINAL_AUDIT_TAG,
        "original_hash_root_cause": "NOT_RECOVERED",
        "original_value": NON_REPRODUCIBLE_V1_HASH,
        "original_value_status": "NON_REPRODUCIBLE",
        "scientific_verdict_changed": False,
        "severity": "PROVENANCE_BLOCKING",
    }
    for key, expected in expected_erratum.items():
        _expect(erratum, key, expected, "erratum", errors)

    identity = documents["corrected_source_identity.json"]
    expected_identity = {
        "archive_layout_tree_sha256": LAYOUT_TREE_SHA256,
        "bozorth3_subtree_sha256": BOZORTH3_TREE_SHA256,
        "canonical_release_root_tree_sha256": CANONICAL_TREE_SHA256,
        "file_count": FILE_COUNT,
        "independent_methods_agree": True,
        "mindtct_subtree_sha256": MINDTCT_TREE_SHA256,
    }
    for key, expected in expected_identity.items():
        _expect(identity, key, expected, "corrected identity", errors)
    archive = identity.get("official_archive", {})
    for key, expected in {
        "filename": "nbis_v5_0_0.zip", "release": "NIST NBIS Release 5.0.0",
        "sha256": ARCHIVE_SHA256, "size_bytes": ARCHIVE_SIZE,
    }.items():
        _expect(archive, key, expected, "official archive", errors)
    algorithm = identity.get("algorithm", {})
    algorithm_rules = {
        "algorithm_id": "nbis_source_tree_identity_v2",
        "directory_entries_included": False,
        "duplicate_normalized_paths_allowed": False,
        "final_newline_required": True,
        "manifest_encoding": "UTF-8 without BOM",
        "path_separator": "forward slash",
        "path_sort": "ordinal case-sensitive by normalized relative path",
        "record_format": "<file_sha256>  <byte_size>  <relative_path>\\n",
        "top_level_prefix_action": "remove exactly Rel_5.0.0/ from every file entry",
    }
    for key, expected in algorithm_rules.items():
        _expect(algorithm, key, expected, "canonical algorithm", errors)
    for method in ("zip_direct_reproduction", "clean_extraction_reproduction"):
        reproduction = identity.get(method, {})
        if reproduction != {
            "archive_layout_tree_sha256": LAYOUT_TREE_SHA256,
            "canonical_release_root_tree_sha256": CANONICAL_TREE_SHA256,
            "status": "PASS",
        }:
            errors.append(f"independent reproduction mismatch: {method}")

    reconciliation = documents["reconciliation_summary.json"]
    if reconciliation.get("differences") != {
        "content": 0, "extra": 0, "missing": 0, "path_only": FILE_COUNT, "size": 0,
    }:
        errors.append("reconciliation differences mismatch")
    original_identity = reconciliation.get("original_locked_identity", {})
    if original_identity != {"sha256": NON_REPRODUCIBLE_V1_HASH, "status": "NON_REPRODUCIBLE"}:
        errors.append("original locked identity status mismatch")
    results = reconciliation.get("results", [])
    expected_results = [
        ("ZIP direct", True, "archive extraction parent", LAYOUT_TREE_SHA256),
        ("ZIP direct", False, "Rel_5.0.0", CANONICAL_TREE_SHA256),
        ("clean extraction", True, "extraction parent", LAYOUT_TREE_SHA256),
        ("clean extraction", False, "Rel_5.0.0", CANONICAL_TREE_SHA256),
    ]
    actual_results = [
        (item.get("method"), item.get("prefix_included"), item.get("root_scope"), item.get("tree_sha256"))
        for item in results if item.get("file_count") == FILE_COUNT
    ]
    if actual_results != expected_results or len(results) != 4:
        errors.append("reconciliation method results mismatch")

    impact = documents["impact_assessment.json"]
    for key, expected in {
        "audit_verdict": "SUITABLE_WITH_PREREQUISITES",
        "archive_provenance_remains_valid": True,
        "biometric_data_affected": False,
        "build_authorization_remains_blocked_until_erratum_is_frozen": True,
        "original_audit_verdict": "SUITABLE_WITH_PREREQUISITES",
        "ppi_findings_changed": False,
        "score_affected": False,
        "source_inspection_findings_remain_valid": True,
        "sourceafis_artifact_affected": False,
        "subtree_evidence_remains_valid": True,
        "verdict_changed": False,
        "source_contents_changed": False,
        "no_prerequisite_resolved_by_erratum": True,
        "blocking_prerequisites_changed": False,
    }.items():
        _expect(impact, key, expected, "impact assessment", errors)
    prerequisites = impact.get("remaining_prerequisites", [])
    if {item.get("prerequisite_id") for item in prerequisites} != PREREQUISITES or any(
        item.get("status") != "UNRESOLVED" for item in prerequisites
    ):
        errors.append("remaining prerequisite set/status mismatch")

    registry = documents["external_evidence_registry.json"].get("evidence", [])
    if len(registry) != len(EXTERNAL_EVIDENCE):
        errors.append("external evidence count mismatch")
    registry_by_name = {item.get("filename"): item for item in registry}
    if set(registry_by_name) != set(EXTERNAL_EVIDENCE):
        errors.append("external evidence filename set mismatch")
    for filename, (label, size, digest) in EXTERNAL_EVIDENCE.items():
        item = registry_by_name.get(filename, {})
        if item.get("label") != label or item.get("bytes") != size or item.get("sha256") != digest:
            errors.append(f"external evidence identity mismatch: {filename}")
        if item.get("absolute_path_recorded") is not False or item.get("stored_outside_git") is not True:
            errors.append(f"external evidence storage declaration mismatch: {filename}")

    report = documents["erratum_validation_report.json"]
    if report.get("valid") is not True or report.get("errors") != []:
        errors.append("erratum validation report is not a clean PASS")
    report_claims = {
        "archive_identity_verified": True,
        "archive_layout_identity_verified": True,
        "canonical_identity_verified": True,
        "external_evidence_locked": True,
        "independent_methods_agree": True,
        "original_audit_package_unchanged": True,
        "original_audit_tag_unchanged": True,
        "original_hash_prohibited": True,
        "prerequisites_resolved": False,
        "scientific_verdict_changed": False,
    }
    if any(report.get(key) != expected for key, expected in report_claims.items()):
        errors.append("validation report claim mismatch")
    if report.get("ci_mode") != {
        "archive_required": False, "dataset_required": False,
        "network_required": False, "wsl_required": False,
    }:
        errors.append("CI mode is not archive/dataset/network/WSL independent")

    accepted_hash_keys = {
        "corrected_value", "canonical_release_root_tree_sha256", "tree_sha256",
        "archive_layout_diagnostic_value", "archive_layout_tree_sha256",
        "mindtct_subtree_sha256", "bozorth3_subtree_sha256",
    }
    for name, document in documents.items():
        for path, value in _walk(document):
            if value == NON_REPRODUCIBLE_V1_HASH and path and path[-1] in accepted_hash_keys:
                errors.append(f"non-reproducible v1 hash used as an accepted identity: {name}:{'.'.join(path)}")
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


def _git(repository_root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args], cwd=repository_root, check=False, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8",
    )


def validate_original_audit_immutability(repository_root: Path) -> list[str]:
    errors: list[str] = []
    tag = _git(repository_root, "rev-parse", f"{ORIGINAL_AUDIT_TAG}^{{commit}}")
    if tag.returncode != 0 or tag.stdout.strip() != ORIGINAL_AUDIT_COMMIT:
        errors.append("original audit tag target mismatch")
    diff = _git(repository_root, "diff", "--quiet", ORIGINAL_AUDIT_COMMIT, "--", *ORIGINAL_AUDIT_PATHS)
    if diff.returncode != 0:
        errors.append("original audit package or validators changed since the locked commit")
    return errors


def validate_tracked_artifacts(repository_root: Path) -> list[str]:
    errors: list[str] = []
    result = _git(repository_root, "ls-files", "-z")
    if result.returncode != 0:
        return ["cannot enumerate tracked files"]
    tracked = [item for item in result.stdout.split("\0") if item]
    for name in tracked:
        path = Path(name)
        lower = name.casefold()
        if path.suffix.casefold() in _FORBIDDEN_TRACKED_SUFFIXES:
            errors.append(f"prohibited archive/binary/image artifact tracked: {name}")
        if lower.endswith(".manifest") or lower.endswith(".manifest.txt"):
            errors.append(f"full source manifest tracked: {name}")
        if any(part.casefold() == "rel_5.0.0" for part in path.parts):
            errors.append(f"NBIS source tree tracked: {name}")
    return errors


def validate_package(repository_root: Path) -> list[str]:
    repository_root = Path(repository_root).resolve()
    package_root = repository_root / PACKAGE_RELATIVE
    if not package_root.is_dir():
        return [f"erratum package is missing: {PACKAGE_RELATIVE.as_posix()}"]
    present = sorted(path.name for path in package_root.iterdir() if path.is_file())
    if present != sorted(PACKAGE_FILES):
        return ["erratum package file set mismatch"]

    errors: list[str] = []
    try:
        documents = {
            name: json.loads((package_root / name).read_text(encoding="utf-8"))
            for name in JSON_FILES
        }
    except (OSError, json.JSONDecodeError) as exc:
        return [f"cannot parse erratum JSON: {exc}"]
    for name, document in documents.items():
        if (package_root / name).read_bytes() != canonical_json_bytes(document):
            errors.append(f"non-canonical JSON: {name}")
    errors.extend(validate_semantics(documents))
    errors.extend(validate_content_safety({}, {
        "README.md": (package_root / "README.md").read_text(encoding="utf-8"),
    }))

    lock = documents["erratum_lock.json"]
    if lock.get("original_audit") != {
        "commit": ORIGINAL_AUDIT_COMMIT, "tag": ORIGINAL_AUDIT_TAG,
        "tag_target": ORIGINAL_AUDIT_COMMIT,
    }:
        errors.append("original audit lock mismatch")
    if lock.get("corrected_identity") != {
        "algorithm_id": "nbis_source_tree_identity_v2",
        "archive_sha256": ARCHIVE_SHA256,
        "archive_size_bytes": ARCHIVE_SIZE,
        "archive_layout_tree_sha256": LAYOUT_TREE_SHA256,
        "canonical_release_root_tree_sha256": CANONICAL_TREE_SHA256,
        "file_count": FILE_COUNT,
    }:
        errors.append("corrected identity lock mismatch")
    locked_files = lock.get("files", {})
    if set(locked_files) != set(CORE_LOCKED_FILES):
        errors.append("erratum lock package file set mismatch")
    for name in CORE_LOCKED_FILES:
        path = package_root / name
        record = locked_files.get(name, {})
        if record.get("sha256") != file_sha256(path) or record.get("bytes") != path.stat().st_size:
            errors.append(f"erratum lock mismatch: {name}")
    code_files = lock.get("code_files", {})
    if set(code_files) != set(CODE_FILES):
        errors.append("erratum lock code file set mismatch")
    for name in CODE_FILES:
        path = repository_root / name
        record = code_files.get(name, {})
        if not path.is_file() or record.get("sha256") != file_sha256(path) or record.get("bytes") != path.stat().st_size:
            errors.append(f"erratum lock code hash mismatch: {name}")
    tracking = lock.get("artifact_tracking", {})
    for key in (
        "archive_tracked", "binary_tracked", "dataset_tracked", "full_manifest_tracked",
        "image_tracked", "minutiae_tracked", "raw_score_tracked", "source_tree_tracked",
    ):
        if tracking.get(key) is not False:
            errors.append(f"prohibited tracked artifact state: {key}")

    checksums, checksum_errors = _parse_checksums(package_root / "SHA256SUMS.txt")
    errors.extend(checksum_errors)
    expected_checksum_names = set(PACKAGE_FILES).difference({"SHA256SUMS.txt"})
    if set(checksums) != expected_checksum_names:
        errors.append("SHA256SUMS.txt file set mismatch")
    for name in sorted(expected_checksum_names):
        if checksums.get(name) != file_sha256(package_root / name):
            errors.append(f"SHA256SUMS.txt mismatch: {name}")

    errors.extend(validate_original_audit_immutability(repository_root))
    errors.extend(validate_tracked_artifacts(repository_root))
    return errors


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repository-root", type=Path, default=Path(__file__).resolve().parents[1],
        help="repository root; defaults to the validator's parent repository",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    errors = validate_package(args.repository_root)
    if errors:
        print("NBIS candidate audit erratum 1 validation: FAIL", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print("NBIS candidate audit erratum 1 validation: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
