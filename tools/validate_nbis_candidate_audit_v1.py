"""Read-only, dataset-independent validation for the NBIS candidate audit v1.

This validator uses only the Python standard library.  It never downloads,
builds, or executes NBIS and never reads protocol images or matcher results.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse


AUDIT_ID = "nbis_candidate_v1"
PACKAGE_RELATIVE = Path("audits") / AUDIT_ID
PACKAGE_FILES = (
    "AUDIT_REPORT.md",
    "README.md",
    "SHA256SUMS.txt",
    "audit_lock.json",
    "audit_validation_report.json",
    "build_audit.json",
    "build_environment_inventory.json",
    "candidate_identity.json",
    "determinism_probe.json",
    "input_format_audit.json",
    "official_sources.json",
    "pipeline_contract.json",
    "resolution_policy_audit.json",
    "risks_and_open_questions.json",
    "source_archive.json",
)
CORE_LOCKED_FILES = tuple(
    name for name in PACKAGE_FILES if name not in {"audit_lock.json", "SHA256SUMS.txt"}
)
JSON_FILES = tuple(name for name in PACKAGE_FILES if name.endswith(".json"))
VALID_VERDICTS = {"SUITABLE", "SUITABLE_WITH_PREREQUISITES", "NOT_SUITABLE"}
REQUIRED_SOURCE_GROUPS = {
    "software_identity_sources",
    "build_sources",
    "mindtct_sources",
    "bozorth3_sources",
    "1000_ppi_sources",
    "2000_ppi_search_sources",
}
REQUIRED_PROTECTED_AREAS = {
    "protocols",
    "qualification",
    "policies",
    "executions",
    "evaluations",
    "migration",
    "migration-audit",
    "src/fingerprint_benchmark",
    "apps/sourceafis-sidecar",
}
REQUIRED_PREREQUISITE_FIELDS = {
    "prerequisite_id",
    "exact_unresolved_question",
    "why_it_blocks_integration",
    "acceptable_evidence",
    "prohibited_shortcuts",
    "recommended_next_task",
    "status",
}
FORBIDDEN_PACKAGE_SUFFIXES = {
    ".a", ".bmp", ".brw", ".dll", ".exe", ".gz", ".jpeg", ".jpg",
    ".min", ".png", ".so", ".tar", ".tgz", ".wsq", ".xyt", ".zip",
}
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_WINDOWS_ABSOLUTE = re.compile(r"(?i)(?:^|[\s\"'`(])[a-z]:[\\/]")
_POSIX_LOCAL_ABSOLUTE = re.compile(r"(?i)(?:^|[\s\"'`(])/(?:home|root|tmp|users|mnt)/")
_HOSTNAME_VALUE = re.compile(r"(?i)\b(?:desktop|laptop|win)-[a-z0-9-]{3,}\b")
_LOCAL_ID_KEYS = {"hostname", "host_name", "username", "user_name", "user"}
_FORBIDDEN_VALUE_KEYS = {"raw_score", "raw_scores", "threshold", "decision"}
_FORBIDDEN_COHORT_KEYS = {"cohort_subject", "cohort_subjects", "cohort_subject_id", "cohort_subject_ids"}


def canonical_json_bytes(value: Any) -> bytes:
    """Return the audit's deterministic JSON representation."""

    return (json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode("utf-8")


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tree_identity(root: Path) -> dict[str, Any]:
    """Compute the locked, platform-independent tree identity."""

    records: list[tuple[str, int, str]] = []
    for path in root.rglob("*"):
        generated_directory = "__pycache__" in path.parts or "target" in path.parts
        if path.is_file() and not generated_directory and path.suffix.casefold() != ".pyc":
            relative = path.relative_to(root).as_posix()
            records.append((file_sha256(path), path.stat().st_size, relative))
    records.sort(key=lambda item: item[2])
    payload = "".join(f"{digest}  {size}  {relative}\n" for digest, size, relative in records)
    return {
        "file_count": len(records),
        "sha256": hashlib.sha256(payload.encode("utf-8")).hexdigest(),
    }


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


def load_documents(package_root: Path) -> dict[str, Any]:
    return {
        name: json.loads((package_root / name).read_text(encoding="utf-8"))
        for name in JSON_FILES
    }


def validate_content_safety(documents: dict[str, Any], text_files: dict[str, str] | None = None) -> list[str]:
    errors: list[str] = []
    for name, document in documents.items():
        for path, value in _walk(document):
            key = path[-1].casefold() if path else ""
            if key in _LOCAL_ID_KEYS:
                errors.append(f"local username/hostname field is prohibited: {name}:{'.'.join(path)}")
            if key in _FORBIDDEN_VALUE_KEYS:
                errors.append(f"prohibited committed value field: {name}:{'.'.join(path)}")
            if key in _FORBIDDEN_COHORT_KEYS and value not in (None, False, [], {}):
                errors.append(f"cohort subject material is prohibited: {name}:{'.'.join(path)}")
            if isinstance(value, str):
                if _WINDOWS_ABSOLUTE.search(value) or _POSIX_LOCAL_ABSOLUTE.search(value):
                    errors.append(f"absolute local path is prohibited: {name}:{'.'.join(path)}")
                if _HOSTNAME_VALUE.search(value):
                    errors.append(f"hostname-like value is prohibited: {name}:{'.'.join(path)}")
                if "nbis.net" in value.casefold():
                    errors.append(f"NBIS.Net evidence is prohibited: {name}:{'.'.join(path)}")
    for name, text in (text_files or {}).items():
        if _WINDOWS_ABSOLUTE.search(text) or _POSIX_LOCAL_ABSOLUTE.search(text):
            errors.append(f"absolute local path is prohibited in text file: {name}")
        if _HOSTNAME_VALUE.search(text):
            errors.append(f"hostname-like value is prohibited in text file: {name}")
        if "nbis.net" in text.casefold():
            errors.append(f"NBIS.Net text is prohibited: {name}")
    return errors


def validate_semantics(documents: dict[str, Any]) -> list[str]:
    """Validate cross-document claims without needing repository or package files."""

    errors: list[str] = []
    required = set(JSON_FILES)
    missing = sorted(required.difference(documents))
    if missing:
        return [f"missing JSON document: {name}" for name in missing]

    for name, document in documents.items():
        if document.get("audit_id") != AUDIT_ID:
            errors.append(f"audit_id mismatch: {name}")

    identity = documents["candidate_identity.json"]
    candidate = identity.get("candidate", {})
    expected_candidate = {
        "name": "NIST Biometric Image Software",
        "release": "5.0.0",
        "extractor": "MINDTCT",
        "matcher": "BOZORTH3",
        "pipeline": "MINDTCT -> BOZORTH3",
        "source_type": "official_nist_release",
        "source_modified": False,
        "fork_used": False,
    }
    for key, expected in expected_candidate.items():
        if candidate.get(key) != expected:
            errors.append(f"candidate identity mismatch: {key}")
    if identity.get("audit_status") != "PASS":
        errors.append("audit status is not PASS")
    if identity.get("protocol_id") != "supervisor_50x10_v1":
        errors.append("protocol identity mismatch")
    if identity.get("dataset_releases") != {"sd300b": 1000, "sd300c": 2000}:
        errors.append("dataset release/PPI identity mismatch")
    verdict = identity.get("candidate_verdict")
    if verdict not in VALID_VERDICTS:
        errors.append("candidate verdict is invalid")

    sources = documents["official_sources.json"]
    if sources.get("official_source_only") is not True or sources.get("third_party_evidence_used") is not False:
        errors.append("official-source-only policy is not satisfied")
    groups = sources.get("source_groups", {})
    if set(groups) != REQUIRED_SOURCE_GROUPS:
        errors.append("official source groups are incomplete or unexpected")
    for group_name, entries in groups.items():
        if not isinstance(entries, list) or not entries:
            errors.append(f"official source group is empty: {group_name}")
            continue
        for entry in entries:
            parsed = urlparse(str(entry.get("official_url", "")))
            official_host = parsed.scheme == "https" and (
                parsed.hostname == "nist.gov" or str(parsed.hostname or "").endswith(".nist.gov")
            )
            if entry.get("official") is not True or not official_host:
                errors.append(f"non-official source in group: {group_name}")
            if entry.get("publisher") != "National Institute of Standards and Technology":
                errors.append(f"source publisher mismatch: {group_name}")
            if not entry.get("claims_supported") or not entry.get("limitations"):
                errors.append(f"source claim boundary missing: {group_name}")

    archive = documents["source_archive.json"]
    if archive.get("official_release_identifier") != "NIST NBIS Release 5.0.0":
        errors.append("official release identifier mismatch")
    if archive.get("source_acquired") is True and not _is_sha256(archive.get("archive_sha256")):
        errors.append("acquired archive lacks a valid SHA-256")
    if not _is_sha256(archive.get("source_tree_sha256")) or archive.get("source_file_count", 0) <= 0:
        errors.append("source tree identity is incomplete")
    for component in ("mindtct", "bozorth3"):
        subtree = archive.get("source_subtrees", {}).get(component, {})
        if not _is_sha256(subtree.get("sha256")) or subtree.get("file_count", 0) <= 0:
            errors.append(f"missing {component.upper()} source evidence")
    if archive.get("source_modified") is not False or candidate.get("source_modified") is not False:
        errors.append("modified source is prohibited")
    if archive.get("third_party_mirror_used") is not False:
        errors.append("third-party mirror is prohibited")
    if archive.get("tracked_in_git") is not False:
        errors.append("source archive or tree is recorded as tracked")

    inventory = documents["build_environment_inventory.json"]
    build = documents["build_audit.json"]
    if inventory.get("installation_performed") is not False:
        errors.append("audit installed build prerequisites")
    if build.get("source_modified") is not False:
        errors.append("build used modified source")
    if build.get("third_party_binary_used") is not False:
        errors.append("third-party binary is prohibited")
    attempted = build.get("build_attempted")
    built = build.get("mindtct_built") is True and build.get("bozorth3_built") is True
    if attempted is False:
        if build.get("exit_code") is not None or built or build.get("executable_hashes"):
            errors.append("not-run build contains success evidence")
    elif attempted is True:
        if build.get("exit_code") == 0 and not built:
            errors.append("successful build exit lacks both executables")
        if built and len(build.get("executable_hashes", {})) != 2:
            errors.append("built executables lack two identities")
    else:
        errors.append("build_attempted is not boolean")

    input_audit = documents["input_format_audit.json"]
    if not input_audit.get("verdict"):
        errors.append("input format verdict is missing")
    if input_audit.get("protocol_input_format") != "PNG":
        errors.append("protocol input format is not PNG")
    if input_audit.get("MINDTCT_direct_PNG_support") is True and not input_audit.get("evidence"):
        errors.append("direct PNG support lacks evidence")
    if input_audit.get("conversion_required") is True:
        if input_audit.get("conversion_lossless") is not True:
            errors.append("required conversion is not proven lossless")
        if input_audit.get("pixel_equivalence_verified") is not True:
            errors.append("lossless conversion lacks pixel hash equality")
    prohibited = input_audit.get("prohibited_preprocessing", {})
    for operation in ("lossy_conversion", "inversion", "enhancement", "crop", "generic_resize"):
        if prohibited.get(operation) is not False:
            errors.append(f"prohibited preprocessing enabled: {operation}")
    if input_audit.get("preprocessing_beyond_format_conversion") is not False:
        errors.append("unapproved preprocessing is recorded")

    resolution = documents["resolution_policy_audit.json"]
    records = resolution.get("records", {})
    for record_id in ("sd300b_1000_ppi", "sd300c_2000_ppi"):
        if record_id not in records:
            errors.append(f"missing resolution record: {record_id}")
    record_1000 = records.get("sd300b_1000_ppi", {})
    record_2000 = records.get("sd300c_2000_ppi", {})
    if record_2000.get("inferred_from_1000_guidance") is not False:
        errors.append("1000 PPI guidance was improperly inferred to cover 2000 PPI")
    if resolution.get("cascade_2000_to_1000_to_500_approved") is not False:
        if resolution.get("official_cascade_source_present") is not True:
            errors.append("2000-to-1000-to-500 cascade lacks an official source")
    if record_2000.get("official_guidance_found") is not True and record_2000.get("canonical_pipeline_available") is True:
        errors.append("2000 PPI canonical path lacks applicable guidance")

    pipeline = documents["pipeline_contract.json"]
    if pipeline.get("method_id") != "nbis_mindtct_bozorth3" or pipeline.get("method_version") != "5.0.0":
        errors.append("pipeline method identity mismatch")
    if pipeline.get("score_direction") != "higher_is_more_similar":
        errors.append("score direction is not established")
    if "integer raw BOZORTH3" not in str(pipeline.get("score_semantics", "")):
        errors.append("raw BOZORTH3 score semantics are missing")
    if not pipeline.get("prepare_operations") or not pipeline.get("compare_operations"):
        errors.append("full image-to-score contract is missing")

    probe = documents["determinism_probe.json"]
    if probe.get("fixture_id") != "00001000":
        errors.append("fixture identity is not restricted to 00001000")
    for field in (
        "fallback_subject_used", "frozen_cohort_subject_used", "cohort_accessed",
        "raw_scores_committed", "threshold_used", "decision_generated",
        "sourceafis_comparison_performed", "performance_comparison_performed",
    ):
        if probe.get(field) is not False:
            errors.append(f"prohibited probe state: {field}")
    if probe.get("executed") is False:
        if probe.get("image_count") != 0 or probe.get("comparison_count") != 0 or probe.get("repetitions") != 0:
            errors.append("not-run probe contains execution counts")
        if probe.get("output_hashes") or probe.get("score_payload_hashes") or probe.get("releases_tested"):
            errors.append("not-run probe contains output evidence")

    risks = documents["risks_and_open_questions.json"]
    prerequisites = risks.get("blocking_prerequisites", [])
    if verdict == "SUITABLE_WITH_PREREQUISITES":
        if not prerequisites:
            errors.append("SUITABLE_WITH_PREREQUISITES lacks a blocking prerequisite")
        for prerequisite in prerequisites:
            missing_fields = REQUIRED_PREREQUISITE_FIELDS.difference(prerequisite)
            if missing_fields or prerequisite.get("status") != "UNRESOLVED" or prerequisite.get("blocks_integration") is not True:
                errors.append("blocking prerequisite is not fully specified")
            if not prerequisite.get("acceptable_evidence") or not prerequisite.get("prohibited_shortcuts"):
                errors.append("blocking prerequisite lacks evidence or shortcut controls")
    elif verdict == "NOT_SUITABLE":
        if not identity.get("blocking_rationale"):
            errors.append("NOT_SUITABLE lacks blocking rationale")
    elif verdict == "SUITABLE":
        suitable_conditions = (
            build.get("build_attempted") is True,
            build.get("exit_code") == 0,
            build.get("mindtct_built") is True,
            build.get("bozorth3_built") is True,
            bool(build.get("executable_hashes")),
            input_audit.get("MINDTCT_direct_PNG_support") is True or (
                input_audit.get("conversion_lossless") is True
                and input_audit.get("pixel_equivalence_verified") is True
            ),
            record_1000.get("canonical_pipeline_available") is True,
            record_2000.get("canonical_pipeline_available") is True,
            pipeline.get("status") == "READY",
            probe.get("executed") is True,
            probe.get("mindtct_output_deterministic") == "PASS",
            probe.get("bozorth3_score_deterministic") == "PASS",
        )
        if not all(suitable_conditions):
            errors.append("SUITABLE does not meet all mandatory build, path, pipeline, and probe criteria")

    artifact_tracking = documents["audit_lock.json"].get("artifact_tracking", {})
    for key in (
        "source_archive_tracked", "source_tree_tracked", "binary_tracked", "image_tracked",
        "minutiae_tracked", "raw_log_tracked", "raw_score_value_tracked",
    ):
        if artifact_tracking.get(key) is not False:
            errors.append(f"prohibited tracked artifact state: {key}")

    report = documents["audit_validation_report.json"]
    if report.get("valid") is not True or report.get("errors") != [] or report.get("audit_status") != "PASS":
        errors.append("audit validation report is not a clean PASS")

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


def validate_package(repository_root: Path) -> list[str]:
    repository_root = Path(repository_root).resolve()
    package_root = repository_root / PACKAGE_RELATIVE
    errors: list[str] = []
    if not package_root.is_dir():
        return [f"audit package is missing: {PACKAGE_RELATIVE.as_posix()}"]
    present = sorted(path.name for path in package_root.iterdir() if path.is_file())
    if present != sorted(PACKAGE_FILES):
        errors.append("audit package file set mismatch")
    if errors:
        return errors

    for path in package_root.iterdir():
        if path.is_file() and path.suffix.casefold() in FORBIDDEN_PACKAGE_SUFFIXES:
            errors.append(f"prohibited binary/archive/image/minutiae artifact: {path.name}")

    try:
        documents = load_documents(package_root)
    except (OSError, json.JSONDecodeError) as exc:
        return [f"cannot parse audit JSON: {exc}"]
    for name, document in documents.items():
        if (package_root / name).read_bytes() != canonical_json_bytes(document):
            errors.append(f"non-canonical JSON: {name}")
    errors.extend(validate_semantics(documents))
    text_files = {
        name: (package_root / name).read_text(encoding="utf-8")
        for name in ("README.md", "AUDIT_REPORT.md")
    }
    errors.extend(validate_content_safety({}, text_files))

    lock = documents["audit_lock.json"]
    if lock.get("candidate_verdict") != documents["candidate_identity.json"].get("candidate_verdict"):
        errors.append("lock verdict mismatch")
    if lock.get("sourceafis_baseline") != {
        "commit": "241dfe41eb8d07a3c6b953b6114040637c4f3012",
        "tag": "sourceafis-policy-application-v1",
    }:
        errors.append("SourceAFIS baseline lock mismatch")
    locked_files = lock.get("files", {})
    if set(locked_files) != set(CORE_LOCKED_FILES):
        errors.append("audit lock file set mismatch or lock/checksum self-reference")
    for name in CORE_LOCKED_FILES:
        path = package_root / name
        record = locked_files.get(name, {})
        if record.get("sha256") != file_sha256(path) or record.get("bytes") != path.stat().st_size:
            errors.append(f"audit lock mismatch: {name}")
    code_files = lock.get("code_files", {})
    expected_code = {
        "tools/validate_nbis_candidate_audit_v1.py": repository_root / "tools" / "validate_nbis_candidate_audit_v1.py",
        "tests/test_nbis_candidate_audit_v1.py": repository_root / "tests" / "test_nbis_candidate_audit_v1.py",
    }
    if set(code_files) != set(expected_code):
        errors.append("audit lock code file set mismatch")
    for name, path in expected_code.items():
        record = code_files.get(name, {})
        if not path.is_file() or record.get("sha256") != file_sha256(path) or record.get("bytes") != path.stat().st_size:
            errors.append(f"audit lock code hash mismatch: {name}")

    protected = lock.get("protected_area_tree_hashes", {})
    if set(protected) != REQUIRED_PROTECTED_AREAS:
        errors.append("protected-area lock set mismatch")
    for relative in sorted(REQUIRED_PROTECTED_AREAS):
        path = repository_root / relative
        if not path.is_dir() or protected.get(relative) != tree_identity(path):
            errors.append(f"protected-area tree mismatch: {relative}")

    tracking = lock.get("artifact_tracking", {})
    for key in (
        "source_archive_tracked", "source_tree_tracked", "binary_tracked", "image_tracked",
        "minutiae_tracked", "raw_log_tracked", "raw_score_value_tracked",
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
    return errors


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repository-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="repository root; defaults to the validator's parent repository",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    errors = validate_package(args.repository_root)
    if errors:
        print("NBIS candidate audit validation: FAIL", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print("NBIS candidate audit validation: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
