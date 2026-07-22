"""Dataset-independent deep validation for the SourceAFIS frozen-cohort execution.

This tool never starts a matcher, never opens a dataset image, and never applies the
frozen decision policy. It reads raw scores only far enough to confirm that they are
present, finite and non-negative; it never returns, prints, aggregates or compares a
score value.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Any

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_SOURCE_ROOT = _REPOSITORY_ROOT / "src"
if _SOURCE_ROOT.is_dir() and str(_SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(_SOURCE_ROOT))

from fingerprint_benchmark.contract import BENCHMARK_CONTRACT_VERSION  # noqa: E402
from fingerprint_benchmark.hashing import file_sha256, stable_sha256  # noqa: E402
from fingerprint_benchmark.manifest import MANIFEST_COLUMNS  # noqa: E402
from fingerprint_benchmark.runner import (  # noqa: E402
    RESULT_COLUMNS,
    ResultBundleError,
    validate_result_bundle,
)

EXECUTION_ID = "sourceafis_frozen_cohort_v1"
EXECUTION_VERSION = 1
METHOD_ID = "sourceafis"
SOURCEAFIS_VERSION = "3.18.1"
EXPECTED_ROWS_PER_MANIFEST = 500
EXPECTED_TOTAL_ROWS = 4000
PROTOCOL_RELATIVE_ROOT = "protocols/supervisor_50x10_v1"
RESULTS_RELATIVE_ROOT = f"results/{EXECUTION_ID}"
ENVIRONMENT_IDENTIFIER = "conda_env/fingerprint-recognition-research"
JAVA_VERSION = "17.0.18"
JAVA_VENDOR = "Azul Systems, Inc."
JAVA_DISTRIBUTION = "Zulu OpenJDK"
MAVEN_VERSION = "3.9.16"
COMPILER_RELEASE = 11

COHORT_MANIFESTS = (
    "sd300b/plain_self.csv",
    "sd300b/roll_self.csv",
    "sd300b/plain_roll_genuine.csv",
    "sd300b/plain_roll_next_subject.csv",
    "sd300c/plain_self.csv",
    "sd300c/roll_self.csv",
    "sd300c/plain_roll_genuine.csv",
    "sd300c/plain_roll_next_subject.csv",
)

EXECUTION_PACKAGE_FILES = (
    "README.md",
    "SHA256SUMS.txt",
    "bundle_registry.json",
    "execution_environment.json",
    "execution_lock.json",
    "execution_plan.json",
    "execution_validation_report.json",
)
EXECUTION_JSON_FILES = tuple(name for name in EXECUTION_PACKAGE_FILES if name.endswith(".json"))

FORBIDDEN_RESULT_COLUMNS = frozenset({
    "accepted", "accuracy", "decision", "different", "false_match", "false_non_match",
    "fmr", "fnmr", "match", "non_match", "rejected", "same", "threshold", "verdict",
})
FORBIDDEN_REGISTRY_KEYS = frozenset({
    "accuracy", "decision", "decisions", "false_match", "false_match_rate", "false_non_match",
    "false_non_match_rate", "fmr", "fnmr", "raw_score", "raw_scores", "score", "score_histogram",
    "score_max", "score_mean", "score_median", "score_min", "scores", "threshold",
})
_ABSOLUTE_WINDOWS_PATH = re.compile(r"(?i)\b[a-z]:[\\/]")
_ABSOLUTE_POSIX_PATH = re.compile(r"(?i)(?:^|[\s\"'])/(?:home|root|tmp|users)/")
_RUN_ID = re.compile(r"^[0-9a-f]{24}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class CohortValidationError(ValueError):
    """A frozen-cohort bundle or execution package failed validation."""


def expected_run_id(manifest_sha256: str, protocol_lock_sha256: str) -> str:
    """Recompute the deterministic run identity produced by the frozen runtime."""
    identity = {
        "contract_version": BENCHMARK_CONTRACT_VERSION,
        "method_id": METHOD_ID,
        "method_version": SOURCEAFIS_VERSION,
        "manifest_sha256": manifest_sha256,
        "protocol_lock_sha256": protocol_lock_sha256,
    }
    return stable_sha256(identity)[:24]


def read_manifest_rows(manifest_path: Path) -> list[dict[str, str]]:
    """Read a frozen manifest as raw strings without resolving any dataset image."""
    manifest_path = Path(manifest_path)
    with manifest_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if tuple(reader.fieldnames or ()) != MANIFEST_COLUMNS:
            raise CohortValidationError(f"manifest header mismatch: {manifest_path.name}")
        return [dict(row) for row in reader]


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise CohortValidationError(message)


def validate_cohort_bundle(
    *,
    bundle: Path,
    protocol_root: Path,
    manifest_relative_path: str,
    expected_rows: int = EXPECTED_ROWS_PER_MANIFEST,
    expected_jar_sha256: str | None = None,
    expected_execution_commit: str | None = None,
    expected_java_version: str | None = None,
) -> dict[str, Any]:
    """Validate one bundle against its source manifest and return score-free counts."""
    bundle = Path(bundle)
    protocol_root = Path(protocol_root)
    metadata_path = bundle / "metadata.json"
    provenance_path = bundle / "provenance.json"
    results_path = bundle / "results.csv"
    for path in (metadata_path, provenance_path, results_path):
        _require(path.is_file(), f"missing bundle file: {path.name}")

    manifest_path = protocol_root / PurePosixPath(manifest_relative_path)
    lock_path = protocol_root / "manifest_lock.json"
    _require(manifest_path.is_file(), f"missing manifest: {manifest_relative_path}")
    _require(lock_path.is_file(), "missing protocol manifest_lock.json")
    manifest_sha256 = file_sha256(manifest_path)
    protocol_lock_sha256 = file_sha256(lock_path)
    manifest_rows = read_manifest_rows(manifest_path)
    _require(
        len(manifest_rows) == expected_rows,
        f"manifest row count is {len(manifest_rows)}, expected {expected_rows}",
    )

    with results_path.open("r", encoding="utf-8", newline="") as handle:
        header = tuple(next(csv.reader(handle), ()))
    forbidden = sorted(FORBIDDEN_RESULT_COLUMNS.intersection(name.lower() for name in header))
    _require(not forbidden, f"decision-bearing column present in results: {', '.join(forbidden)}")
    _require(header == RESULT_COLUMNS, "results schema does not match the frozen result contract")

    try:
        contract_summary = validate_result_bundle(bundle)
    except ResultBundleError as exc:
        raise CohortValidationError(f"result bundle contract failure: {exc}") from exc

    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    identity = metadata.get("identity", {})
    run_id = metadata.get("run_id")

    _require(metadata.get("contract_version") == BENCHMARK_CONTRACT_VERSION, "unexpected contract version")
    _require(isinstance(run_id, str) and bool(_RUN_ID.fullmatch(run_id)), "malformed run identity")
    _require(identity.get("method_id") == METHOD_ID, "bundle was not produced by SourceAFIS")
    _require(identity.get("method_version") == SOURCEAFIS_VERSION, "unexpected SourceAFIS method version")
    _require(identity.get("manifest_sha256") == manifest_sha256, "bundle manifest hash mismatch")
    _require(identity.get("protocol_lock_sha256") == protocol_lock_sha256, "bundle protocol lock hash mismatch")
    _require(run_id == expected_run_id(manifest_sha256, protocol_lock_sha256), "run identity is not derived from the frozen manifest")
    _require(metadata.get("row_count") == expected_rows, f"bundle row count is not {expected_rows}")
    _require(contract_summary["row_count"] == expected_rows, f"bundle row count is not {expected_rows}")

    _require(provenance.get("sourceafis_version") == SOURCEAFIS_VERSION, "provenance SourceAFIS version mismatch")
    _require(provenance.get("manifest_sha256") == manifest_sha256, "provenance manifest hash mismatch")
    _require(provenance.get("protocol_lock_sha256") == protocol_lock_sha256, "provenance protocol lock hash mismatch")
    jar_sha256 = provenance.get("jar_sha256")
    _require(isinstance(jar_sha256, str) and bool(_SHA256.fullmatch(jar_sha256)), "provenance JAR hash is malformed")
    if expected_jar_sha256 is not None:
        _require(jar_sha256 == expected_jar_sha256, "bundle was produced by a different JAR")
    execution_commit = str(provenance.get("git", {}).get("commit", ""))
    if expected_execution_commit is not None:
        _require(execution_commit == expected_execution_commit, "bundle was produced by different execution code")
    java_version = provenance.get("java_version")
    if expected_java_version is not None:
        _require(java_version == expected_java_version, "bundle was produced by a different Java runtime")

    successful_scores = 0
    technical_failures = 0
    with results_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for index, row in enumerate(reader, start=1):
            if index > len(manifest_rows):
                raise CohortValidationError("results contain more rows than the manifest")
            source = manifest_rows[index - 1]
            _require(row["pair_index"] == str(index), f"row {index}: pair index is out of order")
            _require(row["run_id"] == run_id, f"row {index}: run identity mismatch")
            _require(row["manifest_sha256"] == manifest_sha256, f"row {index}: manifest hash mismatch")
            for column in MANIFEST_COLUMNS:
                if row[column] != source[column]:
                    raise CohortValidationError(f"row {index}: {column} does not match the frozen manifest")
            status = row["status"]
            raw_score = row["raw_score"]
            error_code = row["error_code"]
            if status == "ok":
                _require(bool(raw_score), f"row {index}: successful row has no raw score")
                _require(not error_code, f"row {index}: successful row carries an error code")
                try:
                    score = float(raw_score)
                except ValueError as exc:
                    raise CohortValidationError(f"row {index}: raw score is not a float") from exc
                _require(math.isfinite(score), f"row {index}: raw score is not finite")
                _require(score >= 0, f"row {index}: raw score is negative")
                successful_scores += 1
            else:
                _require(not raw_score, f"row {index}: failed row carries a raw score")
                _require(bool(error_code), f"row {index}: failed row has no error code")
                technical_failures += 1

    _require(
        successful_scores + technical_failures == expected_rows,
        "successful scores plus technical failures do not account for every planned pair",
    )
    return {
        "bundle_validation": "PASS",
        "comparison_kind": manifest_rows[0]["comparison_kind"],
        "dataset_release": manifest_rows[0]["dataset_release"],
        "execution_code_commit": execution_commit,
        "jar_sha256": jar_sha256,
        "java_version": java_version,
        "manifest_relative_path": manifest_relative_path,
        "manifest_sha256": manifest_sha256,
        "metadata_sha256": file_sha256(metadata_path),
        "protocol_lock_sha256": protocol_lock_sha256,
        "provenance_sha256": file_sha256(provenance_path),
        "results_csv_sha256": file_sha256(results_path),
        "row_count": expected_rows,
        "run_id": run_id,
        "sourceafis_version": SOURCEAFIS_VERSION,
        "successful_scores": successful_scores,
        "technical_failures": technical_failures,
    }


def compute_bundle_set_sha256(entries: list[dict[str, Any]]) -> str:
    """Hash the ordered identity of all eight bundles."""
    payload = [
        {
            "manifest_sha256": entry["manifest_sha256"],
            "metadata_sha256": entry["metadata_sha256"],
            "provenance_sha256": entry["provenance_sha256"],
            "results_csv_sha256": entry["results_csv_sha256"],
            "run_id": entry["run_id"],
        }
        for entry in sorted(entries, key=lambda item: item["execution_order"])
    ]
    return stable_sha256(payload)


def _iter_items(value: Any):
    if isinstance(value, dict):
        for key, child in value.items():
            yield key, child
            yield from _iter_items(child)
    elif isinstance(value, list):
        for child in value:
            yield from _iter_items(child)


def _parse_checksums(path: Path) -> tuple[dict[str, str], list[str]]:
    checksums: dict[str, str] = {}
    errors: list[str] = []
    order: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\\]+)", line)
        if not match:
            errors.append(f"invalid checksum line: {line!r}")
            continue
        digest, relative = match.groups()
        if relative in checksums:
            errors.append(f"duplicate checksum path: {relative}")
        checksums[relative] = digest
        order.append(relative)
    if order != sorted(order):
        errors.append("SHA256SUMS.txt is not sorted by path")
    return checksums, errors


def validate_execution_package(package_root: Path, repository_root: Path | None = None) -> list[str]:
    """Statically validate the committed execution package with no dataset access."""
    package_root = Path(package_root).resolve()
    repository_root = Path(repository_root).resolve() if repository_root is not None else package_root.parents[1]
    errors: list[str] = []

    def require(condition: bool, message: str) -> None:
        if not condition:
            errors.append(message)

    for name in EXECUTION_PACKAGE_FILES:
        require((package_root / name).is_file(), f"missing execution package file: {name}")
    if errors:
        return errors

    data = {name: json.loads((package_root / name).read_text(encoding="utf-8")) for name in EXECUTION_JSON_FILES}
    for name, value in data.items():
        raw = (package_root / name).read_bytes()
        canonical = (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
        require(raw == canonical, f"non-canonical JSON: {name}")
        require(value.get("execution_id") == EXECUTION_ID, f"execution_id mismatch: {name}")

    plan = data["execution_plan.json"]
    environment = data["execution_environment.json"]
    registry = data["bundle_registry.json"]
    report = data["execution_validation_report.json"]
    lock = data["execution_lock.json"]

    require(plan.get("manifests") == list(COHORT_MANIFESTS), "execution plan manifest order mismatch")
    require(plan.get("expected_rows_per_manifest") == EXPECTED_ROWS_PER_MANIFEST, "expected rows per manifest mismatch")
    require(plan.get("expected_total_rows") == EXPECTED_TOTAL_ROWS, "expected total rows mismatch")
    require(plan.get("decision_policy_applied") is False, "execution plan claims the decision policy was applied")
    require(plan.get("fresh_jvm_per_manifest") is True, "execution plan does not require a fresh JVM per manifest")
    require(plan.get("single_jar_for_all_manifests") is True, "execution plan does not require a single JAR")
    require(plan.get("selective_retry_allowed") is False, "execution plan allows selective retry")
    require(plan.get("score_analysis_allowed") is False, "execution plan allows score analysis")
    require(plan.get("sourceafis_version") == SOURCEAFIS_VERSION, "execution plan SourceAFIS version mismatch")

    require(environment.get("java_version") == JAVA_VERSION, "environment Java version mismatch")
    require(environment.get("java_vendor") == JAVA_VENDOR, "environment Java vendor mismatch")
    require(environment.get("java_distribution") == JAVA_DISTRIBUTION, "environment Java distribution mismatch")
    require(environment.get("maven_version") == MAVEN_VERSION, "environment Maven version mismatch")
    require(environment.get("compiler_release") == COMPILER_RELEASE, "environment compiler release mismatch")
    require(environment.get("sourceafis_version") == SOURCEAFIS_VERSION, "environment SourceAFIS version mismatch")
    require(environment.get("environment") == ENVIRONMENT_IDENTIFIER, "environment identifier mismatch")
    require(environment.get("same_jar_for_all_manifests") is True, "environment does not record a single JAR")
    require(environment.get("conda_environment_modified") is False, "environment records a modified conda environment")
    require(environment.get("persistent_system_environment_modified") is False, "environment records a persistent system change")

    entries = registry.get("bundles", [])
    require(len(entries) == len(COHORT_MANIFESTS), "bundle registry does not contain eight entries")
    if len(entries) == len(COHORT_MANIFESTS):
        total_rows = 0
        for position, entry in enumerate(entries, start=1):
            label = entry.get("manifest_relative_path", "?")
            require(entry.get("execution_order") == position, f"registry order mismatch at {label}")
            require(entry.get("manifest_relative_path") == COHORT_MANIFESTS[position - 1], f"registry manifest mismatch at position {position}")
            require(entry.get("row_count") == EXPECTED_ROWS_PER_MANIFEST, f"registry row count mismatch at {label}")
            require(entry.get("bundle_validation") == "PASS", f"registry entry is not PASS at {label}")
            require(entry.get("sourceafis_version") == SOURCEAFIS_VERSION, f"registry SourceAFIS version mismatch at {label}")
            successful = entry.get("successful_scores")
            failures = entry.get("technical_failures")
            require(
                isinstance(successful, int) and isinstance(failures, int)
                and successful + failures == EXPECTED_ROWS_PER_MANIFEST,
                f"registry counts do not sum to {EXPECTED_ROWS_PER_MANIFEST} at {label}",
            )
            bundle_relative = str(entry.get("bundle_relative_path", ""))
            require(bundle_relative.startswith("raw/"), f"registry bundle path is not inside the raw results root at {label}")
            total_rows += entry.get("row_count") or 0
        require(total_rows == EXPECTED_TOTAL_ROWS, "registry total row count is not 4000")
        require(registry.get("total_rows") == EXPECTED_TOTAL_ROWS, "registry total_rows field is not 4000")
        require(
            lock.get("bundle_set_sha256") == compute_bundle_set_sha256(entries),
            "bundle set hash does not match the registry",
        )

    checks = report.get("checks", {})
    require(report.get("valid") is True and report.get("errors") == [], "execution validation report is not a clean PASS")
    for flag in ("decision_policy_applied", "threshold_read_by_execution", "decision_fields_generated",
                 "selective_retries_performed", "score_analysis_performed", "raw_bundles_tracked_by_git"):
        require(checks.get(flag) is False, f"execution report flag must be false: {flag}")
    for flag in ("single_jar_used", "single_java_runtime_used", "fresh_jvm_per_manifest", "protocol_unchanged",
                 "runtime_unchanged", "qualification_unchanged", "decision_policy_unchanged"):
        require(checks.get(flag) is True, f"execution report flag must be true: {flag}")
    require(checks.get("manifests_executed") == 8, "execution report manifest count mismatch")
    require(checks.get("bundles_valid") == 8, "execution report valid bundle count mismatch")
    require(checks.get("rows_per_bundle") == EXPECTED_ROWS_PER_MANIFEST, "execution report rows-per-bundle mismatch")
    require(checks.get("total_rows") == EXPECTED_TOTAL_ROWS, "execution report total rows mismatch")

    for name, value in data.items():
        for key, child in _iter_items(value):
            if key.lower() in FORBIDDEN_REGISTRY_KEYS:
                errors.append(f"forbidden score or decision key in {name}: {key}")
            if isinstance(child, str) and (_ABSOLUTE_WINDOWS_PATH.search(child) or _ABSOLUTE_POSIX_PATH.search(child)):
                errors.append(f"absolute local path in {name}: {key}")

    combined = "\n".join((package_root / name).read_text(encoding="utf-8") for name in EXECUTION_PACKAGE_FILES)
    require(_ABSOLUTE_WINDOWS_PATH.search(combined) is None, "absolute Windows path found in execution package")
    require(_ABSOLUTE_POSIX_PATH.search(combined) is None, "absolute local POSIX path found in execution package")
    require(re.search(r"(?i)\b(?:hostname|username)\s*[:=]", combined) is None, "username or hostname found in execution package")

    locked_files = lock.get("files", {})
    require(f"executions/{EXECUTION_ID}/execution_lock.json" not in locked_files, "lock includes itself")
    require(f"executions/{EXECUTION_ID}/SHA256SUMS.txt" not in locked_files, "lock includes the checksum index")
    for relative, record in locked_files.items():
        target = repository_root / PurePosixPath(relative)
        if not target.is_file():
            errors.append(f"locked file is missing: {relative}")
            continue
        require(record.get("sha256") == file_sha256(target), f"locked hash mismatch: {relative}")
        require(record.get("size_bytes") == target.stat().st_size, f"locked size mismatch: {relative}")
    require(lock.get("total_rows") == EXPECTED_TOTAL_ROWS, "lock total row count is not 4000")
    require(lock.get("execution_version") == EXECUTION_VERSION, "lock execution version mismatch")

    checksums, checksum_errors = _parse_checksums(package_root / "SHA256SUMS.txt")
    errors.extend(checksum_errors)
    present = sorted(path.name for path in package_root.iterdir() if path.is_file() and path.name != "SHA256SUMS.txt")
    require(set(checksums) == set(present), "SHA256SUMS file set mismatch")
    for name in present:
        require(checksums.get(name) == file_sha256(package_root / name), f"SHA256SUMS mismatch: {name}")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="validate-sourceafis-frozen-cohort-v1")
    parser.add_argument("--repository-root", type=Path, default=_REPOSITORY_ROOT)
    parser.add_argument("--results-root", type=Path, default=None)
    args = parser.parse_args(argv)

    repository_root = args.repository_root.resolve()
    package_root = repository_root / "executions" / EXECUTION_ID
    if not package_root.is_dir():
        print(f"execution package is absent: executions/{EXECUTION_ID}", file=sys.stderr)
        return 1
    errors = validate_execution_package(package_root)

    if args.results_root is not None:
        registry = json.loads((package_root / "bundle_registry.json").read_text(encoding="utf-8"))
        protocol_root = repository_root / PurePosixPath(PROTOCOL_RELATIVE_ROOT)
        for entry in registry.get("bundles", []):
            bundle = Path(args.results_root) / PurePosixPath(entry["bundle_relative_path"])
            try:
                validate_cohort_bundle(
                    bundle=bundle,
                    protocol_root=protocol_root,
                    manifest_relative_path=entry["manifest_relative_path"],
                    expected_jar_sha256=entry.get("jar_sha256"),
                    expected_execution_commit=entry.get("execution_code_commit"),
                    expected_java_version=entry.get("java_version"),
                )
            except (CohortValidationError, OSError) as exc:
                errors.append(f"bundle {entry['manifest_relative_path']}: {exc}")

    if errors:
        print("SourceAFIS frozen-cohort execution validation: FAIL", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print("SourceAFIS frozen-cohort execution validation: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
