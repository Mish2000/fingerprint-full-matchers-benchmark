"""Read-only validation for the frozen SourceAFIS policy application package.

Without ``--results-root`` this validator is dataset-independent and suitable for
CI.  With ``--results-root`` it replays all 4,000 policy decisions, compares every
local decision payload hash, and recomputes all summaries without printing scores.
"""

from __future__ import annotations

import argparse
import ast
import csv
import json
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Any

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_TOOLS_ROOT = _REPOSITORY_ROOT / "tools"
if str(_TOOLS_ROOT) not in sys.path:
    sys.path.insert(0, str(_TOOLS_ROOT))

import apply_sourceafis_decision_policy_v1 as application  # noqa: E402


_ABSOLUTE_WINDOWS_PATH = re.compile(r"(?i)\b[a-z]:[\\/]")
_ABSOLUTE_POSIX_PATH = re.compile(r"(?i)(?:^|[\s\"'])/(?:home|root|tmp|users)/")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_FORBIDDEN_KEYS = {
    "raw_score", "raw_scores", "score_min", "score_max", "score_mean", "score_median",
    "score_distribution", "histogram", "roc", "eer", "pair_id", "pair_ids", "subject_id",
    "subject_ids", "image_path", "image_paths", "timing", "timings",
}


def _iter_items(value: Any):
    if isinstance(value, dict):
        for key, child in value.items():
            yield key, child
            yield from _iter_items(child)
    elif isinstance(value, list):
        for child in value:
            yield from _iter_items(child)


def _canonical(path: Path, value: Any) -> bool:
    return path.read_bytes() == application.canonical_json_bytes(value)


def _parse_checksums(path: Path) -> tuple[dict[str, str], list[str]]:
    result: dict[str, str] = {}
    errors: list[str] = []
    order: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\\]+)", line)
        if not match:
            errors.append(f"invalid checksum line: {line!r}")
            continue
        digest, relative = match.groups()
        if relative in result:
            errors.append(f"duplicate checksum path: {relative}")
        result[relative] = digest
        order.append(relative)
    if order != sorted(order):
        errors.append("SHA256SUMS.txt is not sorted")
    return result, errors


def _validate_rate(rate: Any, numerator: int, denominator: int, label: str, errors: list[str]) -> None:
    try:
        expected = application.machine_rate(numerator, denominator)
    except ValueError as exc:
        errors.append(f"{label}: invalid rate inputs: {exc}")
        return
    if rate != expected:
        errors.append(f"{label}: rate does not match its counts")


def _validate_primary(entry: dict[str, Any], errors: list[str]) -> None:
    label = f"{entry.get('dataset_release', '?')}/{entry.get('comparison_kind', '?')}"
    integer_fields = (
        "planned_pairs", "successful_scores", "technical_failures", "same_decisions",
        "different_decisions", "no_decisions", "correct_same", "correct_different",
        "false_matches", "false_non_matches", "correct_decisions", "incorrect_decisions",
    )
    if any(not isinstance(entry.get(field), int) or isinstance(entry.get(field), bool) or entry[field] < 0
           for field in integer_fields):
        errors.append(f"{label}: counts are not non-negative integers")
        return
    if entry["planned_pairs"] != entry["successful_scores"] + entry["technical_failures"]:
        errors.append(f"{label}: planned-pair arithmetic mismatch")
    if entry["successful_scores"] != entry["same_decisions"] + entry["different_decisions"]:
        errors.append(f"{label}: decision arithmetic mismatch")
    if entry["technical_failures"] != entry["no_decisions"]:
        errors.append(f"{label}: technical-failure arithmetic mismatch")
    if entry["correct_decisions"] != entry["correct_same"] + entry["correct_different"]:
        errors.append(f"{label}: correct-decision arithmetic mismatch")
    if entry["incorrect_decisions"] != entry["false_matches"] + entry["false_non_matches"]:
        errors.append(f"{label}: incorrect-decision arithmetic mismatch")
    if entry["successful_scores"] != entry["correct_decisions"] + entry["incorrect_decisions"]:
        errors.append(f"{label}: correctness denominator mismatch")
    expected = application.EXPECTED_CLASS.get(entry.get("comparison_kind"))
    if expected is None or entry.get("expected_class") != expected:
        errors.append(f"{label}: expected class mismatch")
    if entry.get("reporting_category") != application.REPORTING_CATEGORY.get(entry.get("comparison_kind")):
        errors.append(f"{label}: reporting category mismatch")
    if not isinstance(entry.get("decision_set_sha256"), str) or not _SHA256.fullmatch(entry["decision_set_sha256"]):
        errors.append(f"{label}: malformed decision-set hash")
    _validate_rate(entry.get("decision_coverage"), entry["successful_scores"], entry["planned_pairs"],
                   f"{label} decision_coverage", errors)
    _validate_rate(entry.get("technical_failure_rate"), entry["technical_failures"], entry["planned_pairs"],
                   f"{label} technical_failure_rate", errors)
    _validate_rate(entry.get("valid_only_correct_rate"), entry["correct_decisions"], entry["successful_scores"],
                   f"{label} valid_only_correct_rate", errors)
    _validate_rate(entry.get("strict_correct_completion_rate"), entry["correct_decisions"], entry["planned_pairs"],
                   f"{label} strict_correct_completion_rate", errors)
    if expected == "same":
        if entry.get("correct_same_count") != entry["correct_same"]:
            errors.append(f"{label}: correct_same_count mismatch")
        if entry.get("false_non_match_count") != entry["false_non_matches"]:
            errors.append(f"{label}: false_non_match_count mismatch")
        if "false_match_rate_valid" in entry:
            errors.append(f"{label}: expected-same unit has false-match rate")
        _validate_rate(entry.get("match_rate_valid"), entry["correct_same"], entry["successful_scores"],
                       f"{label} match_rate_valid", errors)
        _validate_rate(entry.get("false_non_match_rate_valid"), entry["false_non_matches"],
                       entry["successful_scores"], f"{label} false_non_match_rate_valid", errors)
    elif expected == "different":
        if entry.get("correct_different_count") != entry["correct_different"]:
            errors.append(f"{label}: correct_different_count mismatch")
        if entry.get("false_match_count") != entry["false_matches"]:
            errors.append(f"{label}: false_match_count mismatch")
        if "false_non_match_rate_valid" in entry:
            errors.append(f"{label}: expected-different unit has false-non-match rate")
        _validate_rate(entry.get("correct_reject_rate_valid"), entry["correct_different"],
                       entry["successful_scores"], f"{label} correct_reject_rate_valid", errors)
        _validate_rate(entry.get("false_match_rate_valid"), entry["false_matches"],
                       entry["successful_scores"], f"{label} false_match_rate_valid", errors)


def _validate_primary_csv(path: Path, entries: list[dict[str, Any]], errors: list[str]) -> None:
    with path.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if len(rows) != application.EXPECTED_PRIMARY_UNITS:
        errors.append("primary_results.csv does not contain eight rows")
        return
    rate_fields = (
        "decision_coverage", "technical_failure_rate", "valid_only_correct_rate",
        "strict_correct_completion_rate", "match_rate_valid", "false_non_match_rate_valid",
        "correct_reject_rate_valid", "false_match_rate_valid",
    )
    for source, row in zip(entries, rows):
        if row.get("dataset_release") != source.get("dataset_release") or row.get("comparison_kind") != source.get("comparison_kind"):
            errors.append("primary_results.csv order or identity mismatch")
        for field in rate_fields:
            expected = source.get(field)
            expected_text = "N/A" if expected is None else application.human_rate(expected["numerator"], expected["denominator"])
            if row.get(field) != expected_text:
                errors.append(f"primary_results.csv human rate mismatch: {field}")


def _validate_aggregates(entries: list[dict[str, Any]], aggregates: list[dict[str, Any]], errors: list[str]) -> None:
    if len(aggregates) != application.EXPECTED_AGGREGATES:
        errors.append("verification aggregate count is not two")
        return
    expected = [application.verification_aggregate(entries, release) for release in ("sd300b", "sd300c")]
    if aggregates != expected:
        errors.append("verification aggregates do not match primary results")
    for aggregate in aggregates:
        if aggregate.get("plain_self_included") is not False or aggregate.get("roll_self_included") is not False:
            errors.append("self comparisons are included in a verification aggregate")


def _validate_code_boundaries(repository_root: Path, errors: list[str]) -> None:
    path = repository_root / "tools" / "apply_sourceafis_decision_policy_v1.py"
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError) as exc:
        errors.append(f"cannot parse application tool: {exc}")
        return
    forbidden_imports = {"subprocess", "http", "urllib", "requests", "fingerprint_benchmark"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in forbidden_imports:
                    errors.append(f"application tool imports forbidden module: {alias.name}")
        elif isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] in forbidden_imports:
            errors.append(f"application tool imports forbidden module: {node.module}")
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "os" and node.func.attr in {"system", "popen", "spawnl", "spawnv"}:
                errors.append(f"application tool invokes a process through os.{node.func.attr}")
    parser = application._parser()
    option_strings = {option for action in parser._actions for option in action.option_strings}
    forbidden_cli = {
        "--threshold", "--operator", "--policy", "--bundle", "--manifest", "--comparison-kind",
        "--release", "--subject", "--score", "--retry", "--replace", "--skip-validation",
    }
    present = option_strings.intersection(forbidden_cli)
    if present:
        errors.append(f"application tool exposes forbidden CLI options: {sorted(present)}")


def _validate_local_replay(
    repository_root: Path, package_root: Path, results_root: Path,
    frozen: dict[str, Any], primary: list[dict[str, Any]], aggregates: list[dict[str, Any]],
    lock: dict[str, Any], errors: list[str],
) -> None:
    try:
        replay = application.derive_all(
            repository_root=repository_root, results_root=results_root, frozen=frozen,
            application_code_commit=lock["application_code_commit"], progress=None,
        )
    except (application.ApplicationBlocked, application.InvalidInput, OSError, KeyError, ValueError) as exc:
        errors.append(f"local replay failed: {exc}")
        return
    if replay["primary"] != primary:
        errors.append("primary results differ from local raw replay")
    if replay["aggregates"] != aggregates:
        errors.append("verification aggregates differ from local raw replay")
    if replay["combined_decision_set_sha256"] != lock.get("combined_decision_set_sha256"):
        errors.append("combined decision-set hash differs from local raw replay")
    derived_root = repository_root / "results" / application.APPLICATION_ID
    metadata_path = derived_root / "application_metadata.json"
    if not metadata_path.is_file():
        errors.append("local application metadata is missing")
        return
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    if metadata.get("combined_decision_set_sha256") != replay["combined_decision_set_sha256"]:
        errors.append("local metadata combined decision-set hash mismatch")
    metadata_files = {item["file"]: item for item in metadata.get("derived_files", [])}
    for item in replay["derived_sets"]:
        name = f"derived/{item['entry']['run_id']}-decisions.csv"
        path = derived_root / PurePosixPath(name)
        if not path.is_file():
            errors.append(f"local derived file is missing: {name}")
            continue
        with path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            if tuple(reader.fieldnames or ()) != application.DERIVED_COLUMNS:
                errors.append(f"local derived header mismatch: {name}")
                continue
            actual_rows = [dict(row) for row in reader]
        if len(actual_rows) != len(item["rows"]):
            errors.append(f"local derived row count mismatch: {name}")
            continue
        for expected_row, actual_row in zip(item["rows"], actual_rows):
            if actual_row != expected_row:
                errors.append(f"local decision payload row mismatch: {name}")
                break
        record = metadata_files.get(name, {})
        if record.get("sha256") != application.file_sha256(path) or record.get("rows") != len(actual_rows):
            errors.append(f"local derived file metadata mismatch: {name}")


def validate_package_root(
    repository_root: Path, package_root: Path, *, results_root: Path | None = None,
) -> list[str]:
    repository_root = Path(repository_root).resolve()
    package_root = Path(package_root).resolve()
    errors: list[str] = []

    for name in application.EVALUATION_FILES:
        if not (package_root / name).is_file():
            errors.append(f"missing evaluation package file: {name}")
    present = sorted(path.name for path in package_root.iterdir() if path.is_file()) if package_root.is_dir() else []
    if present != sorted(application.EVALUATION_FILES):
        errors.append("evaluation package file set mismatch")
    if errors:
        return errors

    json_names = [name for name in application.EVALUATION_FILES if name.endswith(".json")]
    try:
        data = {name: json.loads((package_root / name).read_text(encoding="utf-8")) for name in json_names}
    except json.JSONDecodeError as exc:
        return [f"evaluation package contains invalid JSON: {exc}"]
    for name, value in data.items():
        if not _canonical(package_root / name, value):
            errors.append(f"non-canonical JSON: {name}")
        if value.get("application_id") != application.APPLICATION_ID:
            errors.append(f"application_id mismatch: {name}")

    plan = data["application_plan.json"]
    registry = data["input_bundle_registry.json"]
    primary = data["primary_results.json"].get("entries", [])
    aggregates = data["verification_aggregates.json"].get("entries", [])
    report = data["application_validation_report.json"]
    lock = data["application_lock.json"]

    if len(primary) != application.EXPECTED_PRIMARY_UNITS:
        errors.append("primary result count is not eight")
    expected_units = [
        (entry.get("dataset_release"), entry.get("comparison_kind"))
        for entry in registry.get("bundles", [])
    ]
    actual_units = [(entry.get("dataset_release"), entry.get("comparison_kind")) for entry in primary]
    if actual_units != expected_units:
        errors.append("primary result order does not match the frozen execution")
    for entry in primary:
        _validate_primary(entry, errors)
    _validate_primary_csv(package_root / "primary_results.csv", primary, errors)
    _validate_aggregates(primary, aggregates, errors)

    required_plan = {
        "source_execution_id": application.EXECUTION_ID,
        "source_execution_commit": application.SOURCE_EXECUTION_COMMIT,
        "source_execution_tag": application.SOURCE_EXECUTION_TAG,
        "decision_policy_id": application.POLICY_ID,
        "decision_policy_commit": application.POLICY_COMMIT,
        "decision_policy_tag": application.POLICY_TAG,
        "sourceafis_version": application.SOURCEAFIS_VERSION,
        "threshold": application.THRESHOLD_TEXT, "operator": application.OPERATOR,
        "expected_rows": application.EXPECTED_ROWS,
        "matcher_execution": False, "java_required": False, "score_analysis_allowed": False,
        "threshold_sweep_allowed": False, "row_level_derived_output_tracked": False,
        "external_archive_verified": True,
    }
    for key, expected in required_plan.items():
        if plan.get(key) != expected:
            errors.append(f"application plan mismatch: {key}")
    if plan.get("application_code_commit") != lock.get("application_code_commit"):
        errors.append("application code commit mismatch between plan and lock")
    if registry.get("bundle_set_sha256") != lock.get("execution", {}).get("bundle_set_sha256"):
        errors.append("bundle-set hash mismatch between registry and lock")
    if registry.get("external_archive_id") != "external_archive/sourceafis_frozen_cohort_v1":
        errors.append("external archive identifier mismatch")
    if registry.get("external_archive_verified") is not True:
        errors.append("external archive is not recorded as verified")

    checks = report.get("checks", {})
    if report.get("valid") is not True or report.get("errors") != []:
        errors.append("application validation report is not a clean PASS")
    expected_checks = {
        "external_archive_verified": True, "input_execution_package_valid": True,
        "input_bundles_valid": 8, "input_rows_valid": 4000, "policy_package_valid": True,
        "threshold": "40.0", "operator": ">=", "unrounded_scores_used": True,
        "decision_rows_generated": 4000, "primary_reporting_units": 8,
        "verification_aggregates": 2, "matcher_executed": False, "java_invoked": False,
        "threshold_sweep_performed": False, "score_distribution_computed": False,
        "raw_scores_in_committed_package": False, "row_level_decisions_tracked_by_git": False,
        "protected_areas_unchanged": True,
    }
    if checks != expected_checks:
        errors.append("application validation checks mismatch")
    if application.PROCESS_NOTE_QUALIFICATION_DISPLAY not in report.get("process_notes", []):
        errors.append("qualification-display process note is missing")
    if application.PROCESS_NOTE_EXECUTION_IDENTITY not in report.get("process_notes", []):
        errors.append("execution-identity deviation note is missing")
    if not any(
        isinstance(note, str) and note.startswith(application.PROCESS_NOTE_CODE_FIX_PREFIX)
        and lock.get("application_code_commit", "") in note
        for note in report.get("process_notes", [])
    ):
        errors.append("application code-fix deviation note is missing")

    if lock.get("total_input_rows") != 4000 or lock.get("total_derived_decisions") != 4000:
        errors.append("application lock row totals mismatch")
    if lock.get("primary_unit_count") != 8 or lock.get("aggregate_count") != 2:
        errors.append("application lock reporting counts mismatch")
    if lock.get("threshold") != "40.0" or lock.get("operator") != ">=":
        errors.append("application lock policy mismatch")
    if "evaluations/sourceafis_policy_application_v1/application_lock.json" in lock.get("files", {}):
        errors.append("application lock includes itself")
    if "evaluations/sourceafis_policy_application_v1/SHA256SUMS.txt" in lock.get("files", {}):
        errors.append("application lock includes SHA256SUMS.txt")
    for relative, record in lock.get("files", {}).items():
        target = package_root / PurePosixPath(relative).name
        if not target.is_file():
            errors.append(f"locked evaluation file is missing: {relative}")
        elif record != {"sha256": application.file_sha256(target), "size_bytes": target.stat().st_size}:
            errors.append(f"locked evaluation file mismatch: {relative}")
    for relative, record in lock.get("code_files", {}).items():
        target = repository_root / PurePosixPath(relative)
        if not target.is_file() or record != {"sha256": application.file_sha256(target), "size_bytes": target.stat().st_size}:
            errors.append(f"locked application code mismatch: {relative}")

    checksums, checksum_errors = _parse_checksums(package_root / "SHA256SUMS.txt")
    errors.extend(checksum_errors)
    expected_checksum_names = sorted(name for name in application.EVALUATION_FILES if name != "SHA256SUMS.txt")
    if sorted(checksums) != expected_checksum_names:
        errors.append("SHA256SUMS file set mismatch")
    for name in expected_checksum_names:
        if checksums.get(name) != application.file_sha256(package_root / name):
            errors.append(f"SHA256SUMS mismatch: {name}")

    for name, value in data.items():
        for key, child in _iter_items(value):
            if key.lower() in _FORBIDDEN_KEYS:
                errors.append(f"forbidden private or analytic key in {name}: {key}")
            if isinstance(child, str) and (_ABSOLUTE_WINDOWS_PATH.search(child) or _ABSOLUTE_POSIX_PATH.search(child)):
                errors.append(f"absolute local path in {name}: {key}")
    combined_text = "\n".join((package_root / name).read_text(encoding="utf-8") for name in application.EVALUATION_FILES)
    if _ABSOLUTE_WINDOWS_PATH.search(combined_text) or _ABSOLUTE_POSIX_PATH.search(combined_text):
        errors.append("absolute local path found in evaluation package")
    if re.search(r"(?i)\b(?:hostname|username)\s*[:=]", combined_text):
        errors.append("username or hostname found in evaluation package")
    with (package_root / "primary_results.csv").open("r", encoding="utf-8", newline="") as handle:
        csv_header = {field.lower() for field in (csv.DictReader(handle).fieldnames or [])}
    if csv_header.intersection(_FORBIDDEN_KEYS):
        errors.append("committed CSV contains a forbidden column")
    _validate_code_boundaries(repository_root, errors)

    try:
        frozen = application.validate_frozen_packages(repository_root)
        state = application.verify_clean_worktree(repository_root)
    except (application.ApplicationBlocked, OSError, KeyError, ValueError) as exc:
        errors.append(f"source or protected package validation failed: {exc}")
        frozen = None
        state = {}
    if frozen is not None:
        if registry.get("source_execution_package_sha256") != frozen["execution_package_sha256"]:
            errors.append("source execution package hash mismatch")
        if registry.get("source_execution_lock_sha256") != application.file_sha256(
            repository_root / "executions" / application.EXECUTION_ID / "execution_lock.json"
        ):
            errors.append("source execution lock hash mismatch")
    for path, expected in application.PROTECTED_GIT_TREES.items():
        if state.get(path) != expected or lock.get("protected_git_trees", {}).get(path) != expected:
            errors.append(f"protected area tree mismatch: {path}")
    if results_root is not None and frozen is not None:
        _validate_local_replay(
            repository_root, package_root, Path(results_root).resolve(), frozen,
            primary, aggregates, lock, errors,
        )
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="validate-sourceafis-policy-application-v1")
    parser.add_argument("--repository-root", type=Path, default=_REPOSITORY_ROOT)
    parser.add_argument("--results-root", type=Path, default=None)
    args = parser.parse_args(argv)
    repository_root = args.repository_root.resolve()
    package_root = repository_root / "evaluations" / application.APPLICATION_ID
    if not package_root.is_dir():
        print(f"evaluation package is absent: evaluations/{application.APPLICATION_ID}", file=sys.stderr)
        return 1
    errors = validate_package_root(repository_root, package_root, results_root=args.results_root)
    if errors:
        print("SourceAFIS policy application v1 validation: FAIL", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print("SourceAFIS policy application v1 validation: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
