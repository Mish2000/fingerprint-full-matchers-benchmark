"""Read-only validation and synthetic tests for SourceAFIS decision policy v1."""

from __future__ import annotations

import hashlib
import json
import math
import re
import sys
from decimal import Decimal, ROUND_HALF_UP
from numbers import Real
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


POLICY_ID = "sourceafis_decision_policy_v1"
POLICY_VERSION = 1
SOURCEAFIS_VERSION = "3.18.1"
THRESHOLD_TEXT = "40.0"
THRESHOLD = float(THRESHOLD_TEXT)
OPERATOR = ">="
SCORE_SOURCE = "FingerprintMatcher.match"
SCORE_DIRECTION = "higher_is_more_similar"
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
POLICY_ROOT = REPOSITORY_ROOT / "policies" / POLICY_ID

POLICY_JSON_FILES = (
    "decision_policy.json",
    "policy_lock.json",
    "policy_validation_report.json",
    "reporting_policy.json",
    "source_provenance.json",
)
POLICY_FILES = (
    "README.md",
    "SHA256SUMS.txt",
    *POLICY_JSON_FILES,
)
LOCKED_FILES = (
    f"policies/{POLICY_ID}/README.md",
    f"policies/{POLICY_ID}/decision_policy.json",
    f"policies/{POLICY_ID}/policy_validation_report.json",
    f"policies/{POLICY_ID}/reporting_policy.json",
    f"policies/{POLICY_ID}/source_provenance.json",
    f"tests/test_{POLICY_ID}.py",
    f"tools/validate_{POLICY_ID}.py",
)
EXPECTED_CLASS = {
    "plain_self": "same",
    "roll_self": "same",
    "plain_roll_genuine": "same",
    "plain_roll_next_subject": "different",
}
EXPECTED_DENOMINATORS = {
    "decision_coverage": ("successful_scores", "planned_pairs"),
    "technical_failure_rate": ("technical_failures", "planned_pairs"),
    "valid_only_correct_rate": ("correct_decisions", "successful_scores"),
    "strict_correct_completion_rate": ("correct_decisions", "planned_pairs"),
}
OFFICIAL_URLS = {
    "https://sourceafis.machinezoo.com/java",
    "https://sourceafis.machinezoo.com/javadoc/com.machinezoo.sourceafis/com/machinezoo/sourceafis/FingerprintMatcher.html",
}
PROTECTED_LAYOUT = {
    "protocol": {
        "paths": ("protocols/supervisor_50x10_v1",),
        "suffixes": None,
    },
    "qualification": {
        "paths": ("qualification/sourceafis_runtime_v1",),
        "suffixes": None,
    },
    "runtime_sources": {
        "paths": (
            "src/fingerprint_benchmark",
            "apps/sourceafis-sidecar/pom.xml",
            "apps/sourceafis-sidecar/src/main",
        ),
        "suffixes": {".java", ".properties", ".py", ".xml"},
    },
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_json(data: Any) -> bytes:
    return (json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _invalid_result() -> dict[str, Any]:
    return {
        "decision": None,
        "expected_class": None,
        "outcome": None,
        "policy_application_status": "INVALID_INPUT",
    }


def outcome_for(expected_class: str, decision: str) -> str:
    if decision == "no_decision":
        return "technical_failure"
    mapping = {
        ("same", "same"): "correct_same",
        ("same", "different"): "false_non_match",
        ("different", "same"): "false_match",
        ("different", "different"): "correct_different",
    }
    if (expected_class, decision) not in mapping:
        raise ValueError("unsupported expected class or decision")
    return mapping[(expected_class, decision)]


def evaluate_synthetic_result(
    status: str,
    raw_score: float | None,
    error_code: str | None,
    comparison_kind: str,
) -> dict[str, Any]:
    """Apply the frozen policy to one synthetic row without any runtime access."""
    if comparison_kind not in EXPECTED_CLASS or not isinstance(status, str) or not status:
        return _invalid_result()
    expected_class = EXPECTED_CLASS[comparison_kind]
    if status == "ok":
        valid_number = isinstance(raw_score, Real) and not isinstance(raw_score, bool)
        if error_code is not None or not valid_number:
            return _invalid_result()
        score = float(raw_score)
        if not math.isfinite(score) or score < 0:
            return _invalid_result()
        decision = "same" if score >= THRESHOLD else "different"
    else:
        has_error_code = isinstance(error_code, str) and bool(error_code.strip())
        if raw_score is not None or not has_error_code:
            return _invalid_result()
        decision = "no_decision"
    return {
        "decision": decision,
        "expected_class": expected_class,
        "outcome": outcome_for(expected_class, decision),
        "policy_application_status": "OK",
    }


def machine_rate(numerator: int, denominator: int) -> dict[str, int | str | None]:
    if denominator < 0 or numerator < 0 or numerator > denominator:
        raise ValueError("invalid rate counts")
    value = None
    if denominator:
        ratio = (Decimal(numerator) / Decimal(denominator)).quantize(
            Decimal("0.000001"), rounding=ROUND_HALF_UP
        )
        value = format(ratio, ".6f")
    return {"denominator": denominator, "numerator": numerator, "value": value}


def human_rate(numerator: int, denominator: int) -> str:
    if denominator < 0 or numerator < 0 or numerator > denominator:
        raise ValueError("invalid rate counts")
    if denominator == 0:
        return f"{numerator}/{denominator} (N/A)"
    percentage = (Decimal(numerator) * Decimal(100) / Decimal(denominator)).quantize(
        Decimal("0.01"), rounding=ROUND_HALF_UP
    )
    return f"{numerator}/{denominator} ({percentage:.2f}%)"


def compute_reporting_metrics(*, expected_class: str, **counts: int) -> dict[str, Any]:
    required = {
        "planned_pairs",
        "successful_scores",
        "technical_failures",
        "same_decisions",
        "different_decisions",
        "no_decisions",
        "correct_decisions",
        "incorrect_decisions",
    }
    if set(counts) != required:
        raise ValueError("all and only required raw counts must be supplied")
    if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in counts.values()):
        raise ValueError("counts must be non-negative integers")
    if counts["successful_scores"] + counts["technical_failures"] != counts["planned_pairs"]:
        raise ValueError("planned-pair denominator invariant failed")
    if counts["same_decisions"] + counts["different_decisions"] != counts["successful_scores"]:
        raise ValueError("successful-score denominator invariant failed")
    if counts["no_decisions"] != counts["technical_failures"]:
        raise ValueError("no_decision invariant failed")
    if counts["correct_decisions"] + counts["incorrect_decisions"] != counts["successful_scores"]:
        raise ValueError("correctness invariant failed")
    if expected_class == "same":
        if counts["correct_decisions"] != counts["same_decisions"]:
            raise ValueError("expected-same correctness invariant failed")
        class_counts = {
            "correct_same_count": counts["same_decisions"],
            "false_non_match_count": counts["different_decisions"],
        }
        class_rates = {
            "false_non_match_rate_valid": machine_rate(counts["different_decisions"], counts["successful_scores"]),
            "match_rate_valid": machine_rate(counts["same_decisions"], counts["successful_scores"]),
        }
    elif expected_class == "different":
        if counts["correct_decisions"] != counts["different_decisions"]:
            raise ValueError("expected-different correctness invariant failed")
        class_counts = {
            "correct_different_count": counts["different_decisions"],
            "false_match_count": counts["same_decisions"],
        }
        class_rates = {
            "correct_reject_rate_valid": machine_rate(counts["different_decisions"], counts["successful_scores"]),
            "false_match_rate_valid": machine_rate(counts["same_decisions"], counts["successful_scores"]),
        }
    else:
        raise ValueError("unknown expected class")
    rates = {
        "decision_coverage": machine_rate(counts["successful_scores"], counts["planned_pairs"]),
        "strict_correct_completion_rate": machine_rate(counts["correct_decisions"], counts["planned_pairs"]),
        "technical_failure_rate": machine_rate(counts["technical_failures"], counts["planned_pairs"]),
        "valid_only_correct_rate": machine_rate(counts["correct_decisions"], counts["successful_scores"]),
    }
    return {
        "class_specific_counts": class_counts,
        "class_specific_rates": class_rates,
        "counts": dict(sorted(counts.items())),
        "rates": rates,
    }


def _tree_digest(
    repository_root: Path,
    paths: tuple[str, ...],
    suffixes: set[str] | None,
) -> tuple[str, int]:
    records: list[str] = []
    for relative_root in paths:
        root = repository_root / relative_root
        candidates = [root] if root.is_file() else sorted(root.rglob("*"))
        for path in candidates:
            if not path.is_file() or (suffixes is not None and path.suffix not in suffixes):
                continue
            relative = path.relative_to(repository_root).as_posix()
            records.append(f"{relative}|{path.stat().st_size}|{_sha256(path)}")
    payload = "\n".join(sorted(records, key=str.lower)).encode("utf-8")
    return hashlib.sha256(payload).hexdigest(), len(records)


def _iter_items(value: Any, prefix: tuple[str, ...] = ()):
    if isinstance(value, dict):
        for key, child in value.items():
            yield prefix, key, child
            yield from _iter_items(child, prefix + (key,))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _iter_items(child, prefix + (str(index),))


def _parse_checksums(path: Path) -> tuple[dict[str, str], list[str]]:
    checksums: dict[str, str] = {}
    errors: list[str] = []
    lines = path.read_text(encoding="utf-8").splitlines()
    checksum_paths: list[str] = []
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\\]+)", line)
        if not match:
            errors.append(f"invalid checksum line: {line!r}")
            continue
        digest, relative = match.groups()
        if relative in checksums:
            errors.append(f"duplicate checksum path: {relative}")
        checksums[relative] = digest
        checksum_paths.append(relative)
    if checksum_paths != sorted(checksum_paths):
        errors.append("SHA256SUMS.txt is not sorted by path")
    return checksums, errors


def validate_policy(repository_root: Path = REPOSITORY_ROOT) -> list[str]:
    policy_root = repository_root / "policies" / POLICY_ID
    errors: list[str] = []

    def require(condition: bool, message: str) -> None:
        if not condition:
            errors.append(message)

    required_paths = [policy_root / name for name in POLICY_FILES]
    required_paths.extend(repository_root / name for name in LOCKED_FILES if not name.startswith("policies/"))
    for path in required_paths:
        require(path.is_file(), f"missing required file: {path.relative_to(repository_root).as_posix()}")
    if errors:
        return errors

    data = {name: _load_json(policy_root / name) for name in POLICY_JSON_FILES}
    for name, value in data.items():
        path = policy_root / name
        require(path.read_bytes() == _canonical_json(value), f"non-canonical JSON: {name}")
        require(value.get("policy_id") == POLICY_ID, f"policy_id mismatch: {name}")
    readme = (policy_root / "README.md").read_text(encoding="utf-8")
    require(POLICY_ID in readme, "README omits policy_id")

    decision = data["decision_policy.json"]
    reporting = data["reporting_policy.json"]
    provenance = data["source_provenance.json"]
    report = data["policy_validation_report.json"]
    lock = data["policy_lock.json"]

    require(decision.get("policy_version") == POLICY_VERSION, "policy version is not 1")
    require(decision.get("status") == "frozen", "policy status is not frozen")
    method = decision.get("method", {})
    rule = decision.get("decision_rule", {})
    require(method.get("sourceafis_version") == SOURCEAFIS_VERSION, "SourceAFIS version mismatch")
    require(method.get("score_source") == SCORE_SOURCE, "score source mismatch")
    require(method.get("score_direction") == SCORE_DIRECTION, "score direction mismatch")
    require(method.get("score_type") == "raw_similarity", "score type mismatch")
    require(rule.get("threshold") == THRESHOLD_TEXT, "threshold is not exactly decimal 40.0")
    require(rule.get("operator") == OPERATOR, "operator is not exactly >=")
    require(rule.get("round_before_comparison") is False, "score would be rounded before decision")
    require(rule.get("epsilon_comparison") is False, "epsilon comparison is enabled")
    require(
        [rule.get("same_decision"), rule.get("different_decision"), rule.get("technical_failure_decision")]
        == ["same", "different", "no_decision"],
        "decision names are not frozen",
    )
    require(decision.get("expected_class") == EXPECTED_CLASS, "expected-class mapping mismatch")
    scope = decision.get("scope", {})
    require(scope.get("dataset_releases") == ["sd300b", "sd300c"], "dataset-release scope mismatch")
    require(scope.get("comparison_kinds") == list(EXPECTED_CLASS), "comparison-kind scope mismatch")
    require(scope.get("single_threshold_for_all_releases") is True, "per-release threshold is possible")
    require(scope.get("single_threshold_for_all_comparison_kinds") is True, "per-kind threshold is possible")
    require(scope.get("challenge_records_included") is True, "challenge records are excluded")
    calibration = decision.get("calibration", {})
    require(calibration.get("selection_mode") == "official_fixed_recommendation", "selection mode mismatch")
    require(calibration.get("performed") is False, "calibration is marked performed")
    require(calibration.get("evaluation_data_used") is False, "evaluation data is marked used")
    require(calibration.get("qualification_scores_used") is False, "qualification scores are marked used")
    require(calibration.get("threshold_sweep_allowed") is False, "threshold sweep is allowed")
    require(calibration.get("post_hoc_change_allowed") is False, "post-hoc threshold change is allowed")
    valid_score = decision.get("valid_score", {})
    failure = decision.get("technical_failure", {})
    require(
        valid_score == {
            "error_code_must_be_absent": True,
            "error_message_must_be_absent": True,
            "finite": True,
            "non_negative": True,
            "requires_status": "ok",
        },
        "valid-score policy mismatch",
    )
    require(failure.get("raw_score_must_be_absent") is True, "failure permits a score")
    require(failure.get("error_code_must_be_present") is True, "failure permits missing error code")
    require(failure.get("decision") == "no_decision", "failure is not no_decision")

    require(reporting.get("primary_grouping") == ["dataset_release", "comparison_kind"], "primary grouping mismatch")
    comparison_reporting = reporting.get("comparison_kind_reporting", {})
    for kind, expected in EXPECTED_CLASS.items():
        require(comparison_reporting.get(kind, {}).get("expected_class") == expected, f"reporting class mismatch: {kind}")
    require(comparison_reporting.get("plain_self", {}).get("pool_with_plain_roll_genuine") is False, "plain self is pooled")
    require(comparison_reporting.get("roll_self", {}).get("pool_with_plain_roll_genuine") is False, "roll self is pooled")
    denominators = reporting.get("denominators", {})
    for name, (numerator, denominator) in EXPECTED_DENOMINATORS.items():
        value = denominators.get(name, {})
        require(value.get("numerator") == numerator and value.get("denominator") == denominator, f"denominator mismatch: {name}")
    technical = reporting.get("technical_failures", {})
    require(technical.get("converted_to_score_zero") is False, "failure converts to score zero")
    require(technical.get("converted_to_different") is False, "failure converts to different")
    require(technical.get("included_in_planned_pair_denominator") is True, "failure missing from planned denominator")
    require(technical.get("excluded_from_biometric_rate_denominator") is True, "failure included in biometric denominator")
    secondary = reporting.get("secondary_verification_aggregate", {})
    require(secondary.get("include") == ["plain_roll_genuine", "plain_roll_next_subject"], "verification aggregate include mismatch")
    require(secondary.get("exclude") == ["plain_self", "roll_self"], "self comparison enters verification aggregate")
    require(reporting.get("rounding") == {
        "decision_uses_unrounded_score": True,
        "human_percentage_decimal_places": 2,
        "machine_ratio_decimal_places": 6,
        "mode": "ROUND_HALF_UP",
    }, "rounding policy mismatch")

    for name, value in data.items():
        for _prefix, key, child in _iter_items(value):
            require(key not in {"alternative_threshold", "per_kind_threshold", "per_release_threshold", "threshold_list", "thresholds"}, f"alternative threshold key in {name}: {key}")
            if key == "threshold":
                require(child == THRESHOLD_TEXT, f"non-frozen threshold in {name}")
            require(key not in {"calibration_input", "evaluation_data_path", "qualification_score_path"}, f"forbidden calibration input in {name}: {key}")
            require(key not in {"raw_score", "raw_scores", "scores"}, f"raw score payload key in {name}: {key}")

    sources = provenance.get("official_sources", [])
    source_urls = {source.get("source_url") for source in sources}
    require(source_urls == OFFICIAL_URLS, "official provenance URL set mismatch")
    for source in sources:
        parsed = urlparse(source.get("source_url", ""))
        require(parsed.scheme == "https" and parsed.hostname == "sourceafis.machinezoo.com", "non-official provenance source")
        require(source.get("source_type") in {"official_documentation", "official_javadoc"}, "non-official source type")
        require(source.get("version") == SOURCEAFIS_VERSION, "provenance version mismatch")
    require(provenance.get("sourceafis_version") == SOURCEAFIS_VERSION, "provenance SourceAFIS version mismatch")
    require(provenance.get("decision_rule") == {"operator": OPERATOR, "threshold": THRESHOLD_TEXT}, "provenance decision mismatch")
    derivation = provenance.get("threshold_derivation", {})
    require(all(derivation.get(key) is False for key in (
        "challenge_records_used", "evaluation_scores_used", "previous_project_results_used", "qualification_scores_used"
    )), "prohibited threshold derivation source used")
    summary = provenance.get("summary", {})
    require("approximate" in summary.get("fmr_approximation_caveat", "").lower(), "FMR approximation caveat missing")
    require("application" in summary.get("application_dependent_caveat", "").lower(), "application-dependent caveat missing")

    expected_report = {
        "cohort_scores_read": False,
        "evaluation_data_used": False,
        "expected_classes_valid": True,
        "failure_policy_valid": True,
        "fmr_caveat_present": True,
        "matcher_executed": False,
        "operator": OPERATOR,
        "qualification_scores_used": False,
        "reporting_denominators_valid": True,
        "self_reporting_separate": True,
        "single_threshold": True,
        "sourceafis_version": SOURCEAFIS_VERSION,
        "threshold": THRESHOLD_TEXT,
        "threshold_sweep_allowed": False,
    }
    require(report.get("valid") is True and report.get("errors") == [], "validation report is not a clean PASS")
    require(report.get("checks") == expected_report, "validation report checks mismatch")
    require(len(report.get("warnings", [])) == 2, "validation report warning set mismatch")

    text_paths = [policy_root / name for name in POLICY_FILES]
    combined = "\n".join(path.read_text(encoding="utf-8") for path in text_paths)
    require(re.search(r"(?i)\b[a-z]:[\\/]", combined) is None, "absolute Windows path found")
    require(re.search(r"(?i)(?:^|[\s\"'])/(?:home|root|tmp|users)/", combined) is None, "absolute local POSIX path found")
    require("file://" not in combined.lower(), "local file URL found")
    require(re.search(r"(?i)\b(?:hostname|username)\s*[:=]", combined) is None, "username or hostname found")
    forbidden_qualification_results = "qualification_" + "results.json"
    require(forbidden_qualification_results not in combined, "qualification results reference found")
    for name in POLICY_JSON_FILES:
        text = (policy_root / name).read_text(encoding="utf-8")
        require(re.search(r"\d{4}-\d{2}-\d{2}[Tt][0-9:]+", text) is None, f"dynamic timestamp in {name}")
        for _prefix, key, _child in _iter_items(data[name]):
            require(key not in {"created_at", "generated_at", "timestamp", "updated_at"}, f"dynamic timestamp key in {name}")
            require(key not in {"hostname", "machine_name", "user_name", "username"}, f"identity metadata key in {name}")

    require(lock.get("policy_version") == POLICY_VERSION, "lock policy version mismatch")
    require(lock.get("sourceafis_version") == SOURCEAFIS_VERSION, "lock SourceAFIS version mismatch")
    require(lock.get("threshold") == THRESHOLD_TEXT and lock.get("operator") == OPERATOR, "lock decision mismatch")
    require(lock.get("commits") == {
        "protocol": "29d8de0180403e9aa8a5e81cc468664b96dc8932",
        "qualification": "78af9d227a68456f96f1d63d2547222d5435bb5f",
        "runtime": "db1e499f0ee3a5457ec71fbc7feba22214d34116",
    }, "lock commit set mismatch")
    locked_files = lock.get("files", {})
    require(set(locked_files) == set(LOCKED_FILES), "lock file set mismatch")
    require(f"policies/{POLICY_ID}/policy_lock.json" not in locked_files, "lock includes itself")
    require(f"policies/{POLICY_ID}/SHA256SUMS.txt" not in locked_files, "lock includes checksum index")
    for relative in LOCKED_FILES:
        path = repository_root / relative
        record = locked_files.get(relative, {})
        require(record.get("sha256") == _sha256(path), f"locked hash mismatch: {relative}")
        require(record.get("size_bytes") == path.stat().st_size, f"locked size mismatch: {relative}")
    provenance_path = policy_root / "source_provenance.json"
    require(lock.get("source_provenance_sha256") == _sha256(provenance_path), "source provenance lock mismatch")

    protected = lock.get("protected_areas", {})
    require(set(protected) == set(PROTECTED_LAYOUT), "protected-area set mismatch")
    for name, layout in PROTECTED_LAYOUT.items():
        digest, file_count = _tree_digest(repository_root, layout["paths"], layout["suffixes"])
        record = protected.get(name, {})
        require(record.get("paths") == list(layout["paths"]), f"protected paths mismatch: {name}")
        require(record.get("tree_sha256") == digest, f"protected tree changed: {name}")
        require(record.get("file_count") == file_count, f"protected file count changed: {name}")

    checksums, checksum_errors = _parse_checksums(policy_root / "SHA256SUMS.txt")
    errors.extend(checksum_errors)
    checksum_names = sorted(path.name for path in policy_root.iterdir() if path.is_file() and path.name != "SHA256SUMS.txt")
    require(set(checksums) == set(checksum_names), "SHA256SUMS file set mismatch")
    for name in checksum_names:
        require(checksums.get(name) == _sha256(policy_root / name), f"SHA256SUMS mismatch: {name}")
    return errors


def main() -> int:
    errors = validate_policy()
    if errors:
        print("SourceAFIS decision policy v1 validation: FAIL", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print("SourceAFIS decision policy v1 validation: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
