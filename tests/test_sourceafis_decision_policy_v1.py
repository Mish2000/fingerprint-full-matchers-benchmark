"""Dataset-independent acceptance tests for SourceAFIS decision policy v1."""

from __future__ import annotations

import ast
import json
import math
import sys
from pathlib import Path

import pytest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
TOOLS_ROOT = REPOSITORY_ROOT / "tools"
if str(TOOLS_ROOT) not in sys.path:
    sys.path.insert(0, str(TOOLS_ROOT))

import validate_sourceafis_decision_policy_v1 as policy  # noqa: E402


POLICY_ROOT = REPOSITORY_ROOT / "policies" / policy.POLICY_ID
SAMPLE_COUNTS = {
    "planned_pairs": 4,
    "successful_scores": 3,
    "technical_failures": 1,
    "same_decisions": 2,
    "different_decisions": 1,
    "no_decisions": 1,
    "correct_decisions": 2,
    "incorrect_decisions": 1,
}


def _evaluate(score):
    return policy.evaluate_synthetic_result("ok", score, None, "plain_roll_genuine")


def _json(name):
    return json.loads((POLICY_ROOT / name).read_text(encoding="utf-8"))


def _validator_imports():
    tree = ast.parse((TOOLS_ROOT / f"validate_{policy.POLICY_ID}.py").read_text(encoding="utf-8"))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


def test_01_score_just_below_threshold_is_different():
    assert _evaluate(39.999999999999)["decision"] == "different"


def test_02_score_at_threshold_is_same():
    assert _evaluate(40.0)["decision"] == "same"


def test_03_score_just_above_threshold_is_same():
    assert _evaluate(40.000000000001)["decision"] == "same"


def test_04_zero_score_is_different():
    assert _evaluate(0.0)["decision"] == "different"


def test_05_large_positive_score_is_same():
    assert _evaluate(1_000_000.0)["decision"] == "same"


def test_06_nan_is_invalid_input():
    assert _evaluate(math.nan)["policy_application_status"] == "INVALID_INPUT"


def test_07_positive_infinity_is_invalid_input():
    assert _evaluate(math.inf)["policy_application_status"] == "INVALID_INPUT"


def test_08_negative_infinity_is_invalid_input():
    assert _evaluate(-math.inf)["policy_application_status"] == "INVALID_INPUT"


def test_09_negative_score_is_invalid_input():
    assert _evaluate(-0.000001)["policy_application_status"] == "INVALID_INPUT"


def test_10_missing_success_score_is_invalid_input():
    assert _evaluate(None)["policy_application_status"] == "INVALID_INPUT"


def test_11_well_formed_failure_is_no_decision():
    result = policy.evaluate_synthetic_result("compare_error", None, "technical_error", "plain_self")
    assert result["decision"] == "no_decision"


def test_12_failure_with_score_is_invalid_input():
    result = policy.evaluate_synthetic_result("compare_error", 0.0, "technical_error", "plain_self")
    assert result["policy_application_status"] == "INVALID_INPUT"


def test_13_failure_without_error_code_is_invalid_input():
    result = policy.evaluate_synthetic_result("compare_error", None, None, "plain_self")
    assert result["policy_application_status"] == "INVALID_INPUT"


def test_14_failure_is_not_different():
    result = policy.evaluate_synthetic_result("compare_error", None, "technical_error", "plain_self")
    assert result["decision"] != "different"


def test_15_failure_is_not_false_non_match():
    result = policy.evaluate_synthetic_result("compare_error", None, "technical_error", "plain_self")
    assert result["outcome"] != "false_non_match"


def test_16_failure_is_not_false_match():
    result = policy.evaluate_synthetic_result("compare_error", None, "technical_error", "plain_roll_next_subject")
    assert result["outcome"] != "false_match"


def test_17_plain_self_expected_same():
    assert policy.EXPECTED_CLASS["plain_self"] == "same"


def test_18_roll_self_expected_same():
    assert policy.EXPECTED_CLASS["roll_self"] == "same"


def test_19_plain_roll_genuine_expected_same():
    assert policy.EXPECTED_CLASS["plain_roll_genuine"] == "same"


def test_20_plain_roll_next_subject_expected_different():
    assert policy.EXPECTED_CLASS["plain_roll_next_subject"] == "different"


def test_21_unknown_comparison_kind_is_invalid_input():
    result = policy.evaluate_synthetic_result("ok", 40.0, None, "unknown")
    assert result["policy_application_status"] == "INVALID_INPUT"


def test_22_expected_same_and_same_is_correct_same():
    assert policy.outcome_for("same", "same") == "correct_same"


def test_23_expected_same_and_different_is_false_non_match():
    assert policy.outcome_for("same", "different") == "false_non_match"


def test_24_expected_different_and_same_is_false_match():
    assert policy.outcome_for("different", "same") == "false_match"


def test_25_expected_different_and_different_is_correct_different():
    assert policy.outcome_for("different", "different") == "correct_different"


def test_26_no_decision_is_technical_failure():
    assert policy.outcome_for("same", "no_decision") == "technical_failure"


def test_27_decision_coverage_is_correct():
    metrics = policy.compute_reporting_metrics(expected_class="same", **SAMPLE_COUNTS)
    assert metrics["rates"]["decision_coverage"] == {"numerator": 3, "denominator": 4, "value": "0.750000"}


def test_28_technical_failure_rate_is_correct():
    metrics = policy.compute_reporting_metrics(expected_class="same", **SAMPLE_COUNTS)
    assert metrics["rates"]["technical_failure_rate"]["value"] == "0.250000"


def test_29_valid_only_correct_rate_is_correct():
    metrics = policy.compute_reporting_metrics(expected_class="same", **SAMPLE_COUNTS)
    assert metrics["rates"]["valid_only_correct_rate"]["value"] == "0.666667"


def test_30_strict_correct_completion_rate_is_correct():
    metrics = policy.compute_reporting_metrics(expected_class="same", **SAMPLE_COUNTS)
    assert metrics["rates"]["strict_correct_completion_rate"]["value"] == "0.500000"


def test_31_zero_denominator_returns_null():
    assert policy.machine_rate(0, 0) == {"numerator": 0, "denominator": 0, "value": None}


def test_32_machine_ratio_has_six_places():
    assert policy.machine_rate(1, 500)["value"] == "0.002000"


def test_33_human_percentage_has_two_places_and_counts():
    assert policy.human_rate(1, 500) == "1/500 (0.20%)"


def test_34_round_half_up_is_used():
    assert policy.machine_rate(1, 128)["value"] == "0.007813"
    assert policy.human_rate(1, 32) == "1/32 (3.13%)"


def test_35_all_raw_counts_are_retained():
    metrics = policy.compute_reporting_metrics(expected_class="same", **SAMPLE_COUNTS)
    assert metrics["counts"] == dict(sorted(SAMPLE_COUNTS.items()))


def test_36_threshold_sweep_is_prohibited():
    assert _json("decision_policy.json")["calibration"]["threshold_sweep_allowed"] is False


def test_37_no_threshold_by_release():
    scope = _json("decision_policy.json")["scope"]
    assert scope["single_threshold_for_all_releases"] is True


def test_38_no_threshold_by_comparison_kind():
    scope = _json("decision_policy.json")["scope"]
    assert scope["single_threshold_for_all_comparison_kinds"] is True


def test_39_challenge_records_are_included():
    assert _json("decision_policy.json")["scope"]["challenge_records_included"] is True


def test_40_self_is_not_pooled_with_genuine():
    reporting = _json("reporting_policy.json")["comparison_kind_reporting"]
    assert reporting["plain_self"]["pool_with_plain_roll_genuine"] is False
    assert reporting["roll_self"]["pool_with_plain_roll_genuine"] is False


def test_41_provenance_uses_only_official_sources():
    sources = _json("source_provenance.json")["official_sources"]
    assert {source["source_url"] for source in sources} == policy.OFFICIAL_URLS
    assert all(source["source_type"].startswith("official_") for source in sources)


def test_42_validator_never_reads_qualification_scores():
    source = (TOOLS_ROOT / f"validate_{policy.POLICY_ID}.py").read_text(encoding="utf-8")
    assert "qualification_results.json" not in source
    assert "qualify_sourceafis_runtime_v1" not in source


def test_43_validator_has_no_dataset_access_surface():
    source = (TOOLS_ROOT / f"validate_{policy.POLICY_ID}.py").read_text(encoding="utf-8")
    assert "fingerprint-datasets" not in source
    assert "dataset_root" not in source


def test_44_validator_cannot_execute_matcher():
    imports = _validator_imports()
    assert "subprocess" not in imports
    assert not any(name.startswith("fingerprint_benchmark") for name in imports)


def test_45_validator_does_not_import_runtime_runner():
    assert "fingerprint_benchmark.runner" not in _validator_imports()


def test_46_policy_lock_is_valid():
    errors = policy.validate_policy()
    assert not [error for error in errors if "lock" in error.lower() or "locked" in error.lower()]


def test_47_sha256sums_is_valid():
    errors = policy.validate_policy()
    assert not [error for error in errors if "sha256sums" in error.lower() or "checksum" in error.lower()]


def test_48_json_build_is_deterministic():
    for name in policy.POLICY_JSON_FILES:
        path = POLICY_ROOT / name
        assert path.read_bytes() == policy._canonical_json(json.loads(path.read_text(encoding="utf-8")))


def test_49_policy_publication_is_atomic_and_complete():
    reporting = _json("reporting_policy.json")
    assert reporting["publication"]["atomic_complete_package_required"] is True
    assert {path.name for path in POLICY_ROOT.iterdir() if path.is_file()} == set(policy.POLICY_FILES)
    assert not list(POLICY_ROOT.parent.glob(f"{policy.POLICY_ID}.candidate-*"))
    assert not list(POLICY_ROOT.parent.glob(f"{policy.POLICY_ID}.rollback-*"))


def test_50_protected_packages_remain_byte_identical():
    errors = policy.validate_policy()
    assert not [error for error in errors if "protected" in error.lower()]
