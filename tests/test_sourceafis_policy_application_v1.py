"""Synthetic, dataset-independent tests for the frozen policy application."""

from __future__ import annotations

import ast
import csv
import hashlib
import json
import sys
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
TOOLS_ROOT = REPOSITORY_ROOT / "tools"
if str(TOOLS_ROOT) not in sys.path:
    sys.path.insert(0, str(TOOLS_ROOT))

import apply_sourceafis_decision_policy_v1 as application  # noqa: E402
import validate_sourceafis_policy_application_v1 as validator  # noqa: E402


def _row(
    *, status: str = "ok", score: str = "40.0", error_code: str = "", error_message: str = "",
) -> dict[str, str]:
    return {"status": status, "raw_score": score, "error_code": error_code, "error_message": error_message}


@pytest.mark.parametrize(
    ("score", "decision"),
    [
        ("39.999999999999", "different"),
        ("40.0", "same"),
        ("40.000000000001", "same"),
        ("0.0", "different"),
        ("39.999999999999999999999999999999", "different"),
        ("40.000000000000000000000000000001", "same"),
    ],
)
def test_threshold_boundaries_use_exact_decimal(score: str, decision: str) -> None:
    assert application.decision_for_row(_row(score=score), "plain_roll_genuine")[1] == decision


@pytest.mark.parametrize("score", ["NaN", "sNaN", "Infinity", "-Infinity", "-0.000001", "not-a-number"])
def test_invalid_success_scores_are_rejected(score: str) -> None:
    with pytest.raises(application.InvalidInput):
        application.decision_for_row(_row(score=score), "plain_self")


@pytest.mark.parametrize(
    "row",
    [
        _row(score=""),
        _row(error_code="unexpected"),
        _row(error_message="unexpected"),
        _row(status="comparison_failure", score="1", error_code="failure"),
        _row(status="comparison_failure", score="", error_code=""),
    ],
)
def test_invalid_success_and_failure_shapes_are_rejected(row: dict[str, str]) -> None:
    with pytest.raises(application.InvalidInput):
        application.decision_for_row(row, "roll_self")


def test_valid_failure_is_no_decision() -> None:
    expected, decision, outcome, raw_payload, error_payload = application.decision_for_row(
        _row(status="comparison_failure", score="", error_code="transport_error", error_message="synthetic"),
        "plain_roll_next_subject",
    )
    assert (expected, decision, outcome, raw_payload, error_payload) == (
        "different", "no_decision", "technical_failure", None, "transport_error",
    )


def test_unknown_comparison_kind_is_rejected() -> None:
    with pytest.raises(application.InvalidInput):
        application.decision_for_row(_row(), "unknown")


@pytest.mark.parametrize(
    ("kind", "expected"),
    [
        ("plain_self", "same"),
        ("roll_self", "same"),
        ("plain_roll_genuine", "same"),
        ("plain_roll_next_subject", "different"),
    ],
)
def test_expected_class_mapping(kind: str, expected: str) -> None:
    assert application.decision_for_row(_row(), kind)[0] == expected


@pytest.mark.parametrize(
    ("expected", "decision", "outcome"),
    [
        ("same", "same", "correct_same"),
        ("same", "different", "false_non_match"),
        ("different", "same", "false_match"),
        ("different", "different", "correct_different"),
        ("same", "no_decision", "technical_failure"),
        ("different", "no_decision", "technical_failure"),
    ],
)
def test_outcome_mapping(expected: str, decision: str, outcome: str) -> None:
    assert application.outcome_for(expected, decision) == outcome


@pytest.mark.parametrize(
    ("numerator", "denominator", "value"),
    [
        (0, 0, None),
        (0, 500, "0.000000"),
        (1, 500, "0.002000"),
        (1, 3, "0.333333"),
        (2, 3, "0.666667"),
        (500, 500, "1.000000"),
    ],
)
def test_machine_rates(numerator: int, denominator: int, value: str | None) -> None:
    assert application.machine_rate(numerator, denominator) == {
        "numerator": numerator, "denominator": denominator, "value": value,
    }


@pytest.mark.parametrize(
    ("numerator", "denominator", "value"),
    [
        (0, 0, "0/0 (N/A)"),
        (0, 500, "0/500 (0.00%)"),
        (1, 500, "1/500 (0.20%)"),
        (1, 8, "1/8 (12.50%)"),
        (2, 3, "2/3 (66.67%)"),
    ],
)
def test_human_rates_always_include_counts(numerator: int, denominator: int, value: str) -> None:
    assert application.human_rate(numerator, denominator) == value


@pytest.mark.parametrize("counts", [(-1, 1), (2, 1), (1, -1)])
def test_invalid_rate_counts_are_rejected(counts: tuple[int, int]) -> None:
    with pytest.raises(ValueError):
        application.machine_rate(*counts)


def _derived(decision: str, outcome: str, expected: str = "same") -> dict[str, str]:
    return {"decision": decision, "outcome": outcome, "expected_class": expected}


def test_summary_counts_and_rates() -> None:
    rows = [
        _derived("same", "correct_same"),
        _derived("different", "false_non_match"),
        _derived("no_decision", "technical_failure"),
    ]
    result = application.summarize_rows(rows)
    assert result["planned_pairs"] == 3
    assert result["successful_scores"] == 2
    assert result["technical_failures"] == 1
    assert result["correct_decisions"] == 1
    assert result["incorrect_decisions"] == 1
    assert result["decision_coverage"] == application.machine_rate(2, 3)
    assert result["technical_failure_rate"] == application.machine_rate(1, 3)
    assert result["valid_only_correct_rate"] == application.machine_rate(1, 2)
    assert result["strict_correct_completion_rate"] == application.machine_rate(1, 3)
    assert result["match_rate_valid"] == application.machine_rate(1, 2)
    assert "false_match_rate_valid" not in result


def test_expected_different_summary_has_only_appropriate_class_rates() -> None:
    rows = [
        _derived("different", "correct_different", "different"),
        _derived("same", "false_match", "different"),
    ]
    result = application.summarize_rows(rows)
    assert result["correct_different_count"] == 1
    assert result["false_match_count"] == 1
    assert result["false_match_rate_valid"] == application.machine_rate(1, 2)
    assert "false_non_match_rate_valid" not in result


def _primary(release: str, kind: str, planned: int = 10, successful: int = 9) -> dict[str, object]:
    expected = application.EXPECTED_CLASS[kind]
    failure = planned - successful
    if expected == "same":
        correct_same, correct_different, false_matches, false_non_matches = 8, 0, 0, successful - 8
    else:
        correct_same, correct_different, false_matches, false_non_matches = 0, 7, successful - 7, 0
    return {
        "dataset_release": release, "comparison_kind": kind,
        "planned_pairs": planned, "successful_scores": successful, "technical_failures": failure,
        "correct_same": correct_same, "correct_different": correct_different,
        "false_matches": false_matches, "false_non_matches": false_non_matches,
    }


def test_verification_aggregate_excludes_self_and_uses_correct_denominators() -> None:
    entries = []
    for kind in application.EXPECTED_CLASS:
        item = _primary("sd300b", kind)
        if kind in {"plain_self", "roll_self"}:
            item.update({"planned_pairs": 999, "successful_scores": 999})
        entries.append(item)
    aggregate = application.verification_aggregate(entries, "sd300b")
    assert aggregate["plain_self_included"] is False
    assert aggregate["roll_self_included"] is False
    assert aggregate["genuine_planned"] == 10
    assert aggregate["impostor_planned"] == 10
    assert aggregate["fnmr_valid"] == application.machine_rate(1, 9)
    assert aggregate["fmr_valid"] == application.machine_rate(2, 9)
    assert aggregate["verification_decision_coverage"] == application.machine_rate(18, 20)
    assert aggregate["verification_strict_correct_completion_rate"] == application.machine_rate(15, 20)


def test_aggregates_are_separate_per_release() -> None:
    entries = [_primary(release, kind) for release in ("sd300b", "sd300c") for kind in application.EXPECTED_CLASS]
    aggregates = [application.verification_aggregate(entries, release) for release in ("sd300b", "sd300c")]
    assert [item["dataset_release"] for item in aggregates] == ["sd300b", "sd300c"]
    assert len(aggregates) == 2


def _manifest_row(index: int, kind: str = "plain_roll_genuine") -> dict[str, str]:
    values = {
        "pair_id": f"PAIR_{index}", "comparison_kind": kind, "dataset_release": "sd300b",
        "subject_index_a": str(index), "subject_id_a": f"A{index}", "subject_index_b": str(index),
        "subject_id_b": f"B{index}", "canonical_finger": "1", "hand": "right",
        "finger_name": "thumb", "capture_type_a": "PLAIN", "capture_type_b": "ROLL",
        "nominal_ppi_a": "1000", "nominal_ppi_b": "1000", "relative_path_a": f"a/{index}.png",
        "relative_path_b": f"b/{index}.png", "sha256_a": hashlib.sha256(f"a{index}".encode()).hexdigest(),
        "sha256_b": hashlib.sha256(f"b{index}".encode()).hexdigest(), "source_frgp_a": "11",
        "source_frgp_b": "1", "image_status_a": "valid", "image_status_b": "valid",
        "pair_status": "valid", "source_pair_id": f"SOURCE_{index}",
    }
    return values


def _write_manifest(path: Path, rows: list[dict[str, str]]) -> tuple[str, ...]:
    fields = tuple(rows[0])
    path.parent.mkdir(parents=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    return fields


def _source_result(source: dict[str, str], *, run_id: str, manifest_sha: str, index: int,
                   score: str = "40.0") -> dict[str, str]:
    values = {field: "" for field in application.RESULT_COLUMNS}
    values.update({
        "run_id": run_id, "method": "sourceafis", "method_version": application.SOURCEAFIS_VERSION,
        "protocol_id": "supervisor_50x10_v1", "protocol_version": "1",
        "manifest_relative_path": "sd300b/plain_roll_genuine.csv", "manifest_sha256": manifest_sha,
        "pair_index": str(index), **source, "prepare_a_status": "ok", "prepare_b_status": "ok",
        "comparison_status": "ok", "status": "ok", "raw_score": score,
        "score_direction": "higher_is_more_similar", "score_semantics": "raw_similarity",
    })
    values["score_payload_sha256"] = application._score_payload_hash(values)
    return values


def _synthetic_bundle(tmp_path: Path, *, result_order: list[int] = [1, 2, 3]) -> tuple[Path, Path, dict]:
    repository = tmp_path / "repo"
    results = tmp_path / "results"
    manifest = repository / "protocols" / "supervisor_50x10_v1" / "sd300b" / "plain_roll_genuine.csv"
    sources = [_manifest_row(index) for index in (1, 2, 3)]
    _write_manifest(manifest, sources)
    manifest_sha = application.file_sha256(manifest)
    run_id = "a" * 24
    bundle = results / "raw" / run_id
    bundle.mkdir(parents=True)
    rows = [_source_result(sources[index - 1], run_id=run_id, manifest_sha=manifest_sha, index=index)
            for index in result_order]
    with (bundle / "results.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=application.RESULT_COLUMNS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    provenance = {"sourceafis_version": application.SOURCEAFIS_VERSION, "jar_sha256": application.JAR_SHA256}
    (bundle / "provenance.json").write_text(json.dumps(provenance), encoding="utf-8")
    metadata = {
        "run_id": run_id, "row_count": 3,
        "results_sha256": application.file_sha256(bundle / "results.csv"),
        "provenance_sha256": application.file_sha256(bundle / "provenance.json"),
    }
    (bundle / "metadata.json").write_text(json.dumps(metadata), encoding="utf-8")
    entry = {
        "run_id": run_id, "bundle_relative_path": f"raw/{run_id}",
        "manifest_relative_path": "sd300b/plain_roll_genuine.csv", "manifest_sha256": manifest_sha,
        "metadata_sha256": application.file_sha256(bundle / "metadata.json"),
        "provenance_sha256": application.file_sha256(bundle / "provenance.json"),
        "results_csv_sha256": application.file_sha256(bundle / "results.csv"),
        "comparison_kind": "plain_roll_genuine", "dataset_release": "sd300b",
        "row_count": 3,
    }
    return repository, results, entry


def test_reordered_rows_are_rejected(tmp_path: Path) -> None:
    repository, results, entry = _synthetic_bundle(tmp_path, result_order=[2, 1, 3])
    with pytest.raises(application.InvalidInput, match="reordered"):
        application.process_bundle(repository_root=repository, results_root=results,
                                   entry=entry, application_code_commit="b" * 40)


def test_duplicate_rows_are_rejected(tmp_path: Path) -> None:
    repository, results, entry = _synthetic_bundle(tmp_path, result_order=[1, 1, 3])
    with pytest.raises(application.InvalidInput):
        application.process_bundle(repository_root=repository, results_root=results,
                                   entry=entry, application_code_commit="b" * 40)


def test_missing_rows_are_rejected(tmp_path: Path) -> None:
    repository, results, entry = _synthetic_bundle(tmp_path, result_order=[1, 2])
    entry["results_csv_sha256"] = application.file_sha256(results / "raw" / entry["run_id"] / "results.csv")
    metadata_path = results / "raw" / entry["run_id"] / "metadata.json"
    metadata = json.loads(metadata_path.read_text())
    metadata["results_sha256"] = entry["results_csv_sha256"]
    metadata_path.write_text(json.dumps(metadata))
    entry["metadata_sha256"] = application.file_sha256(metadata_path)
    with pytest.raises(application.InvalidInput, match="missing"):
        application.process_bundle(repository_root=repository, results_root=results,
                                   entry=entry, application_code_commit="b" * 40)


@pytest.mark.parametrize("name", ["metadata.json", "provenance.json", "results.csv"])
def test_bundle_hash_mismatches_are_blocked(tmp_path: Path, name: str) -> None:
    _repository, results, entry = _synthetic_bundle(tmp_path)
    path = results / "raw" / entry["run_id"] / name
    path.write_bytes(path.read_bytes() + b"x")
    with pytest.raises(application.ApplicationBlocked, match="hash mismatch"):
        application.verify_bundle_file_hashes(results / "raw", [entry])


def test_archive_mismatch_is_blocked(tmp_path: Path) -> None:
    archive = tmp_path / "archive"
    archive.mkdir()
    frozen = {"registry": {"bundles": []}, "execution_lock": {"bundle_set_sha256": "0" * 64}}
    with pytest.raises(application.ApplicationBlocked):
        application.verify_external_archive(archive, frozen, allow_create_receipt=False)


def test_raw_rows_are_not_read_after_prerequisite_failure(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    called = False

    def fail_repository(_root: Path) -> dict[str, str]:
        raise application.ApplicationBlocked("dirty worktree")

    def derive_spy(**_kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr(application, "verify_repository", fail_repository)
    monkeypatch.setattr(application, "derive_all", derive_spy)
    result = application.main([
        "--repository-root", str(tmp_path), "--results-root", str(tmp_path / "results"),
        "--archive-root", str(tmp_path / "archive"), "--derived-output-root", str(tmp_path / "derived"),
    ])
    assert result == 2
    assert called is False


@pytest.mark.parametrize("gate", ["tag mismatch", "execution package mismatch", "policy package mismatch", "dirty worktree"])
def test_prerequisite_failures_use_blocked_status(gate: str) -> None:
    assert str(application.ApplicationBlocked(gate)) == gate


def test_atomic_publication_refuses_existing_destination(tmp_path: Path) -> None:
    candidate = tmp_path / ".candidate-1"
    destination = tmp_path / "published"
    candidate.mkdir()
    destination.mkdir()
    with pytest.raises(application.ApplicationBlocked):
        application._publish_candidate(candidate, destination)
    assert candidate.is_dir() and destination.is_dir()


def test_atomic_publication_renames_complete_candidate(tmp_path: Path) -> None:
    candidate = tmp_path / ".candidate-1"
    destination = tmp_path / "published"
    candidate.mkdir()
    (candidate / "complete").write_text("yes")
    application._publish_candidate(candidate, destination)
    assert not candidate.exists()
    assert (destination / "complete").read_text() == "yes"


def test_decision_and_combined_hashes_are_deterministic() -> None:
    payload = {"policy_id": application.POLICY_ID, "raw_score": "40.000"}
    assert application.stable_sha256(payload) == application.stable_sha256(dict(reversed(list(payload.items()))))
    ordered = [application.stable_sha256({"i": index}) for index in range(3)]
    assert application.stable_sha256(ordered) == application.stable_sha256(list(ordered))
    assert application.stable_sha256(ordered) != application.stable_sha256(list(reversed(ordered)))


def test_application_cli_has_only_approved_options() -> None:
    parser = application._parser()
    options = {option for action in parser._actions for option in action.option_strings}
    required = {"--repository-root", "--results-root", "--archive-root", "--derived-output-root"}
    forbidden = {"--threshold", "--operator", "--policy", "--bundle", "--manifest", "--score", "--replace"}
    assert required.issubset(options)
    assert not options.intersection(forbidden)


def test_application_has_no_process_network_or_runner_coupling() -> None:
    source = (TOOLS_ROOT / "apply_sourceafis_decision_policy_v1.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.add((node.module or "").split(".")[0])
    assert not imports.intersection({"subprocess", "http", "urllib", "requests", "fingerprint_benchmark"})
    assert "benchmark.runner" not in source
    assert "os.system(" not in source


@pytest.mark.parametrize("forbidden", ["histogram", "score_min", "score_max", "score_mean", "score_median", "percentile", "ROC", "EER"])
def test_application_does_not_compute_score_statistics(forbidden: str) -> None:
    source = (TOOLS_ROOT / "apply_sourceafis_decision_policy_v1.py").read_text(encoding="utf-8")
    # Documentation strings may state a prohibited activity.  Executable call/name nodes may not.
    tree = ast.parse(source)
    names = {node.id.lower() for node in ast.walk(tree) if isinstance(node, ast.Name)}
    attributes = {node.attr.lower() for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
    assert forbidden.lower() not in names | attributes


def test_derived_schema_excludes_private_values() -> None:
    forbidden = {"raw_score", "relative_path_a", "relative_path_b", "sha256_a", "sha256_b", "error_message"}
    assert not forbidden.intersection(application.DERIVED_COLUMNS)


def test_evaluation_schema_excludes_row_identifiers() -> None:
    assert "pair_id" not in application.EVALUATION_FILES
    assert "subject_id" not in application.EVALUATION_FILES


def test_static_validator_is_read_only_and_has_no_process_coupling() -> None:
    source = (TOOLS_ROOT / "validate_sourceafis_policy_application_v1.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    imports = {
        alias.name.split(".")[0]
        for node in ast.walk(tree) if isinstance(node, ast.Import)
        for alias in node.names
    }
    assert "subprocess" not in imports
    assert "shutil" not in imports


def test_validate_only_mode_is_declared_as_boolean_flag() -> None:
    parser = application._parser()
    action = next(action for action in parser._actions if "--validate-only" in action.option_strings)
    assert action.const is True


def test_failure_path_is_covered_without_real_cohort() -> None:
    row = _row(status="prepare_a_failure", score="", error_code="decode_error", error_message="synthetic")
    assert application.decision_for_row(row, "plain_self")[1:3] == ("no_decision", "technical_failure")


def test_package_file_set_is_fixed() -> None:
    assert set(application.EVALUATION_FILES) == {
        "README.md", "application_plan.json", "input_bundle_registry.json", "primary_results.json",
        "primary_results.csv", "verification_aggregates.json", "application_validation_report.json",
        "application_lock.json", "SHA256SUMS.txt",
    }


def test_input_registry_snapshot_carries_application_identity(tmp_path: Path) -> None:
    execution = tmp_path / "execution"
    execution.mkdir()
    lock_path = execution / "execution_lock.json"
    lock_path.write_text("{}\n", encoding="utf-8")
    frozen = {
        "registry": {"execution_id": application.EXECUTION_ID, "bundles": []},
        "execution_package_sha256": "a" * 64,
        "execution_lock": {"bundle_set_sha256": "b" * 64},
        "roots": {"execution": execution},
    }
    snapshot = application.build_input_bundle_registry(frozen)
    assert snapshot["application_id"] == application.APPLICATION_ID
    assert snapshot["execution_id"] == application.EXECUTION_ID
    assert snapshot["external_archive_verified"] is True


def test_lock_and_checksum_do_not_lock_themselves() -> None:
    locked = [name for name in application.EVALUATION_FILES if name not in {"application_lock.json", "SHA256SUMS.txt"}]
    assert "application_lock.json" not in locked
    assert "SHA256SUMS.txt" not in locked


def test_ci_validator_can_be_imported_without_raw_bundles() -> None:
    assert callable(validator.validate_package_root)
