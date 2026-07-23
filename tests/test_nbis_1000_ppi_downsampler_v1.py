"""Synthetic, dataset-independent tests for the NBIS downsampler audit v1."""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
H1 = "1" * 64
H2 = "2" * 64


def _load_module(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, REPOSITORY_ROOT / relative)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


audit = _load_module(
    "audit_nbis_1000_ppi_downsampler_v1", "tools/audit_nbis_1000_ppi_downsampler_v1.py"
)
validator = _load_module(
    "validate_nbis_1000_ppi_downsampler_v1",
    "tools/validate_nbis_1000_ppi_downsampler_v1.py",
)
runner = _load_module(
    "run_nbis_1000_ppi_downsampler_tests_v1",
    "tools/run_nbis_1000_ppi_downsampler_tests_v1.py",
)


def _document(**values):
    return {"audit_id": validator.AUDIT_ID, "prerequisite_id": validator.PREREQUISITE_ID, **values}


def _source(report: str, url: str) -> dict[str, object]:
    return {
        "official": True,
        "official_url": url,
        "resolved_url": url,
        "retrieval_utc": "2026-07-23T00:00:00Z",
        "title": report,
        "report_number": report,
        "publication_date": "2016-01-01",
        "file_size_bytes": 1,
        "sha256": H1,
        "page_count": 1,
        "relevant_pages_sections": [{"pages": [1], "section": "test"}],
        "normative_status": "MIXED",
        "publisher": "National Institute of Standards and Technology",
    }


def _valid_documents() -> dict[str, object]:
    fields = {}
    for name in validator.PIXEL_SEMANTIC_FIELDS:
        fields[name] = {
            "value": "TEST_VALUE",
            "status": "EXPLICIT",
            "source": "NIST SP 500-289",
            "page": 1,
            "section": "test",
            "normative_level": "NORMATIVE",
            "ambiguity": None,
            "resolved": True,
            "normative_text_summary": "Test-only official-source summary.",
            "confidence": "HIGH",
            "implementation_consequence": "Test-only consequence.",
        }
    for name in validator.CRITICAL_PIXEL_SEMANTICS:
        fields[name].update({
            "value": None,
            "status": "NOT_SPECIFIED",
            "source": "OFFICIAL_DOCUMENT_SET",
            "page": None,
            "section": "no controlling statement located",
            "normative_level": "NONE",
            "ambiguity": "Output-affecting behavior is not fixed.",
            "resolved": False,
            "confidence": "HIGH",
            "implementation_consequence": "Canonical output bytes cannot be selected.",
        })
    vectors = [
        {
            "vector_id": f"test_{purpose}",
            "purpose": purpose,
            "width": 1,
            "height": 1,
            "input_matrix": [[0]],
            "expected_output_matrix": None,
            "expected_source": "NOT_AVAILABLE_UNRESOLVED",
        }
        for purpose in sorted(validator.REQUIRED_VECTOR_PURPOSES)
    ]
    unresolved = sorted(validator.CRITICAL_PIXEL_SEMANTICS)
    documents: dict[str, object] = {
        "audit_plan.json": _document(
            audit_version=1,
            official_source_policy="NIST_OFFICIAL_ONLY",
            biometric_input_allowed=False,
            dataset_access_allowed=False,
            matcher_execution_allowed=False,
            fixed_random_seeds=list(audit.SEEDS),
            fresh_process_repetitions=3,
            pixel_semantic_fields=list(audit.PIXEL_SEMANTIC_FIELDS),
        ),
        "official_sources.json": _document(documents=[
            _source("NISTIR 7839", "https://nvlpubs.nist.gov/a.pdf"),
            _source("NIST SP 500-289", "https://nvlpubs.nist.gov/b.pdf"),
            _source("NIST SP 500-306", "https://nvlpubs.nist.gov/c.pdf"),
        ]),
        "specification_matrix.json": _document(fields=fields),
        "reference_implementation_audit.json": _document(
            official_reference_searched=True,
            official_reference_found=False,
            official_publisher=None,
            version=None,
            source_or_binary=None,
            hash=None,
            license=None,
            relationship_to_guidance="No official implementation located in test fixture.",
            used_as_oracle=False,
            execution_performed=False,
            synthetic_input_only=True,
            third_party_oracle_used=False,
        ),
        "implementation_identity.json": _document(
            canonical_implementation_selected=False,
            source_file_sha256=None,
            reference_implementation_sha256=None,
        ),
        "isolation_incidents.json": _document(
            current_attempt_id="nbis_1000_ppi_downsampler_v1_attempt_2",
            incidents=[{
                "attempt_id": "nbis_1000_ppi_downsampler_v1_attempt_1",
                "status": "FAIL",
                "cause": "unrestricted pytest collection executed a dataset-backed protocol test",
                "dataset_accessed": True,
                "dataset_modified": False,
                "matcher_invoked": False,
                "scores_generated": False,
                "results_discarded": True,
                "used_as_audit_evidence": False,
            }],
        ),
        "synthetic_vectors.json": _document(
            synthetic_only=True,
            dataset_accessed=False,
            fixed_seeds=list(audit.SEEDS),
            vectors=vectors,
        ),
        "conformance_results.json": _document(
            execution_status="NOT_EXECUTED_UNRESOLVED_SPEC",
            overall_status="NOT_APPLICABLE",
            border_discriminating_tests_present=True,
            parity_discriminating_tests_present=True,
            odd_even_dimension_tests_present=True,
            rounding_sensitive_tests_present=True,
            clipping_sensitive_tests_present=True,
        ),
        "determinism_results.json": _document(
            required_fresh_process_repetitions=3,
            execution_performed=False,
            overall_status="NOT_EXECUTED_UNRESOLVED_SPEC",
            windows_ci_equality="NOT_EXECUTED_UNRESOLVED_SPEC",
        ),
        "certification_status.json": _document(
            sp_500_306_reviewed=True,
            current_submission_availability="NOT_ESTABLISHED",
            official_test_package_availability="NOT_ESTABLISHED",
            submission_performed=False,
            certification_received=False,
            claim_permitted="LOCAL_CONFORMANCE_ONLY",
        ),
        "risks_and_open_questions.json": _document(open_questions=unresolved),
        "prerequisite_resolution.json": _document(
            task_status="PASS",
            status="UNRESOLVED",
            unresolved_pixel_semantics=unresolved,
            canonical_implementation_selected=False,
        ),
        "validation_report.json": _document(
            valid=True,
            errors=[],
            task_status="PASS",
            fingerprint_images_accessed=False,
            dataset_accessed=False,
            fixture_processed=False,
            mindtct_invoked_on_image=False,
            bozorth3_invoked=False,
            scores_generated=False,
            threshold_used=False,
        ),
        "preprocessing_lock.json": _document(),
    }
    assert set(documents) == set(validator.JSON_FILES)
    return documents


def _errors(documents: dict[str, object]) -> list[str]:
    return validator.validate_semantics(documents)


def test_pre_package_semantics_fixture_is_valid() -> None:
    assert _errors(_valid_documents()) == []


@pytest.mark.parametrize("purpose,value", [("all_zeros", 0), ("all_255", 255), ("constant_mid_gray", 127)])
def test_constant_matrices(purpose: str, value: int) -> None:
    assert audit.synthetic_matrix(purpose, 5, 4) == [[value] * 5 for _ in range(4)]


def test_center_impulse() -> None:
    rows = audit.synthetic_matrix("impulse_center", 9, 9)
    assert sum(map(sum, rows)) == 255 and rows[4][4] == 255


@pytest.mark.parametrize(
    "purpose,location",
    [
        ("impulse_top_left", (0, 0)),
        ("impulse_top_right", (0, 8)),
        ("impulse_bottom_left", (8, 0)),
        ("impulse_bottom_right", (8, 8)),
    ],
)
def test_corner_impulses(purpose: str, location: tuple[int, int]) -> None:
    rows = audit.synthetic_matrix(purpose, 9, 9)
    assert rows[location[0]][location[1]] == 255 and sum(map(sum, rows)) == 255


def test_edge_sensitive_pattern_is_not_symmetric_or_constant() -> None:
    rows = audit.synthetic_matrix("border_sensitive", 9, 9)
    assert len({value for row in rows for value in row}) > 16
    assert rows[0] != rows[-1]


def test_border_modes_have_distinguishing_coordinate_signatures() -> None:
    modes = (
        "zero_padding", "edge_replication", "reflect_repeated_edge",
        "reflect_101", "symmetric_mirroring", "periodic_wrapping",
    )
    signatures = {
        mode: tuple(audit.border_index(index, 4, mode) for index in range(-7, 11))
        for mode in modes
    }
    assert len(set(signatures.values())) == len(modes)


def test_four_zero_based_parity_modes_are_distinguishable() -> None:
    rows = audit.synthetic_matrix("parity_sensitive", 8, 8)
    outputs = {
        json.dumps(audit.parity_decimation(rows, row_start, column_start))
        for row_start in (0, 1)
        for column_start in (0, 1)
    }
    assert len(outputs) == 4


def test_rounding_sensitive_case_contains_low_and_high_terms() -> None:
    values = {value for row in audit.synthetic_matrix("rounding_half_sensitive", 9, 9) for value in row}
    assert {0, 1, 255}.issubset(values)


def test_clipping_sensitive_case_contains_near_limit_terms() -> None:
    values = {value for row in audit.synthetic_matrix("clipping_sensitive", 9, 9) for value in row}
    assert {0, 254, 255}.issubset(values)


@pytest.mark.parametrize("width,height", [(9, 9), (8, 8), (11, 11), (8, 9), (9, 8)])
def test_odd_even_dimension_cases(width: int, height: int) -> None:
    rows = audit.synthetic_matrix("checkerboard", width, height)
    assert len(rows) == height and all(len(row) == width for row in rows)


@pytest.mark.parametrize("size", range(1, 13))
def test_dimensions_one_through_twelve(size: int) -> None:
    rows = audit.synthetic_matrix("deterministic_pseudorandom", size, size, seed=7839)
    assert len(rows) == size and len(rows[0]) == size


def test_input_smaller_than_kernel_is_representable_without_padding_assumption() -> None:
    rows = audit.synthetic_matrix("checkerboard", 3, 2)
    assert rows == [[0, 255, 0], [255, 0, 255]]


@pytest.mark.parametrize("width,height", [(0, 1), (1, 0), (-1, 2)])
def test_empty_or_nonpositive_matrix_is_rejected(width: int, height: int) -> None:
    with pytest.raises(ValueError, match="positive"):
        audit.synthetic_matrix("all_zeros", width, height)


@pytest.mark.parametrize("value", [-1, 256, 1.5, True])
def test_invalid_constant_u8_value_is_rejected(value: object) -> None:
    with pytest.raises(ValueError, match="unsigned 8-bit"):
        audit._matrix(2, 2, value)  # type: ignore[arg-type]


def test_nonrectangular_vector_is_rejected() -> None:
    documents = _valid_documents()
    documents["synthetic_vectors.json"]["vectors"][0]["input_matrix"] = [[0], [1, 2]]  # type: ignore[index]
    assert any("dimensions mismatch" in error for error in _errors(documents))


@pytest.mark.parametrize("value", [-1, 256, 1.5, True])
def test_invalid_vector_value_is_rejected(value: object) -> None:
    documents = _valid_documents()
    documents["synthetic_vectors.json"]["vectors"][0]["input_matrix"] = [[value]]  # type: ignore[index]
    assert any("not u8" in error for error in _errors(documents))


def test_deterministic_random_seeds_are_fixed_and_repeatable() -> None:
    assert list(audit.SEEDS) == validator.REQUIRED_SEEDS
    for seed in audit.SEEDS:
        first = audit.synthetic_matrix("deterministic_pseudorandom", 12, 7, seed=seed)
        second = audit.synthetic_matrix("deterministic_pseudorandom", 12, 7, seed=seed)
        assert first == second


def test_three_fresh_process_plan_payloads_are_identical(tmp_path: Path) -> None:
    payloads = []
    for repetition in range(3):
        workspace = tmp_path / f"run-{repetition}"
        subprocess.run(
            [sys.executable, str(REPOSITORY_ROOT / "tools" / "audit_nbis_1000_ppi_downsampler_v1.py"),
             "--workspace-root", str(workspace)],
            cwd=tmp_path, check=True, capture_output=True, text=True,
        )
        payloads.append((workspace / "audit_plan.json").read_bytes())
    assert payloads[0] == payloads[1] == payloads[2]


def test_plan_is_locale_timezone_hashseed_and_cwd_independent(tmp_path: Path) -> None:
    payloads = []
    for index, values in enumerate((
        {"LC_ALL": "C", "TZ": "UTC", "PYTHONHASHSEED": "0"},
        {"LC_ALL": "C.UTF-8", "TZ": "Pacific/Honolulu", "PYTHONHASHSEED": "7839"},
    )):
        workspace = tmp_path / f"environment-{index}"
        working_directory = tmp_path / ("cwd-a" if index == 0 else "cwd-b")
        working_directory.mkdir()
        environment = os.environ.copy()
        environment.update(values)
        subprocess.run(
            [sys.executable, str(REPOSITORY_ROOT / "tools" / "audit_nbis_1000_ppi_downsampler_v1.py"),
             "--workspace-root", str(workspace)],
            cwd=working_directory,
            env=environment, check=True, capture_output=True, text=True,
        )
        payloads.append((workspace / "audit_plan.json").read_bytes())
    assert payloads[0] == payloads[1]


def test_unresolved_ambiguity_blocks_resolved() -> None:
    documents = _valid_documents()
    documents["prerequisite_resolution.json"]["status"] = "RESOLVED"  # type: ignore[index]
    assert "unresolved critical pixel semantics block RESOLVED" in _errors(documents)


def test_unresolved_forbids_canonical_implementation() -> None:
    documents = _valid_documents()
    documents["implementation_identity.json"]["canonical_implementation_selected"] = True  # type: ignore[index]
    assert "canonical implementation is prohibited for UNRESOLVED" in _errors(documents)


def test_third_party_oracle_is_rejected() -> None:
    documents = _valid_documents()
    documents["reference_implementation_audit.json"]["third_party_oracle_used"] = True  # type: ignore[index]
    assert "third-party oracle is prohibited" in _errors(documents)


def test_false_nist_certification_claim_is_rejected() -> None:
    documents = _valid_documents()
    documents["certification_status.json"]["certification_received"] = True  # type: ignore[index]
    assert "unsupported NIST submission/certification claim" in _errors(documents)


def test_forbidden_dataset_path_is_rejected() -> None:
    documents = _valid_documents()
    prohibited = Path(Path.cwd().anchor) / "fingerprint-datasets" / "NIST"
    documents["risks_and_open_questions.json"]["location"] = str(prohibited)  # type: ignore[index]
    assert any("dataset path" in error for error in _errors(documents))


def test_subject_identifier_is_rejected() -> None:
    documents = _valid_documents()
    documents["risks_and_open_questions.json"]["subject"] = "".join(("0000", "1000"))  # type: ignore[index]
    assert any("subject identifier" in error for error in _errors(documents))


def test_score_and_threshold_values_are_rejected() -> None:
    documents = _valid_documents()
    documents["risks_and_open_questions.json"]["score"] = 42  # type: ignore[index]
    documents["risks_and_open_questions.json"]["threshold"] = 7  # type: ignore[index]
    errors = _errors(documents)
    assert sum("biometric/matcher result" in error for error in errors) == 2


def test_prohibited_old_hash_is_rejected() -> None:
    documents = _valid_documents()
    documents["risks_and_open_questions.json"]["legacy"] = validator.PROHIBITED_OLD_HASH  # type: ignore[index]
    assert any("prohibited legacy" in error for error in _errors(documents))


def test_checksum_parser_accepts_sorted_records(tmp_path: Path) -> None:
    path = tmp_path / "SHA256SUMS.txt"
    path.write_text(f"{H1}  a.json\n{H2}  b.json\n", encoding="utf-8")
    checksums, errors = validator._parse_checksums(path)
    assert errors == [] and checksums == {"a.json": H1, "b.json": H2}


def test_checksum_parser_rejects_unsorted_records(tmp_path: Path) -> None:
    path = tmp_path / "SHA256SUMS.txt"
    path.write_text(f"{H2}  b.json\n{H1}  a.json\n", encoding="utf-8")
    _, errors = validator._parse_checksums(path)
    assert "SHA256SUMS.txt is not sorted" in errors


def test_tree_identity_changes_with_content(tmp_path: Path) -> None:
    root = tmp_path / "tree"
    root.mkdir()
    path = root / "item"
    path.write_text("first", encoding="utf-8")
    before = validator.tree_identity(root)
    path.write_text("second", encoding="utf-8")
    assert validator.tree_identity(root) != before


def test_protected_tree_validation_does_not_open_protocol_manifests() -> None:
    identities = validator.protected_tree_oids(REPOSITORY_ROOT)
    lock = {"protected_area_git_tree_oids": identities}
    assert validator.validate_protected_trees(REPOSITORY_ROOT, lock) == []


def test_baseline_tags_are_fixed() -> None:
    assert validator.validate_baseline_tags(REPOSITORY_ROOT) == []


def test_source_and_executable_identities_are_fixed() -> None:
    assert validator.SOURCE_ALGORITHM == "nbis_source_tree_identity_v2"
    assert validator.SOURCE_TREE_SHA256 == "00ae5eff70693fa5647e3ff57232eff7abd623e4786c110a3286ac8614ac7f3e"
    assert set(validator.EXECUTABLE_HASHES) == {"mindtct", "bozorth3"}


def test_no_binary_archive_pdf_or_image_is_tracked() -> None:
    assert validator.validate_tracked_artifacts(REPOSITORY_ROOT) == []


def test_validator_is_read_only_and_network_independent() -> None:
    source = (REPOSITORY_ROOT / "tools" / "validate_nbis_1000_ppi_downsampler_v1.py").read_text(encoding="utf-8")
    for mutation in ("write_bytes(", "write_text(", "unlink(", "mkdir(", "rmdir("):
        assert mutation not in source
    assert "urlopen" not in source and "requests" not in source
    assert "wsl.exe" not in source


@pytest.mark.parametrize(
    "flag",
    ["--image", "--dataset", "--manifest", "--subject", "--fixture", "--score", "--threshold", "--decision"],
)
def test_audit_tool_rejects_biometric_and_matcher_flags(flag: str) -> None:
    with pytest.raises(SystemExit):
        audit._parser().parse_args(["--workspace-root", "external", flag, "value"])


def test_ci_runs_downsampler_tests_and_validator() -> None:
    workflow = (REPOSITORY_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "run_nbis_1000_ppi_downsampler_tests_v1.py --suite audit" in workflow
    assert "validate_nbis_1000_ppi_downsampler_v1.py" in workflow


def test_ci_keeps_all_three_baseline_validators() -> None:
    workflow = (REPOSITORY_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "validate_nbis_build_environment_v1.py" in workflow
    assert "validate_nbis_candidate_v1_erratum_1.py" in workflow
    assert "validate_nbis_candidate_audit_v1.py" in workflow


def test_ci_does_not_download_nist_material_or_use_wsl() -> None:
    workflow = (REPOSITORY_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8").casefold()
    assert "nvlpubs.nist.gov" not in workflow
    assert "wsl.exe" not in workflow
    assert "curl " not in workflow and "wget " not in workflow


def test_runner_has_exact_fixed_audit_allowlist() -> None:
    assert runner.AUDIT_TEST_FILES == ("tests/test_nbis_1000_ppi_downsampler_v1.py",)
    assert "tests/test_supervisor_50x10_v1.py" not in runner.AUDIT_TEST_FILES


def test_runner_project_allowlist_matches_dataset_independent_ci_set() -> None:
    assert set(runner.PROJECT_TEST_FILES) == {
        "tests/test_benchmark_contract.py",
        "tests/test_benchmark_runner.py",
        "tests/test_protocol_manifest_reader.py",
        "tests/test_sourceafis_adapter.py",
        "tests/test_sourceafis_client.py",
        "tests/test_sourceafis_sidecar_lifecycle.py",
        "tests/test_forbidden_runtime_coupling.py",
        "tests/test_sourceafis_runtime_qualification.py",
        "tests/test_sourceafis_decision_policy_v1.py",
        "tests/test_sourceafis_frozen_cohort_v1.py",
        "tests/test_sourceafis_policy_application_v1.py",
    }


def test_runner_rejects_positional_test_paths() -> None:
    with pytest.raises(SystemExit):
        runner._parser().parse_args(["tests/test_supervisor_50x10_v1.py"])


def test_audit_suite_disables_repository_conftest_collection() -> None:
    assert runner.pytest_arguments("audit") == [
        "-q", "--noconftest", "tests/test_nbis_1000_ppi_downsampler_v1.py",
    ]


def test_runner_forbids_dataset_tree_before_open() -> None:
    prohibited = Path(Path.cwd().anchor) / "fingerprint-datasets" / "NIST" / "sample.bin"
    assert runner.path_is_forbidden(prohibited, audit_suite=True)


def test_runner_forbids_committed_protocol_manifests_for_audit_suite() -> None:
    prohibited = REPOSITORY_ROOT / "protocols" / "manifest.csv"
    assert runner.path_is_forbidden(prohibited, audit_suite=True)
    assert not runner.path_is_forbidden(prohibited, audit_suite=False)


def test_ci_has_no_unrestricted_pytest_command() -> None:
    workflow = (REPOSITORY_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    for line in workflow.splitlines():
        stripped = line.strip()
        if "python -m pytest" in stripped:
            assert ".py" in stripped, f"unrestricted pytest command: {stripped}"


def test_attempt_1_failure_is_permanently_recorded() -> None:
    incidents = _valid_documents()["isolation_incidents.json"]
    assert incidents["incidents"][0]["status"] == "FAIL"  # type: ignore[index]
    assert incidents["incidents"][0]["dataset_accessed"] is True  # type: ignore[index]
    assert incidents["incidents"][0]["used_as_audit_evidence"] is False  # type: ignore[index]
