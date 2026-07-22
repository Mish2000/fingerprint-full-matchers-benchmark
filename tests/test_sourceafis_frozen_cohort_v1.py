"""Dataset-independent acceptance tests for the SourceAFIS frozen-cohort execution.

Every fixture here is synthetic. No test opens an SD300 image, starts a JVM, executes
SourceAFIS, or applies the frozen decision policy.
"""

from __future__ import annotations

import ast
import csv
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
TOOLS_ROOT = REPOSITORY_ROOT / "tools"
if str(TOOLS_ROOT) not in sys.path:
    sys.path.insert(0, str(TOOLS_ROOT))

import run_sourceafis_frozen_cohort_v1 as orchestrator  # noqa: E402
import validate_sourceafis_frozen_cohort_v1 as cohort  # noqa: E402
from fingerprint_benchmark.contract import BENCHMARK_CONTRACT_VERSION  # noqa: E402
from fingerprint_benchmark.hashing import file_sha256, stable_sha256  # noqa: E402
from fingerprint_benchmark.manifest import MANIFEST_COLUMNS  # noqa: E402
from fingerprint_benchmark.runner import RESULT_COLUMNS  # noqa: E402

DEFAULT_JAR_SHA256 = "c" * 64
DEFAULT_COMMIT = "d" * 40
DEFAULT_JAVA_VERSION = "17.0.18"
FIRST_MANIFEST = cohort.COHORT_MANIFESTS[0]
CANONICAL_ENVIRONMENT = {
    "compiler_release": 11,
    "java_vendor": cohort.JAVA_VENDOR,
    "java_version": cohort.JAVA_VERSION,
    "maven_version": cohort.MAVEN_VERSION,
    "os_arch": "amd64",
}
CANONICAL_TREES = {
    "protocol": "1" * 64,
    "qualification": "2" * 64,
    "runtime_sources": "3" * 64,
    "decision_policy": "4" * 64,
}


# --------------------------------------------------------------------------- fixtures


def _manifest_row(index: int, *, kind: str = "plain_roll_genuine", release: str = "sd300b") -> dict[str, str]:
    subject_a = f"{1000 + index:08d}"
    subject_b = f"{2000 + index:08d}"
    return {
        "pair_id": f"GEN_{subject_a}_F{index:02d}",
        "comparison_kind": kind,
        "dataset_release": release,
        "subject_index_a": str(index),
        "subject_id_a": subject_a,
        "subject_index_b": str(index),
        "subject_id_b": subject_b,
        "canonical_finger": str(index),
        "hand": "right",
        "finger_name": "thumb",
        "capture_type_a": "PLAIN",
        "capture_type_b": "ROLL",
        "nominal_ppi_a": "1000",
        "nominal_ppi_b": "1000",
        "relative_path_a": f"{release}/images/1000/png/plain/{subject_a}_plain_1000_11.png",
        "relative_path_b": f"{release}/images/1000/png/roll/{subject_b}_roll_1000_01.png",
        "sha256_a": hashlib.sha256(f"a{index}".encode()).hexdigest(),
        "sha256_b": hashlib.sha256(f"b{index}".encode()).hexdigest(),
        "source_frgp_a": "11",
        "source_frgp_b": "1",
        "image_status_a": "valid_core_candidate",
        "image_status_b": "valid_core_candidate",
        "pair_status": "valid",
        "source_pair_id": f"G_{subject_a}_F{index:02d}",
    }


def _write_manifest(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=MANIFEST_COLUMNS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def _build_protocol(root: Path, *, rows: int = 3, relative: str = FIRST_MANIFEST) -> Path:
    protocol_root = root / "protocols" / "supervisor_50x10_v1"
    _write_manifest(protocol_root / relative, [_manifest_row(index) for index in range(1, rows + 1)])
    (protocol_root / "manifest_lock.json").write_text(
        json.dumps({"protocol_id": "supervisor_50x10_v1", "protocol_version": 1}, indent=2) + "\n",
        encoding="utf-8",
    )
    return protocol_root


def _payload_hash(row: dict[str, str]) -> str:
    try:
        return stable_sha256({
            "contract_version": BENCHMARK_CONTRACT_VERSION,
            "method_id": row["method"],
            "method_version": row["method_version"],
            "protocol_id": row["protocol_id"],
            "protocol_version": int(row["protocol_version"]),
            "manifest_sha256": row["manifest_sha256"],
            "pair_index": int(row["pair_index"]),
            "pair_id": row["pair_id"],
            "comparison_kind": row["comparison_kind"],
            "subject_id_a": row["subject_id_a"],
            "subject_id_b": row["subject_id_b"],
            "sha256_a": row["sha256_a"],
            "sha256_b": row["sha256_b"],
            "result_status": row["status"],
            "error_code": row["error_code"] or None,
            "raw_score": float(row["raw_score"]) if row["raw_score"] else None,
        })
    except ValueError:
        return "0" * 64


def _result_row(
    *, run_id: str, manifest_relative: str, manifest_sha256: str, source: dict[str, str], pair_index: int,
    status: str = "ok", raw_score: str = "120.5", error_code: str = "", error_message: str = "",
) -> dict[str, str]:
    row = {
        "run_id": run_id,
        "method": "sourceafis",
        "method_version": cohort.SOURCEAFIS_VERSION,
        "protocol_id": "supervisor_50x10_v1",
        "protocol_version": "1",
        "manifest_relative_path": manifest_relative,
        "manifest_sha256": manifest_sha256,
        "pair_index": str(pair_index),
        **{column: source[column] for column in MANIFEST_COLUMNS},
        "prepare_a_status": "ok",
        "prepare_b_status": "ok",
        "comparison_status": "ok" if status == "ok" else "error",
        "status": status,
        "error_code": error_code,
        "error_message": error_message,
        "raw_score": raw_score,
        "score_direction": "higher_is_more_similar",
        "score_semantics": "raw_similarity",
        "prepare_a_wall_ms": "10.0",
        "prepare_b_wall_ms": "10.0",
        "compare_wall_ms": "1.0",
        "method_internal_prepare_a_ms": "9.0",
        "method_internal_prepare_b_ms": "9.0",
        "method_internal_compare_ms": "0.5",
        "score_payload_sha256": "",
    }
    row["score_payload_sha256"] = _payload_hash(row)
    return {column: row[column] for column in RESULT_COLUMNS}


def _write_bundle_files(bundle: Path, rows: list[dict[str, str]], identity: dict[str, str], provenance: dict) -> None:
    bundle.mkdir(parents=True, exist_ok=True)
    with (bundle / "results.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=RESULT_COLUMNS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    (bundle / "provenance.json").write_text(
        json.dumps(provenance, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    metadata = {
        "contract_version": BENCHMARK_CONTRACT_VERSION,
        "run_id": stable_sha256(identity)[:24],
        "row_count": len(rows),
        "identity": identity,
        "results_sha256": file_sha256(bundle / "results.csv"),
        "provenance_sha256": file_sha256(bundle / "provenance.json"),
    }
    (bundle / "metadata.json").write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _build_bundle(
    bundle: Path, protocol_root: Path, *, manifest_relative: str = FIRST_MANIFEST,
    jar_sha256: str = DEFAULT_JAR_SHA256, commit: str = DEFAULT_COMMIT,
    java_version: str = DEFAULT_JAVA_VERSION, failures: int = 0,
) -> Path:
    manifest_path = protocol_root / manifest_relative
    manifest_sha256 = file_sha256(manifest_path)
    protocol_lock_sha256 = file_sha256(protocol_root / "manifest_lock.json")
    identity = {
        "contract_version": BENCHMARK_CONTRACT_VERSION,
        "method_id": "sourceafis",
        "method_version": cohort.SOURCEAFIS_VERSION,
        "manifest_sha256": manifest_sha256,
        "protocol_lock_sha256": protocol_lock_sha256,
    }
    run_id = stable_sha256(identity)[:24]
    source_rows = cohort.read_manifest_rows(manifest_path)
    rows = []
    for index, source in enumerate(source_rows, start=1):
        if index <= failures:
            rows.append(_result_row(
                run_id=run_id, manifest_relative=manifest_relative, manifest_sha256=manifest_sha256,
                source=source, pair_index=index, status="comparison_failure", raw_score="",
                error_code="transport_error", error_message="synthetic failure",
            ))
        else:
            rows.append(_result_row(
                run_id=run_id, manifest_relative=manifest_relative, manifest_sha256=manifest_sha256,
                source=source, pair_index=index,
            ))
    provenance = {
        "git": {"commit": commit, "dirty": False},
        "jar_sha256": jar_sha256,
        "java_version": java_version,
        "manifest_sha256": manifest_sha256,
        "protocol_lock_sha256": protocol_lock_sha256,
        "python_version": "3.11.15",
        "sidecar_contract_version": "sourceafis-sidecar-contract-v1",
        "sidecar_implementation_version": "1.0.0",
        "sourceafis_maven_coordinates": "com.machinezoo.sourceafis:sourceafis:3.18.1",
        "sourceafis_version": cohort.SOURCEAFIS_VERSION,
    }
    _write_bundle_files(bundle, rows, identity, provenance)
    return bundle


def _read_result_rows(bundle: Path) -> list[dict[str, str]]:
    with (bundle / "results.csv").open("r", encoding="utf-8", newline="") as handle:
        return [dict(row) for row in csv.DictReader(handle)]


def _rewrite_results(bundle: Path, rows: list[dict[str, str]], *, columns=RESULT_COLUMNS) -> None:
    with (bundle / "results.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(columns), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    metadata = json.loads((bundle / "metadata.json").read_text(encoding="utf-8"))
    metadata["results_sha256"] = file_sha256(bundle / "results.csv")
    metadata["row_count"] = len(rows)
    (bundle / "metadata.json").write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _validate(bundle: Path, protocol_root: Path, **kwargs):
    parameters = {
        "bundle": bundle, "protocol_root": protocol_root,
        "manifest_relative_path": FIRST_MANIFEST, "expected_rows": 3,
    }
    parameters.update(kwargs)
    return cohort.validate_cohort_bundle(**parameters)


@pytest.fixture()
def protocol(tmp_path: Path) -> Path:
    return _build_protocol(tmp_path)


@pytest.fixture()
def bundle(tmp_path: Path, protocol: Path) -> Path:
    return _build_bundle(tmp_path / "raw" / "bundle", protocol)


def _execution_entries(count: int = 8, *, failures: int = 0) -> list[dict]:
    entries = []
    for order, relative in enumerate(cohort.COHORT_MANIFESTS[:count], start=1):
        release, _, kind = relative.partition("/")
        entries.append({
            "bundle_relative_path": f"raw/{order:024d}",
            "bundle_validation": "PASS",
            "comparison_kind": kind.removesuffix(".csv"),
            "dataset_release": release,
            "execution_code_commit": DEFAULT_COMMIT,
            "execution_order": order,
            "jar_sha256": DEFAULT_JAR_SHA256,
            "java_version": DEFAULT_JAVA_VERSION,
            "manifest_relative_path": relative,
            "manifest_sha256": hashlib.sha256(f"manifest{order}".encode()).hexdigest(),
            "metadata_sha256": hashlib.sha256(f"metadata{order}".encode()).hexdigest(),
            "protocol_lock_sha256": hashlib.sha256(b"lock").hexdigest(),
            "provenance_sha256": hashlib.sha256(f"provenance{order}".encode()).hexdigest(),
            "results_csv_sha256": hashlib.sha256(f"results{order}".encode()).hexdigest(),
            "row_count": cohort.EXPECTED_ROWS_PER_MANIFEST,
            "run_id": f"{order:024d}",
            "sourceafis_version": cohort.SOURCEAFIS_VERSION,
            "successful_scores": cohort.EXPECTED_ROWS_PER_MANIFEST - failures,
            "technical_failures": failures,
        })
    return entries


def _build_execution_package(tmp_path: Path, *, entries: list[dict] | None = None) -> tuple[Path, Path]:
    repository_root = tmp_path / "repo"
    (repository_root / "tools").mkdir(parents=True, exist_ok=True)
    (repository_root / "tests").mkdir(parents=True, exist_ok=True)
    for relative in (
        f"tools/run_{cohort.EXECUTION_ID}.py",
        f"tools/validate_{cohort.EXECUTION_ID}.py",
        f"tests/test_{cohort.EXECUTION_ID}.py",
    ):
        shutil.copy2(REPOSITORY_ROOT / relative, repository_root / relative)
    package_root = orchestrator.write_execution_package(
        repository_root=repository_root,
        entries=entries if entries is not None else _execution_entries(),
        environment=dict(CANONICAL_ENVIRONMENT),
        jar_sha256=DEFAULT_JAR_SHA256,
        execution_code_commit=DEFAULT_COMMIT,
        tree_hashes=dict(CANONICAL_TREES),
        started_at="2026-07-22T00:00:00Z",
        finished_at="2026-07-22T01:00:00Z",
    )
    return package_root, repository_root


def _option_strings() -> set[str]:
    return {option for action in orchestrator._parser()._actions for option in action.option_strings}


# ------------------------------------------------------------------- execution plan


def test_01_exactly_eight_manifests():
    assert len(cohort.COHORT_MANIFESTS) == 8


def test_02_manifest_order_is_frozen():
    assert cohort.COHORT_MANIFESTS == (
        "sd300b/plain_self.csv", "sd300b/roll_self.csv",
        "sd300b/plain_roll_genuine.csv", "sd300b/plain_roll_next_subject.csv",
        "sd300c/plain_self.csv", "sd300c/roll_self.csv",
        "sd300c/plain_roll_genuine.csv", "sd300c/plain_roll_next_subject.csv",
    )


def test_03_expected_rows_per_manifest_is_500():
    assert cohort.EXPECTED_ROWS_PER_MANIFEST == 500


def test_04_expected_total_rows_is_4000():
    assert cohort.EXPECTED_TOTAL_ROWS == 4000
    assert len(cohort.COHORT_MANIFESTS) * cohort.EXPECTED_ROWS_PER_MANIFEST == 4000


def test_05_no_subset_selection_options():
    assert _option_strings().isdisjoint({"--manifest", "--subject", "--comparison-kind"})


def test_06_no_threshold_option():
    assert "--threshold" not in _option_strings()


def test_07_no_decision_option():
    assert "--decision" not in _option_strings()


def test_08_no_retry_or_replace_options():
    assert _option_strings().isdisjoint({"--retry-failures", "--replace", "--skip-preflight"})


# ---------------------------------------------------------------------- environment


def _environment_repository(tmp_path: Path, *, release: str = "11", sourceafis: str = "3.18.1") -> tuple[Path, Path, Path]:
    repository_root = tmp_path / "env-repo"
    pom = repository_root / "apps" / "sourceafis-sidecar" / "pom.xml"
    pom.parent.mkdir(parents=True, exist_ok=True)
    pom.write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<project xmlns="http://maven.apache.org/POM/4.0.0">\n'
        "  <properties>\n"
        f"    <maven.compiler.release>{release}</maven.compiler.release>\n"
        f"    <sourceafis.version>{sourceafis}</sourceafis.version>\n"
        "  </properties>\n"
        "</project>\n",
        encoding="utf-8",
    )
    java = tmp_path / "java.exe"
    maven = tmp_path / "mvn.cmd"
    java.write_text("", encoding="utf-8")
    maven.write_text("", encoding="utf-8")
    return repository_root, java, maven


def _stub_toolchain(monkeypatch, *, java_version="17.0.18", vendor=cohort.JAVA_VENDOR, maven_version="3.9.16"):
    java_home = "/opt/jvm"

    def fake_run_text(command, *, cwd=None, env=None):
        if "-XshowSettings:properties" in command:
            return (
                f"    java.home = {java_home}\n"
                f"    java.vendor = {vendor}\n"
                f"    java.version = {java_version}\n"
                "    os.arch = amd64\n"
            )
        return (
            f"Apache Maven {maven_version} (NON_CANONICAL)\n"
            f"Java version: {java_version}, vendor: {vendor}, runtime: {java_home}\n"
            'OS name: "windows 11", version: "10.0", arch: "amd64", family: "windows"\n'
        )

    monkeypatch.setattr(orchestrator, "_run_text", fake_run_text)


def test_09_canonical_java_is_accepted(tmp_path, monkeypatch):
    repository_root, java, maven = _environment_repository(tmp_path)
    _stub_toolchain(monkeypatch)
    environment = orchestrator.verify_environment(repository_root, java, maven)
    assert environment["java_version"] == "17.0.18"
    assert environment["java_vendor"] == cohort.JAVA_VENDOR


def test_10_other_java_is_rejected(tmp_path, monkeypatch):
    repository_root, java, maven = _environment_repository(tmp_path)
    _stub_toolchain(monkeypatch, java_version="21.0.4")
    with pytest.raises(orchestrator.ExecutionBlocked):
        orchestrator.verify_environment(repository_root, java, maven)


def test_11_canonical_maven_is_accepted(tmp_path, monkeypatch):
    repository_root, java, maven = _environment_repository(tmp_path)
    _stub_toolchain(monkeypatch)
    assert orchestrator.verify_environment(repository_root, java, maven)["maven_version"] == "3.9.16"


def test_12_other_maven_is_rejected(tmp_path, monkeypatch):
    repository_root, java, maven = _environment_repository(tmp_path)
    _stub_toolchain(monkeypatch, maven_version="3.9.9")
    with pytest.raises(orchestrator.ExecutionBlocked):
        orchestrator.verify_environment(repository_root, java, maven)


def test_13_other_sourceafis_version_is_rejected(tmp_path, monkeypatch):
    repository_root, java, maven = _environment_repository(tmp_path, sourceafis="3.17.0")
    _stub_toolchain(monkeypatch)
    with pytest.raises(orchestrator.ExecutionBlocked):
        orchestrator.verify_environment(repository_root, java, maven)


def test_14_other_compiler_release_is_rejected(tmp_path, monkeypatch):
    repository_root, java, maven = _environment_repository(tmp_path, release="17")
    _stub_toolchain(monkeypatch)
    with pytest.raises(orchestrator.ExecutionBlocked):
        orchestrator.verify_environment(repository_root, java, maven)


def test_15_absolute_paths_are_rejected_in_the_package(tmp_path):
    package_root, repository_root = _build_execution_package(tmp_path)
    registry = json.loads((package_root / "bundle_registry.json").read_text(encoding="utf-8"))
    registry["bundles"][0]["bundle_relative_path"] = "C:/fingerprint/results/raw/bundle"
    (package_root / "bundle_registry.json").write_text(
        json.dumps(registry, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    errors = cohort.validate_execution_package(package_root, repository_root)
    assert any("absolute" in error for error in errors)


# ------------------------------------------------------------------------ preflight


class _FakeExtracted:
    def __init__(self, payload: bytes):
        self.payload = payload
        self.format_id = "sourceafis"
        self.format_version = "3.18.1"
        self.elapsed_ms = 1.0


class _FakeVerification:
    def __init__(self, score: float):
        self.score = score
        self.elapsed_ms = 1.0


class _FakeClient:
    def __init__(self, templates: dict[bytes, bytes], scores: dict[tuple[bytes, bytes], float]):
        self._templates = templates
        self._scores = scores

    def health(self):
        return {"sourceafis_version": cohort.SOURCEAFIS_VERSION}

    def extract_template(self, payload: bytes, dpi: int):
        return _FakeExtracted(self._templates[payload])

    def verify(self, template_a: bytes, template_b: bytes):
        return _FakeVerification(self._scores[(template_a, template_b)])


def _install_fake_sidecar(monkeypatch, client: _FakeClient, *, removed_route_status: int = 404):
    class _FakeSidecar:
        def __init__(self, jar_path, java_executable="java"):
            self.process = object()
            self.base_url = "http://127.0.0.1:1"

        def start(self):
            return client

        def close(self):
            self.process = None

    monkeypatch.setattr(orchestrator, "SourceAfisSidecar", _FakeSidecar)
    monkeypatch.setattr(orchestrator, "_post_status", lambda base_url, path, payload: removed_route_status)


def _qualification_fixture(tmp_path: Path, *, image_override: bytes | None = None) -> tuple[Path, Path, _FakeClient, float]:
    repository_root = tmp_path / "qual-repo"
    dataset_root = tmp_path / "dataset"
    qualification_root = repository_root / "qualification" / "sourceafis_runtime_v1"
    qualification_root.mkdir(parents=True, exist_ok=True)
    keys = ("sd300b_plain", "sd300b_roll", "sd300c_plain", "sd300c_roll")
    images = {key: f"image-{key}".encode() for key in keys}
    templates = {key: f"template-{key}".encode() for key in keys}
    manifest_images = {}
    for key, payload in images.items():
        relative = f"{key.split('_')[0]}/images/{key}.png"
        path = dataset_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload if image_override is None else image_override)
        manifest_images[key] = {
            "nominal_ppi": 1000 if key.startswith("sd300b") else 2000,
            "relative_path": relative,
            "sha256": hashlib.sha256(payload).hexdigest(),
        }
    (qualification_root / "qualification_manifest.json").write_text(
        json.dumps({"images": manifest_images}, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    marker_score = 4242.4242
    scores = {}
    raw_scores = {}
    for name, (left, right) in orchestrator.QUALIFICATION_COMPARISONS.items():
        scores[(templates[left], templates[right])] = marker_score
        raw_scores[name] = marker_score
    repetition = {
        "raw_scores": raw_scores,
        "template_format": {key: "sourceafis" for key in keys},
        "template_sha256": {key: hashlib.sha256(payload).hexdigest() for key, payload in templates.items()},
        "template_version": {key: "3.18.1" for key in keys},
    }
    (qualification_root / "qualification_results.json").write_text(
        json.dumps({"implementations": {"new": {"repetitions": [repetition, repetition]}}}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8")
    client = _FakeClient({images[key]: templates[key] for key in keys}, scores)
    return repository_root, dataset_root, client, marker_score


def test_16_qualification_image_hash_mismatch_fails(tmp_path, monkeypatch):
    repository_root, dataset_root, client, _ = _qualification_fixture(tmp_path, image_override=b"tampered")
    _install_fake_sidecar(monkeypatch, client)
    with pytest.raises(orchestrator.ExecutionFailed):
        orchestrator.run_preflight(repository_root, dataset_root, tmp_path / "jar", tmp_path / "java")


def test_17_template_mismatch_fails(tmp_path, monkeypatch):
    repository_root, dataset_root, client, _ = _qualification_fixture(tmp_path)
    results_path = repository_root / "qualification" / "sourceafis_runtime_v1" / "qualification_results.json"
    locked = json.loads(results_path.read_text(encoding="utf-8"))
    for repetition in locked["implementations"]["new"]["repetitions"]:
        repetition["template_sha256"]["sd300b_plain"] = "e" * 64
    results_path.write_text(json.dumps(locked, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _install_fake_sidecar(monkeypatch, client)
    with pytest.raises(orchestrator.ExecutionFailed, match="template_parity"):
        orchestrator.run_preflight(repository_root, dataset_root, tmp_path / "jar", tmp_path / "java")


def test_18_score_mismatch_fails(tmp_path, monkeypatch):
    repository_root, dataset_root, client, marker = _qualification_fixture(tmp_path)
    client._scores = {key: marker + 1 for key in client._scores}
    _install_fake_sidecar(monkeypatch, client)
    with pytest.raises(orchestrator.ExecutionFailed, match="score_parity"):
        orchestrator.run_preflight(repository_root, dataset_root, tmp_path / "jar", tmp_path / "java")


def test_19_removed_route_without_404_fails(tmp_path, monkeypatch):
    repository_root, dataset_root, client, _ = _qualification_fixture(tmp_path)
    _install_fake_sidecar(monkeypatch, client, removed_route_status=200)
    with pytest.raises(orchestrator.ExecutionFailed, match="removed_routes_absent"):
        orchestrator.run_preflight(repository_root, dataset_root, tmp_path / "jar", tmp_path / "java")


def test_20_preflight_never_prints_a_score(tmp_path, monkeypatch, capsys):
    repository_root, dataset_root, client, marker = _qualification_fixture(tmp_path)
    _install_fake_sidecar(monkeypatch, client)
    checks = orchestrator.run_preflight(repository_root, dataset_root, tmp_path / "jar", tmp_path / "java")
    captured = capsys.readouterr()
    assert all(checks.values())
    assert str(marker) not in captured.out + captured.err
    assert not any(isinstance(value, float) for value in checks.values())


# -------------------------------------------------------------------------- bundles


def test_21_expected_row_count_is_enforced(bundle, protocol):
    with pytest.raises(cohort.CohortValidationError):
        _validate(bundle, protocol, expected_rows=cohort.EXPECTED_ROWS_PER_MANIFEST)


def test_22_missing_row_fails(bundle, protocol):
    rows = _read_result_rows(bundle)
    _rewrite_results(bundle, rows[:-1])
    with pytest.raises(cohort.CohortValidationError):
        _validate(bundle, protocol)


def test_23_duplicate_row_fails(bundle, protocol):
    rows = _read_result_rows(bundle)
    _rewrite_results(bundle, rows[:-1] + [rows[0]])
    with pytest.raises(cohort.CohortValidationError):
        _validate(bundle, protocol)


def test_24_reordered_rows_fail(bundle, protocol):
    rows = _read_result_rows(bundle)
    _rewrite_results(bundle, [rows[1], rows[0], rows[2]])
    with pytest.raises(cohort.CohortValidationError):
        _validate(bundle, protocol)


def test_25_pair_id_mismatch_fails(bundle, protocol):
    rows = _read_result_rows(bundle)
    rows[1]["pair_id"] = "GEN_99999999_F09"
    rows[1]["score_payload_sha256"] = _payload_hash(rows[1])
    _rewrite_results(bundle, rows)
    with pytest.raises(cohort.CohortValidationError, match="pair_id"):
        _validate(bundle, protocol)


def test_26_subject_mismatch_fails(bundle, protocol):
    rows = _read_result_rows(bundle)
    rows[0]["subject_id_b"] = "00009999"
    rows[0]["score_payload_sha256"] = _payload_hash(rows[0])
    _rewrite_results(bundle, rows)
    with pytest.raises(cohort.CohortValidationError, match="subject_id_b"):
        _validate(bundle, protocol)


def test_27_path_and_hash_mutation_fails(bundle, protocol):
    rows = _read_result_rows(bundle)
    rows[2]["relative_path_a"] = "sd300b/images/1000/png/plain/00000000_plain_1000_11.png"
    _rewrite_results(bundle, rows)
    with pytest.raises(cohort.CohortValidationError, match="relative_path_a"):
        _validate(bundle, protocol)


def test_28_manifest_hash_mismatch_fails(bundle, protocol):
    manifest_path = protocol / FIRST_MANIFEST
    rows = cohort.read_manifest_rows(manifest_path)
    rows.append(_manifest_row(99))
    _write_manifest(manifest_path, rows)
    with pytest.raises(cohort.CohortValidationError):
        _validate(bundle, protocol, expected_rows=4)


def test_29_jar_hash_mismatch_fails(bundle, protocol):
    with pytest.raises(cohort.CohortValidationError, match="different JAR"):
        _validate(bundle, protocol, expected_jar_sha256="f" * 64)


def test_30_java_and_commit_provenance_mismatch_fails(bundle, protocol):
    with pytest.raises(cohort.CohortValidationError, match="different Java runtime"):
        _validate(bundle, protocol, expected_java_version="21.0.4")
    with pytest.raises(cohort.CohortValidationError, match="different execution code"):
        _validate(bundle, protocol, expected_execution_commit="e" * 40)


def test_31_finite_non_negative_score_is_accepted(bundle, protocol):
    summary = _validate(bundle, protocol)
    assert summary["successful_scores"] == 3
    assert summary["technical_failures"] == 0
    assert "raw_score" not in summary


def test_32_nan_score_fails(bundle, protocol):
    rows = _read_result_rows(bundle)
    rows[0]["raw_score"] = "nan"
    _rewrite_results(bundle, rows)
    with pytest.raises(cohort.CohortValidationError):
        _validate(bundle, protocol)


def test_33_infinite_score_fails(bundle, protocol):
    rows = _read_result_rows(bundle)
    rows[0]["raw_score"] = "inf"
    _rewrite_results(bundle, rows)
    with pytest.raises(cohort.CohortValidationError):
        _validate(bundle, protocol)


def test_34_negative_score_fails(bundle, protocol):
    rows = _read_result_rows(bundle)
    rows[0]["raw_score"] = "-1.5"
    rows[0]["score_payload_sha256"] = _payload_hash(rows[0])
    _rewrite_results(bundle, rows)
    with pytest.raises(cohort.CohortValidationError, match="negative"):
        _validate(bundle, protocol)


def test_35_failure_carrying_a_score_fails(bundle, protocol):
    rows = _read_result_rows(bundle)
    rows[0]["status"] = "comparison_failure"
    rows[0]["error_code"] = "transport_error"
    rows[0]["score_payload_sha256"] = _payload_hash(rows[0])
    _rewrite_results(bundle, rows)
    with pytest.raises(cohort.CohortValidationError):
        _validate(bundle, protocol)


def test_36_failure_without_error_code_fails(bundle, protocol):
    rows = _read_result_rows(bundle)
    rows[0]["status"] = "comparison_failure"
    rows[0]["raw_score"] = ""
    rows[0]["error_code"] = ""
    rows[0]["score_payload_sha256"] = _payload_hash(rows[0])
    _rewrite_results(bundle, rows)
    with pytest.raises(cohort.CohortValidationError):
        _validate(bundle, protocol)


def test_37_success_without_score_fails(bundle, protocol):
    rows = _read_result_rows(bundle)
    rows[0]["raw_score"] = ""
    rows[0]["score_payload_sha256"] = _payload_hash(rows[0])
    _rewrite_results(bundle, rows)
    with pytest.raises(cohort.CohortValidationError):
        _validate(bundle, protocol)


def test_38_score_payload_mismatch_fails(bundle, protocol):
    rows = _read_result_rows(bundle)
    rows[1]["score_payload_sha256"] = "0" * 64
    _rewrite_results(bundle, rows)
    with pytest.raises(cohort.CohortValidationError, match="payload"):
        _validate(bundle, protocol)


def test_39_decision_column_fails(bundle, protocol):
    rows = _read_result_rows(bundle)
    for row in rows:
        row["decision"] = "same"
    _rewrite_results(bundle, rows, columns=list(RESULT_COLUMNS) + ["decision"])
    with pytest.raises(cohort.CohortValidationError, match="decision-bearing"):
        _validate(bundle, protocol)


def test_40_threshold_column_fails(bundle, protocol):
    rows = _read_result_rows(bundle)
    for row in rows:
        row["threshold"] = "40.0"
    _rewrite_results(bundle, rows, columns=list(RESULT_COLUMNS) + ["threshold"])
    with pytest.raises(cohort.CohortValidationError, match="decision-bearing"):
        _validate(bundle, protocol)


# --------------------------------------------------------------------------- resume


def test_41_identical_valid_bundle_is_reusable(bundle, protocol):
    summary = _validate(
        bundle, protocol, expected_jar_sha256=DEFAULT_JAR_SHA256,
        expected_execution_commit=DEFAULT_COMMIT, expected_java_version=DEFAULT_JAVA_VERSION,
    )
    assert summary["bundle_validation"] == "PASS"
    assert summary["run_id"] == cohort.expected_run_id(
        file_sha256(protocol / FIRST_MANIFEST), file_sha256(protocol / "manifest_lock.json"))


def _blocked_execute(tmp_path: Path, protocol_root: Path, bundle_dir: Path):
    return orchestrator.execute_cohort(
        repository_root=protocol_root.parents[1], dataset_root=tmp_path / "dataset",
        results_root=bundle_dir.parents[1], jar_path=tmp_path / "jar", jar_sha256=DEFAULT_JAR_SHA256,
        java=tmp_path / "java", execution_code_commit=DEFAULT_COMMIT, java_version=DEFAULT_JAVA_VERSION,
    )


def _cohort_layout(tmp_path: Path, **bundle_kwargs) -> tuple[Path, Path]:
    """A repository whose first frozen manifest already has a published bundle."""
    protocol_root = _build_protocol(tmp_path / "repo", rows=cohort.EXPECTED_ROWS_PER_MANIFEST)
    results_root = tmp_path / "results"
    manifest_sha256 = file_sha256(protocol_root / FIRST_MANIFEST)
    lock_sha256 = file_sha256(protocol_root / "manifest_lock.json")
    run_id = cohort.expected_run_id(manifest_sha256, lock_sha256)
    bundle_dir = results_root / "raw" / run_id
    _build_bundle(bundle_dir, protocol_root, **bundle_kwargs)
    return protocol_root, bundle_dir


def test_42_valid_bundle_from_another_jar_is_blocked(tmp_path):
    protocol_root, bundle_dir = _cohort_layout(tmp_path, jar_sha256="a" * 64)
    with pytest.raises(orchestrator.ExecutionBlocked, match="will not be overwritten"):
        _blocked_execute(tmp_path, protocol_root, bundle_dir)
    assert (bundle_dir / "results.csv").is_file()


def test_43_valid_bundle_from_another_commit_is_blocked(tmp_path):
    protocol_root, bundle_dir = _cohort_layout(tmp_path, commit="b" * 40)
    with pytest.raises(orchestrator.ExecutionBlocked, match="will not be overwritten"):
        _blocked_execute(tmp_path, protocol_root, bundle_dir)
    assert (bundle_dir / "results.csv").is_file()


def test_44_invalid_bundle_is_never_overwritten(tmp_path):
    protocol_root, bundle_dir = _cohort_layout(tmp_path)
    (bundle_dir / "results.csv").write_text("corrupted\n", encoding="utf-8")
    before = (bundle_dir / "results.csv").read_bytes()
    with pytest.raises(orchestrator.ExecutionBlocked, match="will not be overwritten"):
        _blocked_execute(tmp_path, protocol_root, bundle_dir)
    assert (bundle_dir / "results.csv").read_bytes() == before


def test_45_pair_level_failures_do_not_trigger_selective_retry(tmp_path):
    protocol_root, bundle_dir = _cohort_layout(tmp_path, failures=7)
    summary = cohort.validate_cohort_bundle(
        bundle=bundle_dir, protocol_root=protocol_root, manifest_relative_path=FIRST_MANIFEST,
        expected_jar_sha256=DEFAULT_JAR_SHA256, expected_execution_commit=DEFAULT_COMMIT,
        expected_java_version=DEFAULT_JAVA_VERSION,
    )
    assert summary["technical_failures"] == 7
    assert summary["successful_scores"] + summary["technical_failures"] == cohort.EXPECTED_ROWS_PER_MANIFEST
    assert "--retry-failures" not in _option_strings()


def test_46_interrupted_manifest_leaves_no_reusable_state(tmp_path):
    raw_root = tmp_path / "raw"
    raw_root.mkdir()
    run_id = "0" * 24
    candidate = raw_root / f"{run_id}.candidate-abc123"
    candidate.mkdir()
    (candidate / "results.csv").write_text("partial\n", encoding="utf-8")
    orchestrator._clear_stale_candidates(raw_root, run_id)
    assert not candidate.exists()
    assert not (raw_root / run_id).exists()


def test_47_partial_candidate_is_not_a_valid_bundle(tmp_path, protocol):
    candidate = tmp_path / "raw" / "deadbeef.candidate-1"
    candidate.mkdir(parents=True)
    (candidate / "results.csv").write_text("partial\n", encoding="utf-8")
    with pytest.raises(cohort.CohortValidationError, match="missing bundle file"):
        _validate(candidate, protocol)


# ------------------------------------------------------------------------- registry


def test_48_registry_contains_eight_entries(tmp_path):
    package_root, repository_root = _build_execution_package(tmp_path)
    registry = json.loads((package_root / "bundle_registry.json").read_text(encoding="utf-8"))
    assert len(registry["bundles"]) == 8
    assert cohort.validate_execution_package(package_root, repository_root) == []


def test_49_registry_total_rows_is_4000(tmp_path):
    package_root, _ = _build_execution_package(tmp_path)
    registry = json.loads((package_root / "bundle_registry.json").read_text(encoding="utf-8"))
    assert registry["total_rows"] == 4000


def test_50_successful_plus_failures_is_500_per_bundle(tmp_path):
    package_root, _ = _build_execution_package(tmp_path, entries=_execution_entries(failures=3))
    registry = json.loads((package_root / "bundle_registry.json").read_text(encoding="utf-8"))
    for entry in registry["bundles"]:
        assert entry["successful_scores"] + entry["technical_failures"] == 500


def test_51_registry_contains_no_raw_scores(tmp_path):
    package_root, repository_root = _build_execution_package(tmp_path)
    registry = json.loads((package_root / "bundle_registry.json").read_text(encoding="utf-8"))
    registry["bundles"][0]["raw_score"] = 12.5
    (package_root / "bundle_registry.json").write_text(
        json.dumps(registry, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    assert any("raw_score" in error for error in cohort.validate_execution_package(package_root, repository_root))


def test_52_registry_contains_no_threshold(tmp_path):
    package_root, repository_root = _build_execution_package(tmp_path)
    plan = json.loads((package_root / "execution_plan.json").read_text(encoding="utf-8"))
    assert "threshold" not in json.dumps(plan)
    plan["threshold"] = "40.0"
    (package_root / "execution_plan.json").write_text(
        json.dumps(plan, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    assert any("threshold" in error for error in cohort.validate_execution_package(package_root, repository_root))


def test_53_registry_contains_no_decisions(tmp_path):
    package_root, repository_root = _build_execution_package(tmp_path)
    registry = json.loads((package_root / "bundle_registry.json").read_text(encoding="utf-8"))
    registry["bundles"][0]["decision"] = "same"
    (package_root / "bundle_registry.json").write_text(
        json.dumps(registry, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    assert any("decision" in error for error in cohort.validate_execution_package(package_root, repository_root))


def test_54_bundle_set_hash_is_deterministic(tmp_path):
    entries = _execution_entries()
    first = cohort.compute_bundle_set_sha256(entries)
    second = cohort.compute_bundle_set_sha256(list(reversed(entries)))
    assert first == second
    mutated = _execution_entries()
    mutated[3]["results_csv_sha256"] = "9" * 64
    assert cohort.compute_bundle_set_sha256(mutated) != first


def test_55_execution_lock_is_valid(tmp_path):
    package_root, repository_root = _build_execution_package(tmp_path)
    lock = json.loads((package_root / "execution_lock.json").read_text(encoding="utf-8"))
    assert f"executions/{cohort.EXECUTION_ID}/execution_lock.json" not in lock["files"]
    assert f"executions/{cohort.EXECUTION_ID}/SHA256SUMS.txt" not in lock["files"]
    assert lock["total_rows"] == 4000
    assert not [error for error in cohort.validate_execution_package(package_root, repository_root) if "lock" in error.lower()]


def test_56_sha256sums_is_valid(tmp_path):
    package_root, repository_root = _build_execution_package(tmp_path)
    checksums, errors = cohort._parse_checksums(package_root / "SHA256SUMS.txt")
    assert not errors
    assert "SHA256SUMS.txt" not in checksums
    assert set(checksums) == {path.name for path in package_root.iterdir() if path.name != "SHA256SUMS.txt"}
    for name, digest in checksums.items():
        assert digest == file_sha256(package_root / name)
    assert not [error for error in cohort.validate_execution_package(package_root, repository_root) if "checksum" in error.lower()]


def test_57_raw_result_paths_are_not_tracked():
    tracked = subprocess.run(
        ["git", "ls-files"], cwd=REPOSITORY_ROOT, check=True, text=True, stdout=subprocess.PIPE,
    ).stdout.splitlines()
    assert not [path for path in tracked if path.startswith("results/") or path.endswith(".jar")]


def test_58_protected_areas_remain_byte_identical():
    assert orchestrator.verify_protected_trees(REPOSITORY_ROOT)


def test_59_execution_package_publication_is_atomic(tmp_path):
    package_root, _ = _build_execution_package(tmp_path)
    siblings = list(package_root.parent.iterdir())
    assert siblings == [package_root]
    assert {path.name for path in package_root.iterdir()} == set(cohort.EXECUTION_PACKAGE_FILES)


def test_60_validation_only_cannot_execute_a_matcher():
    tree = ast.parse((TOOLS_ROOT / f"validate_{cohort.EXECUTION_ID}.py").read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
    assert "subprocess" not in imported
    assert not any("sidecar" in name or "client" in name for name in imported)
