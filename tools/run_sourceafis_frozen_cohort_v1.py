"""Frozen-cohort raw-score orchestrator for the qualified SourceAFIS runtime.

The tool always executes the same eight frozen manifests in the same frozen order.
It builds exactly one JAR, proves the successful path against the runtime
qualification fixture, runs every manifest in a fresh JVM, deep-validates each
published bundle against its source manifest, and only then writes the execution
registry. It never applies a threshold, never derives a biometric decision, and
never analyses, aggregates or prints a raw score.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import math
import os
import re
import shutil
import subprocess
import sys
import uuid
import xml.etree.ElementTree as ElementTree
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_SOURCE_ROOT = _REPOSITORY_ROOT / "src"
_TOOLS_ROOT = _REPOSITORY_ROOT / "tools"
for _candidate in (_SOURCE_ROOT, _TOOLS_ROOT):
    if _candidate.is_dir() and str(_candidate) not in sys.path:
        sys.path.insert(0, str(_candidate))

import validate_sourceafis_decision_policy_v1 as decision_policy  # noqa: E402
import validate_sourceafis_frozen_cohort_v1 as cohort  # noqa: E402
from fingerprint_benchmark.hashing import file_sha256  # noqa: E402
from fingerprint_benchmark.io import write_json_atomic  # noqa: E402
from fingerprint_benchmark.sourceafis_sidecar import SourceAfisSidecar  # noqa: E402

EXECUTION_ID = cohort.EXECUTION_ID
EXECUTION_VERSION = cohort.EXECUTION_VERSION
COHORT_MANIFESTS = cohort.COHORT_MANIFESTS
PROTOCOL_RELATIVE_ROOT = cohort.PROTOCOL_RELATIVE_ROOT
QUALIFICATION_RELATIVE_ROOT = "qualification/sourceafis_runtime_v1"
POLICY_RELATIVE_ROOT = "policies/sourceafis_decision_policy_v1"
SIDECAR_POM = "apps/sourceafis-sidecar/pom.xml"
SHADED_JAR_NAME = "sourceafis-sidecar-1.0.0-all.jar"

REQUIRED_TAGS = {
    "protocol-supervisor-50x10-v1": "29d8de0180403e9aa8a5e81cc468664b96dc8932",
    "sourceafis-runtime-v1": "db1e499f0ee3a5457ec71fbc7feba22214d34116",
    "sourceafis-runtime-qualified-v1": "78af9d227a68456f96f1d63d2547222d5435bb5f",
    "sourceafis-decision-policy-v1": "fdef2e36a347e952a0509c07725a222e47aca9c3",
}
FROZEN_INPUT_TAGS = {
    "protocol": "protocol-supervisor-50x10-v1",
    "runtime": "sourceafis-runtime-v1",
    "qualification": "sourceafis-runtime-qualified-v1",
    "decision_policy": "sourceafis-decision-policy-v1",
}
QUALIFICATION_COMPARISONS = {
    "sd300b_plain_roll": ("sd300b_plain", "sd300b_roll"),
    "sd300b_plain_self": ("sd300b_plain", "sd300b_plain"),
    "sd300b_roll_self": ("sd300b_roll", "sd300b_roll"),
    "sd300c_plain_roll": ("sd300c_plain", "sd300c_roll"),
    "sd300c_plain_self": ("sd300c_plain", "sd300c_plain"),
    "sd300c_roll_self": ("sd300c_roll", "sd300c_roll"),
}
REMOVED_ROUTES = ("/extract-template-raw", "/extract-final-minutiae")


class ExecutionBlocked(RuntimeError):
    """A frozen precondition does not hold; the matcher must not run."""


class ExecutionFailed(RuntimeError):
    """The execution produced an unusable or inconsistent artefact."""


def _git(repository_root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args], cwd=repository_root, check=False, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        raise ExecutionBlocked(f"git {' '.join(args)} failed: {completed.stderr.strip()}")
    return completed.stdout.strip()


def verify_repository(repository_root: Path) -> dict[str, Any]:
    """Confirm the branch, a clean worktree, and every frozen tag and commit."""
    branch = _git(repository_root, "branch", "--show-current")
    if branch != "main":
        raise ExecutionBlocked(f"execution requires branch main, found {branch!r}")
    if _git(repository_root, "status", "--porcelain"):
        raise ExecutionBlocked("worktree is not clean")
    head = _git(repository_root, "rev-parse", "HEAD")
    for tag, commit in REQUIRED_TAGS.items():
        try:
            resolved = _git(repository_root, "rev-list", "-n", "1", tag)
        except ExecutionBlocked as exc:
            raise ExecutionBlocked(f"required tag is missing: {tag}") from exc
        if resolved != commit:
            raise ExecutionBlocked(f"tag {tag} points at {resolved}, expected {commit}")
        ancestor = subprocess.run(
            ["git", "merge-base", "--is-ancestor", commit, head],
            cwd=repository_root, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        if ancestor.returncode != 0:
            raise ExecutionBlocked(f"required commit is not an ancestor of HEAD: {commit}")
    return {"branch": branch, "head": head, "worktree_clean": True}


def _verify_checksum_index(root: Path, label: str) -> None:
    sums_path = root / "SHA256SUMS.txt"
    if not sums_path.is_file():
        raise ExecutionBlocked(f"{label} package has no SHA256SUMS.txt")
    for line in sums_path.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        digest, separator, relative = line.partition("  ")
        if not separator:
            raise ExecutionBlocked(f"{label} package has a malformed checksum line")
        target = root / PurePosixPath(relative)
        if not target.is_file() or file_sha256(target) != digest:
            raise ExecutionBlocked(f"{label} package checksum mismatch: {relative}")


def verify_freeze_packages(repository_root: Path) -> None:
    """Confirm the protocol, qualification and decision-policy packages are intact."""
    _verify_checksum_index(repository_root / PurePosixPath(PROTOCOL_RELATIVE_ROOT), "protocol")
    _verify_checksum_index(repository_root / PurePosixPath(QUALIFICATION_RELATIVE_ROOT), "qualification")
    errors = decision_policy.validate_policy(repository_root)
    if errors:
        raise ExecutionBlocked(f"decision policy package is not intact: {errors[0]}")
    for relative in COHORT_MANIFESTS:
        manifest = repository_root / PurePosixPath(PROTOCOL_RELATIVE_ROOT) / PurePosixPath(relative)
        if not manifest.is_file():
            raise ExecutionBlocked(f"frozen manifest is missing: {relative}")


def protected_tree_hashes(repository_root: Path) -> dict[str, str]:
    """Recompute the protected-area tree hashes locked by the decision policy."""
    hashes: dict[str, str] = {}
    for name, layout in decision_policy.PROTECTED_LAYOUT.items():
        digest, _count = decision_policy._tree_digest(repository_root, layout["paths"], layout["suffixes"])
        hashes[name] = digest
    digest, _count = decision_policy._tree_digest(repository_root, (POLICY_RELATIVE_ROOT,), None)
    hashes["decision_policy"] = digest
    return hashes


def verify_protected_trees(repository_root: Path, baseline: dict[str, str] | None = None) -> dict[str, str]:
    """Compare protected-area trees with the decision-policy lock and any baseline."""
    lock = json.loads((repository_root / PurePosixPath(POLICY_RELATIVE_ROOT) / "policy_lock.json").read_text(encoding="utf-8"))
    locked = lock.get("protected_areas", {})
    current = protected_tree_hashes(repository_root)
    for name, record in locked.items():
        if current.get(name) != record.get("tree_sha256"):
            raise ExecutionBlocked(f"protected area changed: {name}")
    if baseline is not None:
        for name, digest in baseline.items():
            if current.get(name) != digest:
                raise ExecutionBlocked(f"protected area changed during execution: {name}")
    return current


def _run_text(command: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None) -> str:
    completed = subprocess.run(
        command, cwd=cwd, env=env, check=False, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if completed.returncode != 0:
        raise ExecutionBlocked(f"command failed: {Path(command[0]).name} (exit {completed.returncode})")
    return completed.stdout


def _pom_compiler_release(pom_path: Path) -> int:
    root = ElementTree.parse(pom_path).getroot()
    namespace = {"m": root.tag.partition("}")[0].strip("{")} if root.tag.startswith("{") else {}
    node = root.find("m:properties/m:maven.compiler.release", namespace) if namespace else root.find("properties/maven.compiler.release")
    if node is None or not (node.text or "").strip().isdigit():
        raise ExecutionBlocked("sidecar POM does not declare a compiler release")
    return int((node.text or "").strip())


def _pom_sourceafis_version(pom_path: Path) -> str:
    root = ElementTree.parse(pom_path).getroot()
    namespace = {"m": root.tag.partition("}")[0].strip("{")} if root.tag.startswith("{") else {}
    node = root.find("m:properties/m:sourceafis.version", namespace) if namespace else root.find("properties/sourceafis.version")
    if node is None or not (node.text or "").strip():
        raise ExecutionBlocked("sidecar POM does not declare a SourceAFIS version")
    return (node.text or "").strip()


def verify_environment(repository_root: Path, java: Path, maven: Path) -> dict[str, Any]:
    """Confirm the canonical Zulu 17.0.18 / Maven 3.9.16 toolchain and the frozen POM."""
    if not Path(java).is_file():
        raise ExecutionBlocked("configured Java executable does not exist")
    if not Path(maven).is_file():
        raise ExecutionBlocked("configured Maven launcher does not exist")
    properties: dict[str, str] = {}
    for line in _run_text([str(java), "-XshowSettings:properties", "-version"]).splitlines():
        key, separator, value = line.strip().partition(" = ")
        if separator:
            properties[key] = value.strip()
    java_version = properties.get("java.version", "")
    java_vendor = properties.get("java.vendor", "")
    java_home = properties.get("java.home", "")
    architecture = properties.get("os.arch", "")
    # The sidecar reports java.runtime.version ("17.0.18+8-LTS"), which is the string that
    # reaches bundle provenance; java.version ("17.0.18") is the version we pin.
    java_runtime_version = properties.get("java.runtime.version", "")
    if java_version != cohort.JAVA_VERSION:
        raise ExecutionBlocked(f"Java version must be {cohort.JAVA_VERSION}, found {java_version!r}")
    if java_vendor != cohort.JAVA_VENDOR:
        raise ExecutionBlocked(f"Java vendor must be {cohort.JAVA_VENDOR}, found {java_vendor!r}")
    if architecture != "amd64":
        raise ExecutionBlocked(f"architecture must be amd64, found {architecture!r}")
    if not java_runtime_version.startswith(cohort.JAVA_VERSION):
        raise ExecutionBlocked(f"Java runtime version {java_runtime_version!r} is not a {cohort.JAVA_VERSION} build")

    maven_output = _run_text([str(maven), "-version"], env={**os.environ, "JAVA_HOME": java_home})
    maven_version = ""
    maven_java_home = ""
    maven_vendor = ""
    for line in maven_output.splitlines():
        stripped = line.strip()
        if stripped.startswith("Apache Maven "):
            maven_version = stripped.split()[2]
        elif stripped.startswith("Java version:"):
            # The vendor string itself contains a comma, so anchor on the field labels.
            detail = re.search(r"vendor:\s*(?P<vendor>.+?),\s*runtime:\s*(?P<runtime>.+?)\s*$", stripped)
            if detail:
                maven_vendor = detail.group("vendor")
                maven_java_home = detail.group("runtime")
    if maven_version != cohort.MAVEN_VERSION:
        raise ExecutionBlocked(f"Maven version must be {cohort.MAVEN_VERSION}, found {maven_version!r}")
    if maven_vendor != cohort.JAVA_VENDOR:
        raise ExecutionBlocked(f"Maven reports Java vendor {maven_vendor!r}")
    if not maven_java_home or Path(maven_java_home).resolve() != Path(java_home).resolve():
        raise ExecutionBlocked("Maven does not use the canonical Java home")

    pom_path = repository_root / PurePosixPath(SIDECAR_POM)
    compiler_release = _pom_compiler_release(pom_path)
    sourceafis_version = _pom_sourceafis_version(pom_path)
    if compiler_release != cohort.COMPILER_RELEASE:
        raise ExecutionBlocked(f"compiler release must be {cohort.COMPILER_RELEASE}, found {compiler_release}")
    if sourceafis_version != cohort.SOURCEAFIS_VERSION:
        raise ExecutionBlocked(f"SourceAFIS version must be {cohort.SOURCEAFIS_VERSION}, found {sourceafis_version!r}")
    return {
        "compiler_release": compiler_release,
        "java_distribution": cohort.JAVA_DISTRIBUTION,
        "java_home": java_home,
        "java_runtime_version": java_runtime_version,
        "java_vendor": java_vendor,
        "java_version": java_version,
        "maven_version": maven_version,
        "os_arch": architecture,
        "sourceafis_version": sourceafis_version,
    }


def build_canonical_jar(repository_root: Path, results_root: Path, maven: Path, java_home: str) -> tuple[Path, str]:
    """Build the shaded JAR once and freeze a canonical copy for the whole series."""
    pom_path = repository_root / PurePosixPath(SIDECAR_POM)
    runtime_root = results_root / "runtime"
    canonical = runtime_root / SHADED_JAR_NAME
    if canonical.is_file():
        return canonical, file_sha256(canonical)
    environment = {**os.environ, "JAVA_HOME": java_home}
    _run_text([str(maven), "-B", "-f", str(pom_path), "clean", "test", "package"],
              cwd=repository_root, env=environment)
    built = pom_path.parent / "target" / SHADED_JAR_NAME
    if not built.is_file():
        raise ExecutionFailed("Maven did not produce the shaded sidecar JAR")
    runtime_root.mkdir(parents=True, exist_ok=True)
    shutil.copy2(built, canonical)
    return canonical, file_sha256(canonical)


def _post_status(base_url: str, path: str, payload: dict[str, Any]) -> int:
    host, _, port = base_url.removeprefix("http://").partition(":")
    connection = http.client.HTTPConnection(host, int(port), timeout=10)
    try:
        connection.request("POST", path, body=json.dumps(payload).encode("utf-8"),
                           headers={"Content-Type": "application/json"})
        response = connection.getresponse()
        response.read()
        return response.status
    finally:
        connection.close()


def run_preflight(repository_root: Path, dataset_root: Path, jar_path: Path, java: Path) -> dict[str, bool]:
    """Prove the successful path against the locked qualification fixture.

    Qualification template hashes and raw scores are compared numerically for
    technical parity only. No score is returned, printed, aggregated or compared
    against any threshold.
    """
    qualification_root = repository_root / PurePosixPath(QUALIFICATION_RELATIVE_ROOT)
    manifest = json.loads((qualification_root / "qualification_manifest.json").read_text(encoding="utf-8"))
    locked = json.loads((qualification_root / "qualification_results.json").read_text(encoding="utf-8"))
    repetitions = locked["implementations"]["new"]["repetitions"]
    if not repetitions:
        raise ExecutionFailed("qualification package records no repetitions")
    reference = repetitions[0]
    for repetition in repetitions[1:]:
        if repetition["template_sha256"] != reference["template_sha256"] or repetition["raw_scores"] != reference["raw_scores"]:
            raise ExecutionFailed("qualification package is internally inconsistent")

    images: dict[str, bytes] = {}
    for key, record in manifest["images"].items():
        path = Path(dataset_root) / PurePosixPath(record["relative_path"])
        if not path.is_file():
            raise ExecutionBlocked(f"qualification image is missing: {record['relative_path']}")
        payload = path.read_bytes()
        if file_sha256(path) != record["sha256"]:
            raise ExecutionFailed(f"qualification image hash mismatch: {key}")
        images[key] = payload

    checks = {
        "image_hashes_match": True,
        "sourceafis_version_matches": False,
        "template_format_matches": False,
        "extraction_successful": False,
        "verification_successful": False,
        "template_parity": False,
        "score_parity": False,
        "scores_finite": False,
        "removed_routes_absent": False,
        "sidecar_closed": False,
    }
    sidecar = SourceAfisSidecar(jar_path, java_executable=str(java))
    try:
        client = sidecar.start()
        health = client.health()
        checks["sourceafis_version_matches"] = health["sourceafis_version"] == cohort.SOURCEAFIS_VERSION
        templates: dict[str, bytes] = {}
        formats_ok = True
        for key, payload in images.items():
            extracted = client.extract_template(payload, int(manifest["images"][key]["nominal_ppi"]))
            templates[key] = extracted.payload
            formats_ok = formats_ok and extracted.format_id == reference["template_format"][key]
            formats_ok = formats_ok and extracted.format_version == reference["template_version"][key]
        checks["extraction_successful"] = len(templates) == len(images)
        checks["template_format_matches"] = formats_ok
        checks["template_parity"] = all(
            hashlib.sha256(payload).hexdigest() == reference["template_sha256"][key]
            for key, payload in templates.items()
        )
        parity = True
        finite = True
        completed = 0
        for name, (left, right) in QUALIFICATION_COMPARISONS.items():
            verification = client.verify(templates[left], templates[right])
            completed += 1
            finite = finite and math.isfinite(verification.score)
            parity = parity and verification.score == reference["raw_scores"][name]
        checks["verification_successful"] = completed == len(QUALIFICATION_COMPARISONS)
        checks["score_parity"] = parity
        checks["scores_finite"] = finite
        checks["removed_routes_absent"] = all(
            _post_status(sidecar.base_url, route, {}) == 404 for route in REMOVED_ROUTES
        )
    finally:
        sidecar.close()
        checks["sidecar_closed"] = sidecar.process is None
    if not all(checks.values()):
        failed = sorted(name for name, ok in checks.items() if not ok)
        raise ExecutionFailed(f"successful-path preflight failed: {', '.join(failed)}")
    return checks


def _clear_stale_candidates(raw_root: Path, run_id: str) -> None:
    for candidate in raw_root.glob(f"{run_id}.candidate-*"):
        if candidate.is_dir():
            shutil.rmtree(candidate)
    for rollback in raw_root.glob(f"{run_id}.rollback-*"):
        if rollback.is_dir():
            shutil.rmtree(rollback)


def execute_cohort(
    *,
    repository_root: Path,
    dataset_root: Path,
    results_root: Path,
    jar_path: Path,
    jar_sha256: str,
    java: Path,
    execution_code_commit: str,
    java_version: str,
) -> list[dict[str, Any]]:
    """Run the eight frozen manifests in order, validating each bundle before the next."""
    protocol_root = repository_root / PurePosixPath(PROTOCOL_RELATIVE_ROOT)
    raw_root = results_root / "raw"
    raw_root.mkdir(parents=True, exist_ok=True)
    lock_sha256 = file_sha256(protocol_root / "manifest_lock.json")
    entries: list[dict[str, Any]] = []
    for order, relative in enumerate(COHORT_MANIFESTS, start=1):
        manifest_path = protocol_root / PurePosixPath(relative)
        run_id = cohort.expected_run_id(file_sha256(manifest_path), lock_sha256)
        destination = raw_root / run_id
        reused = False
        if destination.is_dir():
            try:
                summary = cohort.validate_cohort_bundle(
                    bundle=destination, protocol_root=protocol_root, manifest_relative_path=relative,
                    expected_jar_sha256=jar_sha256, expected_execution_commit=execution_code_commit,
                    expected_java_version=java_version,
                )
            except cohort.CohortValidationError as exc:
                raise ExecutionBlocked(
                    f"existing bundle for {relative} cannot be reused and will not be overwritten: {exc}"
                ) from exc
            reused = True
        else:
            _clear_stale_candidates(raw_root, run_id)
            command = [
                sys.executable, "-m", "fingerprint_benchmark.cli", "run-sourceafis-manifest",
                "--manifest", str(manifest_path), "--dataset-root", str(dataset_root),
                "--output-root", str(raw_root), "--jar", str(jar_path), "--java", str(java),
            ]
            completed = subprocess.run(
                command, cwd=repository_root, check=False, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            if completed.returncode != 0:
                raise ExecutionFailed(
                    f"manifest execution failed for {relative}: {completed.stderr.strip() or 'no diagnostic output'}"
                )
            if not destination.is_dir():
                raise ExecutionFailed(f"manifest execution published no bundle for {relative}")
            summary = cohort.validate_cohort_bundle(
                bundle=destination, protocol_root=protocol_root, manifest_relative_path=relative,
                expected_jar_sha256=jar_sha256, expected_execution_commit=execution_code_commit,
                expected_java_version=java_version,
            )
        entries.append({
            "bundle_relative_path": f"raw/{run_id}",
            "bundle_validation": summary["bundle_validation"],
            "comparison_kind": summary["comparison_kind"],
            "dataset_release": summary["dataset_release"],
            "execution_code_commit": summary["execution_code_commit"],
            "execution_order": order,
            "jar_sha256": summary["jar_sha256"],
            "java_version": summary["java_version"],
            "manifest_relative_path": relative,
            "manifest_sha256": summary["manifest_sha256"],
            "metadata_sha256": summary["metadata_sha256"],
            "protocol_lock_sha256": summary["protocol_lock_sha256"],
            "provenance_sha256": summary["provenance_sha256"],
            "results_csv_sha256": summary["results_csv_sha256"],
            "reused_existing_bundle": reused,
            "row_count": summary["row_count"],
            "run_id": summary["run_id"],
            "sourceafis_version": summary["sourceafis_version"],
            "successful_scores": summary["successful_scores"],
            "technical_failures": summary["technical_failures"],
        })
    return entries


def _package_payloads(
    *,
    repository_root: Path,
    entries: list[dict[str, Any]],
    environment: dict[str, Any],
    jar_sha256: str,
    execution_code_commit: str,
    tree_hashes: dict[str, str],
    started_at: str,
    finished_at: str,
) -> dict[str, Any]:
    registry_entries = [{key: value for key, value in entry.items() if key != "reused_existing_bundle"} for entry in entries]
    total_rows = sum(entry["row_count"] for entry in registry_entries)
    technical_failures = sum(entry["technical_failures"] for entry in registry_entries)

    plan = {
        "decision_policy_applied": False,
        "decision_policy_id": decision_policy.POLICY_ID,
        "decision_policy_tag": FROZEN_INPUT_TAGS["decision_policy"],
        "execution_code_commit": execution_code_commit,
        "execution_id": EXECUTION_ID,
        "execution_version": EXECUTION_VERSION,
        "expected_rows_per_manifest": cohort.EXPECTED_ROWS_PER_MANIFEST,
        "expected_total_rows": cohort.EXPECTED_TOTAL_ROWS,
        "fresh_jvm_per_manifest": True,
        "manifests": list(COHORT_MANIFESTS),
        "method_id": cohort.METHOD_ID,
        "method_version": cohort.SOURCEAFIS_VERSION,
        "protocol_id": "supervisor_50x10_v1",
        "protocol_relative_root": PROTOCOL_RELATIVE_ROOT,
        "protocol_version": 1,
        "runtime_qualification_id": "sourceafis_runtime_v1",
        "score_analysis_allowed": False,
        "selective_retry_allowed": False,
        "single_jar_for_all_manifests": True,
        "sourceafis_version": cohort.SOURCEAFIS_VERSION,
    }
    environment_payload = {
        "compiler_release": environment["compiler_release"],
        "conda_environment_modified": False,
        "environment": cohort.ENVIRONMENT_IDENTIFIER,
        "execution_code_commit": execution_code_commit,
        "execution_finished_utc": finished_at,
        "execution_id": EXECUTION_ID,
        "execution_started_utc": started_at,
        "jar_sha256": jar_sha256,
        "java_distribution": cohort.JAVA_DISTRIBUTION,
        "java_runtime_version": environment["java_runtime_version"],
        "java_vendor": environment["java_vendor"],
        "java_version": environment["java_version"],
        "maven_version": environment["maven_version"],
        "os_architecture": environment["os_arch"],
        "persistent_system_environment_modified": False,
        "python_version": ".".join(str(part) for part in sys.version_info[:3]),
        "same_jar_for_all_manifests": True,
        "sidecar_contract_version": "sourceafis-sidecar-contract-v1",
        "sidecar_implementation_version": "1.0.0",
        "sourceafis_version": cohort.SOURCEAFIS_VERSION,
        "worktree_clean_at_execution": True,
    }
    registry = {
        "bundles": registry_entries,
        "execution_id": EXECUTION_ID,
        "results_relative_root": cohort.RESULTS_RELATIVE_ROOT,
        "total_rows": total_rows,
        "tracked_by_git": False,
    }
    warnings: list[str] = []
    if technical_failures:
        warnings.append("One or more pair-level technical failures were preserved without selective retry.")
    report = {
        "checks": {
            "bundles_valid": len(registry_entries),
            "decision_fields_generated": False,
            "decision_policy_applied": False,
            "decision_policy_unchanged": True,
            "fresh_jvm_per_manifest": True,
            "manifests_executed": len(registry_entries),
            "protocol_unchanged": True,
            "qualification_unchanged": True,
            "raw_bundles_tracked_by_git": False,
            "rows_per_bundle": cohort.EXPECTED_ROWS_PER_MANIFEST,
            "runtime_unchanged": True,
            "score_analysis_performed": False,
            "selective_retries_performed": False,
            "single_jar_used": True,
            "single_java_runtime_used": True,
            "threshold_read_by_execution": False,
            "total_rows": total_rows,
        },
        "errors": [],
        "execution_id": EXECUTION_ID,
        "valid": True,
        "warnings": warnings,
    }
    return {
        "bundle_registry.json": registry,
        "execution_environment.json": environment_payload,
        "execution_plan.json": plan,
        "execution_validation_report.json": report,
    }


def _lock_payload(
    *,
    repository_root: Path,
    package_root: Path,
    entries: list[dict[str, Any]],
    environment: dict[str, Any],
    jar_sha256: str,
    execution_code_commit: str,
    tree_hashes: dict[str, str],
) -> dict[str, Any]:
    files: dict[str, dict[str, Any]] = {}
    # The lock never covers itself, and never covers the checksum index that covers it.
    locked_package_files = sorted(
        set(cohort.EXECUTION_PACKAGE_FILES) - {"execution_lock.json", "SHA256SUMS.txt"}
    )
    for name in locked_package_files:
        path = package_root / name
        files[f"executions/{EXECUTION_ID}/{name}"] = {
            "sha256": file_sha256(path), "size_bytes": path.stat().st_size,
        }
    for relative in (
        f"tools/run_{EXECUTION_ID}.py",
        f"tools/validate_{EXECUTION_ID}.py",
        f"tests/test_{EXECUTION_ID}.py",
    ):
        path = repository_root / PurePosixPath(relative)
        files[relative] = {"sha256": file_sha256(path), "size_bytes": path.stat().st_size}
    frozen_inputs = {}
    for name, tag in FROZEN_INPUT_TAGS.items():
        frozen_inputs[name] = {
            "commit": REQUIRED_TAGS[tag],
            "tag": tag,
            "tree_sha256": tree_hashes["runtime_sources" if name == "runtime" else name],
        }
    return {
        "bundle_set_sha256": cohort.compute_bundle_set_sha256(entries),
        "bundles": [
            {
                "execution_order": entry["execution_order"],
                "manifest_relative_path": entry["manifest_relative_path"],
                "manifest_sha256": entry["manifest_sha256"],
                "metadata_sha256": entry["metadata_sha256"],
                "provenance_sha256": entry["provenance_sha256"],
                "results_csv_sha256": entry["results_csv_sha256"],
                "run_id": entry["run_id"],
            }
            for entry in sorted(entries, key=lambda item: item["execution_order"])
        ],
        "environment": {
            "compiler_release": environment["compiler_release"],
            "environment": cohort.ENVIRONMENT_IDENTIFIER,
            "java_vendor": environment["java_vendor"],
            "java_version": environment["java_version"],
            "maven_version": environment["maven_version"],
        },
        "execution_code_commit": execution_code_commit,
        "execution_id": EXECUTION_ID,
        "execution_version": EXECUTION_VERSION,
        "files": files,
        "frozen_inputs": frozen_inputs,
        "jar_sha256": jar_sha256,
        "sourceafis_version": cohort.SOURCEAFIS_VERSION,
        "total_rows": sum(entry["row_count"] for entry in entries),
    }


def write_execution_package(
    *,
    repository_root: Path,
    entries: list[dict[str, Any]],
    environment: dict[str, Any],
    jar_sha256: str,
    execution_code_commit: str,
    tree_hashes: dict[str, str],
    started_at: str,
    finished_at: str,
) -> Path:
    """Build the execution package in a candidate directory and publish it atomically."""
    destination = repository_root / "executions" / EXECUTION_ID
    destination.parent.mkdir(parents=True, exist_ok=True)
    candidate = destination.with_name(f"{EXECUTION_ID}.candidate-{uuid.uuid4().hex}")
    candidate.mkdir(parents=True, exist_ok=False)
    try:
        payloads = _package_payloads(
            repository_root=repository_root, entries=entries, environment=environment,
            jar_sha256=jar_sha256, execution_code_commit=execution_code_commit,
            tree_hashes=tree_hashes, started_at=started_at, finished_at=finished_at,
        )
        for name, payload in payloads.items():
            write_json_atomic(candidate / name, payload)
        (candidate / "README.md").write_text(_readme_text(), encoding="utf-8", newline="\n")
        write_json_atomic(candidate / "execution_lock.json", _lock_payload(
            repository_root=repository_root, package_root=candidate, entries=entries,
            environment=environment, jar_sha256=jar_sha256,
            execution_code_commit=execution_code_commit, tree_hashes=tree_hashes,
        ))
        lines = [
            f"{file_sha256(path)}  {path.name}"
            for path in sorted(candidate.iterdir(), key=lambda item: item.name)
            if path.is_file() and path.name != "SHA256SUMS.txt"
        ]
        (candidate / "SHA256SUMS.txt").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
        backup = destination.with_name(f"{EXECUTION_ID}.rollback-{uuid.uuid4().hex}")
        moved = False
        if destination.exists():
            os.replace(destination, backup)
            moved = True
        try:
            os.replace(candidate, destination)
        except BaseException:
            if moved:
                os.replace(backup, destination)
            raise
        if moved:
            shutil.rmtree(backup, ignore_errors=True)
        return destination
    except BaseException:
        shutil.rmtree(candidate, ignore_errors=True)
        raise


def _readme_text() -> str:
    return f"""# SourceAFIS frozen-cohort raw-score execution v1

`{EXECUTION_ID}` records the first execution of the qualified SourceAFIS runtime over the
frozen supervisor protocol. It produces raw similarity scores only. No threshold is applied,
no biometric decision is derived, and no accuracy, FMR or FNMR figure is computed here.

## Manifests and order

The eight frozen manifests always run in this order, and the tool exposes no way to select a
subset, reorder them, or add another manifest:

{chr(10).join(f'{index}. `{name}`' for index, name in enumerate(COHORT_MANIFESTS, start=1))}

Each manifest contributes {cohort.EXPECTED_ROWS_PER_MANIFEST} planned pairs, for
{cohort.EXPECTED_TOTAL_ROWS} result rows in total.

## Environment and runtime

The series runs in the qualified environment `{cohort.ENVIRONMENT_IDENTIFIER}` using
{cohort.JAVA_DISTRIBUTION} {cohort.JAVA_VERSION} ({cohort.JAVA_VENDOR}), Maven
{cohort.MAVEN_VERSION}, compiler release {cohort.COMPILER_RELEASE} and SourceAFIS
{cohort.SOURCEAFIS_VERSION}. Exactly one shaded JAR is built for the whole series and every
manifest reuses that same canonical copy; its SHA-256 is recorded in
`execution_environment.json` and `execution_lock.json`. Every manifest runs in a fresh
process and a fresh JVM, so no template or representation cache is carried between
manifests.

## Results, resume and failures

Raw bundles are written to `{cohort.RESULTS_RELATIVE_ROOT}` inside the working copy and are
deliberately **not** tracked by Git; this package records only their identities, hashes and
counts. An existing bundle is reused only when it validates completely and its manifest
hash, protocol lock hash, JAR hash, execution code commit and Java runtime all match the
current series; any other provenance is reported as BLOCKED and is never overwritten. There
is no resume from the middle of a CSV: an interrupted manifest is discarded with its
candidate directory and re-run in full.

A pair-level extraction or comparison failure is preserved in its own row with an error code
and no score. Such failures are never retried selectively and never converted into a score,
a zero, or a `different` outcome. For every bundle,
`successful_scores + technical_failures = {cohort.EXPECTED_ROWS_PER_MANIFEST}`.

## Validation

The committed package can be checked, with no dataset and no matcher, from the repository
root:

```text
python tools/validate_{EXECUTION_ID}.py
```

Adding `--results-root` to that command additionally re-validates every local raw bundle
row-by-row against its source manifest.

## Stopping point

This package is the end of the execution stage. Applying the frozen decision policy,
producing the supervisor report, and computing FMR, FNMR, accuracy, score distributions or
timing comparisons are all separate, later stages.
"""


def _acquire_execution_lock(results_root: Path) -> Path:
    results_root.mkdir(parents=True, exist_ok=True)
    lock_path = results_root / ".execution.lock"
    try:
        descriptor = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError as exc:
        raise ExecutionBlocked(
            "another frozen-cohort execution holds the local lock; remove it only if no run is active"
        ) from exc
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(json.dumps({"execution_id": EXECUTION_ID, "pid": os.getpid()}) + "\n")
    return lock_path


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=f"run-{EXECUTION_ID}")
    parser.add_argument("--repository-root", required=True, type=Path)
    parser.add_argument("--dataset-root", required=True, type=Path)
    parser.add_argument("--results-root", required=True, type=Path)
    parser.add_argument("--java", required=True, type=Path)
    parser.add_argument("--maven", required=True, type=Path)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--validate-only", action="store_true")
    mode.add_argument("--preflight-only", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    repository_root = args.repository_root.resolve()
    results_root = args.results_root.resolve()
    started_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    try:
        repository = verify_repository(repository_root)
        verify_freeze_packages(repository_root)
        baseline = verify_protected_trees(repository_root)
        if args.validate_only:
            package_root = repository_root / "executions" / EXECUTION_ID
            errors = cohort.validate_execution_package(package_root) if package_root.is_dir() else ["execution package is absent"]
            verify_protected_trees(repository_root, baseline)
            print(json.dumps({"status": "FAIL" if errors else "PASS", "mode": "validate-only",
                              "errors": errors}, indent=2, sort_keys=True))
            return 1 if errors else 0

        environment = verify_environment(repository_root, args.java, args.maven)
        lock_path = _acquire_execution_lock(results_root)
        try:
            jar_path, jar_sha256 = build_canonical_jar(repository_root, results_root, args.maven, environment["java_home"])
            preflight = run_preflight(repository_root, args.dataset_root, jar_path, args.java)
            if args.preflight_only:
                verify_protected_trees(repository_root, baseline)
                print(json.dumps({"status": "PASS", "mode": "preflight-only",
                                  "jar_sha256": jar_sha256, "preflight": preflight}, indent=2, sort_keys=True))
                return 0
            entries = execute_cohort(
                repository_root=repository_root, dataset_root=args.dataset_root, results_root=results_root,
                jar_path=jar_path, jar_sha256=jar_sha256, java=args.java,
                execution_code_commit=repository["head"], java_version=environment["java_runtime_version"],
            )
        finally:
            lock_path.unlink(missing_ok=True)

        tree_hashes = verify_protected_trees(repository_root, baseline)
        finished_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        package_root = write_execution_package(
            repository_root=repository_root, entries=entries, environment=environment,
            jar_sha256=jar_sha256, execution_code_commit=repository["head"],
            tree_hashes=tree_hashes, started_at=started_at, finished_at=finished_at,
        )
        errors = cohort.validate_execution_package(package_root)
        if errors:
            raise ExecutionFailed(f"execution package failed validation: {errors[0]}")
        print(json.dumps({
            "status": "PASS",
            "execution_code_commit": repository["head"],
            "jar_sha256": jar_sha256,
            "bundles": [
                {
                    "comparison_kind": entry["comparison_kind"],
                    "dataset_release": entry["dataset_release"],
                    "execution_order": entry["execution_order"],
                    "reused_existing_bundle": entry["reused_existing_bundle"],
                    "successful_scores": entry["successful_scores"],
                    "technical_failures": entry["technical_failures"],
                }
                for entry in entries
            ],
            "total_rows": sum(entry["row_count"] for entry in entries),
        }, indent=2, sort_keys=True))
        return 0
    except ExecutionBlocked as exc:
        print(json.dumps({"status": "BLOCKED", "reason": str(exc)}, indent=2, sort_keys=True), file=sys.stderr)
        return 3
    except (ExecutionFailed, cohort.CohortValidationError) as exc:
        print(json.dumps({"status": "FAIL", "reason": str(exc)}, indent=2, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
