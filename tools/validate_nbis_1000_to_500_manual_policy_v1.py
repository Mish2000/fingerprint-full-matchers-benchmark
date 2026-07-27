"""Read-only validation for the project-local manual downsampler policy v1."""

from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


POLICY_ID = "NBIS_1000_TO_500_MANUAL_POLICY_V1"
POLICY_VERSION = 1
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_RELATIVE = Path("preprocessing") / "nbis_1000_to_500_manual_policy_v1"
PACKAGE_FILES = (
    "README.md",
    "SHA256SUMS.txt",
    "determinism_results.json",
    "implementation_identity.json",
    "policy.json",
    "synthetic_vectors.json",
    "validation_report.json",
)
JSON_FILES = tuple(name for name in PACKAGE_FILES if name.endswith(".json"))
CHECKSUM_FILES = tuple(name for name in PACKAGE_FILES if name != "SHA256SUMS.txt")
IDENTITY_FILES = (
    ".github/workflows/nbis-1000-to-500-manual-policy-v1.yml",
    "docs/nbis_1000_to_500_manual_policy_v1.md",
    "tests/test_nbis_1000_to_500_manual_policy_v1.py",
    "tools/nbis_downsample_1000_to_500_manual_reference_v1.py",
    "tools/nbis_downsample_1000_to_500_manual_v1.py",
    "tools/run_nbis_1000_to_500_manual_policy_tests_v1.py",
    "tools/validate_nbis_1000_to_500_manual_policy_v1.py",
)
SOURCE_AUDIT_TAG = "nbis-1000-ppi-downsampler-audit-v1"
SOURCE_AUDIT_COMMIT = "58c2f3f5454af87d76bdaf8d166b6d6f1a28e77f"
Q31_SCALE = 1 << 31
KERNEL_Q31 = [
    14706, 1922071, 62430569, 503934447, 1010880062,
    503934447, 62430569, 1922071, 14706,
]
REQUIRED_PURPOSES = {
    "all_zeros", "all_255", "constant_mid_gray", "impulse_center",
    "impulse_top_left", "impulse_top_right", "impulse_bottom_left", "impulse_bottom_right",
    "impulse_adjacent_top", "impulse_adjacent_bottom", "impulse_adjacent_left",
    "impulse_adjacent_right", "horizontal_gradient", "vertical_gradient",
    "two_dimensional_gradient", "horizontal_alternating_stripes",
    "vertical_alternating_stripes", "checkerboard", "isolated_zero_in_255",
    "isolated_255_in_zero", "clipping_sensitive", "rounding_half_sensitive",
    "kernel_sized_9x9", "smaller_than_kernel", "even_width_even_height",
    "odd_width_odd_height", "even_width_odd_height", "odd_width_even_height",
    "dimensions_1_through_12", "deterministic_pseudorandom", "parity_sensitive",
    "border_sensitive",
}
FORBIDDEN_IMPORTS = {"cv2", "numpy", "PIL", "scipy", "skimage"}
_WINDOWS_ABSOLUTE = re.compile(r"(?i)(?:^|[\s\"'`(])[a-z]:[\\/]")
_FORBIDDEN_DATASET = re.compile(r"(?i)fingerprint-datasets[\\/]nist")
_FORBIDDEN_SUBJECT = re.compile(r"(?<!\d)00001000(?!\d)")


def canonical_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode("utf-8")


def file_sha256(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def _load(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, REPOSITORY_ROOT / relative)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {relative}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _walk(value: Any):
    yield value
    if isinstance(value, dict):
        for child in value.values():
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


def _parse_checksums(path: Path) -> tuple[dict[str, str], list[str]]:
    records: dict[str, str] = {}
    order: list[str] = []
    errors: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\\]+)", line)
        if match is None:
            errors.append(f"invalid checksum line: {line!r}")
            continue
        digest, name = match.groups()
        if name in records:
            errors.append(f"duplicate checksum entry: {name}")
        records[name] = digest
        order.append(name)
    if order != sorted(order):
        errors.append("checksum records are not sorted")
    return records, errors


def _forbidden_imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    return imported.intersection(FORBIDDEN_IMPORTS)


def validate_package(repository_root: Path = REPOSITORY_ROOT) -> list[str]:
    repository_root = Path(repository_root).resolve()
    package_root = repository_root / PACKAGE_RELATIVE
    if not package_root.is_dir():
        return [f"manual-policy package is missing: {PACKAGE_RELATIVE.as_posix()}"]
    present = sorted(path.name for path in package_root.iterdir() if path.is_file())
    if present != sorted(PACKAGE_FILES):
        return ["manual-policy package file set mismatch"]

    errors: list[str] = []
    try:
        documents = {
            name: json.loads((package_root / name).read_text(encoding="utf-8"))
            for name in JSON_FILES
        }
    except (OSError, json.JSONDecodeError) as exc:
        return [f"cannot parse manual-policy JSON: {exc}"]
    for name, document in documents.items():
        if (package_root / name).read_bytes() != canonical_json_bytes(document):
            errors.append(f"non-canonical JSON: {name}")
        if document.get("policy_id") != POLICY_ID or document.get("policy_version") != POLICY_VERSION:
            errors.append(f"policy identity mismatch: {name}")

    policy = documents["policy.json"]
    expected_policy = {
        "authority": "PROJECT_OWNER_MANUAL_SELECTION",
        "border_rule": "EDGE_REPLICATION",
        "clipping_rule": "CLAMP_TO_U8_AFTER_TRUNCATION",
        "column_start_zero_based": 1,
        "filter_before_decimation": True,
        "kernel_q31": KERNEL_Q31,
        "nist_conformance_claim": "NOT_CLAIMED",
        "normalization_scale": Q31_SCALE,
        "output_height_rule": "floor(input_height/2)",
        "output_rounding": "TRUNCATE_NONNEGATIVE_FIXED_POINT",
        "output_width_rule": "floor(input_width/2)",
        "prior_audit_status": "UNRESOLVED_UNCHANGED",
        "radius": 4,
        "row_start_zero_based": 1,
        "sigma_decimal": "0.8475",
    }
    for key, expected in expected_policy.items():
        if policy.get(key) != expected:
            errors.append(f"manual policy mismatch: {key}")
    if sum(policy.get("kernel_q31", [])) != Q31_SCALE:
        errors.append("Q31 kernel does not sum exactly to its scale")
    if policy.get("kernel_q31") != list(reversed(policy.get("kernel_q31", []))):
        errors.append("Q31 kernel is not symmetric")

    identity = documents["implementation_identity.json"]
    records = identity.get("files", {})
    if set(records) != set(IDENTITY_FILES):
        errors.append("implementation identity file set mismatch")
    else:
        for relative in IDENTITY_FILES:
            path = repository_root / relative
            expected = {"bytes": path.stat().st_size, "sha256": file_sha256(path)}
            if records.get(relative) != expected:
                errors.append(f"implementation identity mismatch: {relative}")
    if identity.get("canonical_structure") != "SEPARABLE_TWO_PASS_SINGLE_FINAL_DIVISION":
        errors.append("canonical structure identity mismatch")
    if identity.get("reference_structure") != "DIRECT_TWO_DIMENSIONAL_CONVOLUTION":
        errors.append("reference structure identity mismatch")
    if identity.get("third_party_dependencies") != []:
        errors.append("manual implementation has third-party dependencies")

    canonical = _load("manual_policy_canonical", "tools/nbis_downsample_1000_to_500_manual_v1.py")
    reference = _load("manual_policy_reference", "tools/nbis_downsample_1000_to_500_manual_reference_v1.py")
    if canonical.POLICY_ID != POLICY_ID or reference.POLICY_ID != POLICY_ID:
        errors.append("implementation module policy identity mismatch")
    if list(canonical.KERNEL_Q31) != KERNEL_Q31 or list(reference.KERNEL_Q31) != KERNEL_Q31:
        errors.append("implementation coefficient identity mismatch")
    for relative in (
        "tools/nbis_downsample_1000_to_500_manual_v1.py",
        "tools/nbis_downsample_1000_to_500_manual_reference_v1.py",
    ):
        forbidden = _forbidden_imports(repository_root / relative)
        if forbidden:
            errors.append(f"forbidden dependency import in {relative}: {sorted(forbidden)}")

    vectors = documents["synthetic_vectors.json"]
    if vectors.get("synthetic_only") is not True or vectors.get("dataset_accessed") is not False:
        errors.append("synthetic vector isolation mismatch")
    records_list = vectors.get("vectors", [])
    purposes = {record.get("purpose") for record in records_list if isinstance(record, dict)}
    if not REQUIRED_PURPOSES.issubset(purposes):
        errors.append("synthetic vector purpose coverage is incomplete")
    if vectors.get("vector_count") != len(records_list):
        errors.append("synthetic vector count mismatch")
    for record in records_list:
        if not isinstance(record, dict):
            errors.append("invalid synthetic vector record")
            continue
        matrix = record.get("input_matrix")
        expected_output = record.get("expected_output_matrix")
        try:
            actual = canonical.downsample_u8_matrix(matrix)
            independent = reference.downsample_u8_matrix(matrix)
        except (TypeError, ValueError) as exc:
            errors.append(f"synthetic vector cannot execute: {record.get('vector_id')}: {exc}")
            continue
        if actual != independent or actual != expected_output:
            errors.append(f"synthetic vector output mismatch: {record.get('vector_id')}")
        if record.get("expected_source") != "MANUAL_POLICY_INDEPENDENT_IMPLEMENTATION_AGREEMENT":
            errors.append(f"synthetic vector source mismatch: {record.get('vector_id')}")

    determinism = documents["determinism_results.json"]
    if determinism.get("fresh_process_repetitions") != 3:
        errors.append("fresh-process repetition count mismatch")
    if determinism.get("local_fresh_process_status") != "PASS":
        errors.append("local fresh-process result is not PASS")
    if determinism.get("ci_required") is not True:
        errors.append("CI determinism requirement is not fixed")

    report = documents["validation_report.json"]
    if report.get("valid") is not True or report.get("errors") != []:
        errors.append("validation report is not a clean PASS")
    for flag in (
        "biometric_input_accessed", "dataset_accessed", "fixture_processed",
        "protocol_image_manifest_read", "mindtct_invoked", "bozorth3_invoked",
        "scores_generated",
    ):
        if report.get(flag) is not False:
            errors.append(f"isolation evidence mismatch: {flag}")

    for value in _walk(documents):
        if isinstance(value, str) and (
            _WINDOWS_ABSOLUTE.search(value)
            or _FORBIDDEN_DATASET.search(value)
            or _FORBIDDEN_SUBJECT.search(value)
        ):
            errors.append("package contains prohibited local path or subject material")
            break
    readme = (package_root / "README.md").read_text(encoding="utf-8")
    if _WINDOWS_ABSOLUTE.search(readme) or _FORBIDDEN_DATASET.search(readme) or _FORBIDDEN_SUBJECT.search(readme):
        errors.append("README contains prohibited local path or subject material")

    checksums, checksum_errors = _parse_checksums(package_root / "SHA256SUMS.txt")
    errors.extend(checksum_errors)
    if set(checksums) != set(CHECKSUM_FILES):
        errors.append("checksum file set mismatch")
    else:
        for name in CHECKSUM_FILES:
            if checksums.get(name) != file_sha256(package_root / name):
                errors.append(f"checksum mismatch: {name}")

    try:
        tag_commit = subprocess.run(
            ["git", "rev-list", "-n", "1", SOURCE_AUDIT_TAG],
            cwd=repository_root, check=True, capture_output=True, text=True, encoding="utf-8",
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        errors.append(f"cannot resolve source audit tag: {exc}")
    else:
        if tag_commit != SOURCE_AUDIT_COMMIT:
            errors.append("source audit tag identity mismatch")

    workflow = (repository_root / IDENTITY_FILES[0]).read_text(encoding="utf-8").casefold()
    if "run_nbis_1000_to_500_manual_policy_tests_v1.py" not in workflow:
        errors.append("dedicated workflow does not run the fixed test runner")
    if "validate_nbis_1000_to_500_manual_policy_v1.py" not in workflow:
        errors.append("dedicated workflow does not run the policy validator")
    if any(token in workflow for token in ("curl ", "wget ", "wsl.exe", "python -m pytest")):
        errors.append("dedicated workflow contains a prohibited command")
    return errors


def main() -> int:
    errors = validate_package()
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        print("NBIS manual downsampler policy v1 validation: FAIL", file=sys.stderr)
        return 1
    print("NBIS manual downsampler policy v1 validation: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
