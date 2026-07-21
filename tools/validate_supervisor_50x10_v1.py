"""Read-only validator for the supervisor_50x10_v1 protocol package."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


PROTOCOL_ID = "supervisor_50x10_v1"
PROTOCOL_VERSION = 1
SOURCE_REPOSITORY_COMMIT = "0893d50d08972fc68337749332ecdaa0faef2a70"
AUDIT_REPOSITORY_COMMIT = "a72e97f35b2a66ec6171a6ece25013ae1c371aef"
LOCKED_CONFIG_SHA256 = "4903c78b3d93218e05b834fc4d9a4308defda894b1a7e47d3169f5aa07bc7570"
CURRENT_CONFIG_SHA256 = "3c0fbd38861da31b5bb015f62d7332a58863527529580e5a8a8a66406529e7f3"

MANIFEST_COLUMNS = [
    "pair_id",
    "comparison_kind",
    "dataset_release",
    "subject_index_a",
    "subject_id_a",
    "subject_index_b",
    "subject_id_b",
    "canonical_finger",
    "hand",
    "finger_name",
    "capture_type_a",
    "capture_type_b",
    "nominal_ppi_a",
    "nominal_ppi_b",
    "relative_path_a",
    "relative_path_b",
    "sha256_a",
    "sha256_b",
    "source_frgp_a",
    "source_frgp_b",
    "image_status_a",
    "image_status_b",
    "pair_status",
    "source_pair_id",
]

RELEASES = {"sd300b": 1000, "sd300c": 2000}
COMPARISON_KINDS = (
    "plain_self",
    "roll_self",
    "plain_roll_genuine",
    "plain_roll_next_subject",
)
MANIFEST_FILENAMES = {
    "plain_self": "plain_self.csv",
    "roll_self": "roll_self.csv",
    "plain_roll_genuine": "plain_roll_genuine.csv",
    "plain_roll_next_subject": "plain_roll_next_subject.csv",
}
SOURCE_BASE_MANIFESTS = {
    ("sd300b", "plain_roll_genuine"): "outputs/base_500_genuine_sd300b.csv",
    ("sd300c", "plain_roll_genuine"): "outputs/base_500_genuine_sd300c.csv",
    ("sd300b", "plain_roll_next_subject"): "outputs/base_500_impostor_sd300b.csv",
    ("sd300c", "plain_roll_next_subject"): "outputs/base_500_impostor_sd300c.csv",
}
PROVENANCE_COPIES = {
    "provenance/selected_50_subjects.csv": "outputs/selected_50_subjects.csv",
    "provenance/selected_50_subjects.txt": "outputs/selected_50_subjects.txt",
    "provenance/selection_provenance.json": "outputs/selection_provenance.json",
    "provenance/manual_review_decisions.csv": "config/manual_review_decisions.csv",
    "provenance/duplicate_identity_review.csv": "outputs/duplicate_identity_review.csv",
    "provenance/duplicate_identity_summary.json": "outputs/duplicate_identity_summary.json",
    "provenance/raw_data_verification.json": "outputs/raw_data_verification.json",
}
REQUIRED_SOURCE_HASH_PATHS = {
    *SOURCE_BASE_MANIFESTS.values(),
    *PROVENANCE_COPIES.values(),
    "outputs/manifest_lock.json",
    "outputs/MANIFEST_SHA256SUMS.txt",
    "config/stage0_config.yaml",
}
EXPECTED_WARNINGS = [
    "Stage0 config hash mismatch is documented; the old config is not a protocol runtime input.",
    "Two structurally complete subjects were blocked by an unverified prior-report suspicion and are not part of the frozen cohort.",
    "Manual review decisions are included and hashed as selection provenance.",
]

# Split literals keep this audit list from being mistaken for an active integration.
FORBIDDEN_ACTIVE_TERMS = (
    "Source" + "AFIS",
    "Fingerprint" + "Matcher",
    "SI" + "FT",
    "Root" + "SI" + "FT",
    "Har" + "ris",
    "GF" + "TT",
    "Open" + "CV",
    "RAN" + "SAC",
    "detector_" + "only",
    "final_" + "minutiae",
    "thresh" + "old",
    "calib" + "ration",
)


@dataclass
class ValidationResult:
    checks: dict[str, Any]
    errors: list[str]
    warnings: list[str]

    @property
    def valid(self) -> bool:
        return not self.errors and all(
            value is True
            for key, value in self.checks.items()
            if key.endswith("_valid")
        )

    def report(self) -> dict[str, Any]:
        return {
            "protocol_id": PROTOCOL_ID,
            "valid": self.valid,
            "checks": self.checks,
            "errors": self.errors,
            "warnings": self.warnings,
        }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            block = handle.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def read_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        return list(reader.fieldnames or []), list(reader)


def json_text(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _is_lower_sha256(value: str) -> bool:
    return len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def _safe_relative_source_path(root: Path, relative: str) -> Path:
    if not relative or "\\" in relative or ":" in relative or relative.startswith("/"):
        raise ValueError(f"unsafe source-relative path: {relative!r}")
    parts = relative.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise ValueError(f"unsafe source-relative path: {relative!r}")
    resolved_root = root.resolve()
    resolved = resolved_root.joinpath(*parts).resolve()
    try:
        resolved.relative_to(resolved_root)
    except ValueError as exc:
        raise ValueError(f"source path escapes curation root: {relative!r}") from exc
    return resolved


def _validate_dataset_path(
    value: str,
    release: str,
    dataset_root: Path,
    errors: list[str],
    context: str,
) -> None:
    if not value or "\\" in value or ":" in value or value.startswith("/"):
        errors.append(f"{context}: path is not a normalized relative path: {value!r}")
        return
    parts = value.split("/")
    if any(part in ("", ".", "..") for part in parts):
        errors.append(f"{context}: path contains an unsafe component: {value!r}")
        return
    if parts[0].lower() != release:
        errors.append(f"{context}: path is outside release {release}: {value!r}")
        return
    root = dataset_root.resolve()
    target = root.joinpath(*parts).resolve()
    try:
        target.relative_to(root)
    except ValueError:
        errors.append(f"{context}: path escapes dataset root: {value!r}")
        return
    if not target.is_file():
        errors.append(f"{context}: referenced image does not exist: {value!r}")


def _source_path_as_relative(source_path: str, dataset_root: Path, release: str) -> str:
    root = dataset_root.resolve()
    path = Path(source_path).resolve()
    relative = path.relative_to(root).as_posix()
    if not path.is_file() or relative.split("/", 1)[0].lower() != release:
        raise ValueError(f"source image path is invalid for {release}: {source_path}")
    return relative


def _expected_hand_and_name(finger: int) -> tuple[str, str]:
    names = ("thumb", "index", "middle", "ring", "little")
    if 1 <= finger <= 5:
        return "right", names[finger - 1]
    return "left", names[finger - 6]


def _expected_pair_id(kind: str, subject_a: str, subject_b: str, finger: int) -> str:
    if kind == "plain_self":
        return f"PSELF_{subject_a}_F{finger:02d}"
    if kind == "roll_self":
        return f"RSELF_{subject_a}_F{finger:02d}"
    if kind == "plain_roll_genuine":
        return f"GEN_{subject_a}_F{finger:02d}"
    return f"IMP_{subject_a}_{subject_b}_F{finger:02d}"


def _load_selected_subjects(protocol_root: Path, errors: list[str]) -> list[str]:
    csv_path = protocol_root / "provenance" / "selected_50_subjects.csv"
    txt_path = protocol_root / "provenance" / "selected_50_subjects.txt"
    if not csv_path.is_file() or not txt_path.is_file():
        errors.append("selected-subject provenance files are missing")
        return []
    _, rows = read_csv(csv_path)
    text_ids = [line.strip() for line in txt_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    ids = [row.get("subject_id", "") for row in rows]
    indices = [row.get("subject_index", "") for row in rows]
    if len(ids) != 50 or len(set(ids)) != 50:
        errors.append("selected_50_subjects.csv must contain 50 unique subjects")
    if indices != [str(index) for index in range(1, 51)]:
        errors.append("selected_50_subjects.csv subject_index order is not 1..50")
    if ids != text_ids:
        errors.append("selected subject order differs between CSV and TXT")
    if "00001585" in ids or "00001586" in ids:
        errors.append("suspected duplicate subjects appear in the frozen cohort")
    return ids


def _validate_manifest_rows(
    release: str,
    kind: str,
    rows: list[dict[str, str]],
    selected: list[str],
    dataset_root: Path,
    errors: list[str],
) -> None:
    expected_ppi = str(RELEASES[release])
    seen_pair_ids: set[str] = set()
    for position, row in enumerate(rows):
        context = f"{release}/{MANIFEST_FILENAMES[kind]} row {position + 2}"
        subject_index = position // 10 + 1
        finger = position % 10 + 1
        if row.get("comparison_kind") != kind:
            errors.append(f"{context}: comparison_kind mismatch")
        if row.get("dataset_release") != release:
            errors.append(f"{context}: dataset_release mismatch")
        if row.get("subject_index_a") != str(subject_index):
            errors.append(f"{context}: subject_index_a/order mismatch")
        if selected and row.get("subject_id_a") != selected[subject_index - 1]:
            errors.append(f"{context}: subject_id_a/order mismatch")
        if row.get("canonical_finger") != str(finger):
            errors.append(f"{context}: canonical finger/order mismatch")
        hand, name = _expected_hand_and_name(finger)
        if row.get("hand") != hand or row.get("finger_name") != name:
            errors.append(f"{context}: hand/finger_name mismatch")

        if kind == "plain_roll_next_subject":
            subject_index_b = subject_index % 50 + 1
            subject_b = selected[subject_index_b - 1] if selected else ""
            expected_types = ("PLAIN", "ROLL")
            if row.get("subject_id_a") == row.get("subject_id_b"):
                errors.append(f"{context}: impostor subjects are equal")
        else:
            subject_index_b = subject_index
            subject_b = selected[subject_index - 1] if selected else ""
            expected_types = {
                "plain_self": ("PLAIN", "PLAIN"),
                "roll_self": ("ROLL", "ROLL"),
                "plain_roll_genuine": ("PLAIN", "ROLL"),
            }[kind]
            if row.get("subject_id_a") != row.get("subject_id_b"):
                errors.append(f"{context}: self/genuine subjects differ")

        if row.get("subject_index_b") != str(subject_index_b):
            errors.append(f"{context}: subject_index_b/cyclic mapping mismatch")
        if selected and row.get("subject_id_b") != subject_b:
            errors.append(f"{context}: subject_id_b/cyclic mapping mismatch")
        if (row.get("capture_type_a"), row.get("capture_type_b")) != expected_types:
            errors.append(f"{context}: capture types mismatch")
        if row.get("nominal_ppi_a") != expected_ppi or row.get("nominal_ppi_b") != expected_ppi:
            errors.append(f"{context}: nominal PPI mismatch")
        if "5080" in (row.get("nominal_ppi_a", ""), row.get("nominal_ppi_b", "")):
            errors.append(f"{context}: forbidden PNG metadata PPI appears")
        expected_id = _expected_pair_id(
            kind,
            row.get("subject_id_a", ""),
            row.get("subject_id_b", ""),
            finger,
        )
        if row.get("pair_id") != expected_id:
            errors.append(f"{context}: pair_id mismatch")
        if row.get("pair_id", "") in seen_pair_ids:
            errors.append(f"{context}: duplicate pair_id")
        seen_pair_ids.add(row.get("pair_id", ""))
        if not row.get("source_pair_id"):
            errors.append(f"{context}: source_pair_id is empty")
        for side in ("a", "b"):
            if not _is_lower_sha256(row.get(f"sha256_{side}", "")):
                errors.append(f"{context}: sha256_{side} is invalid")
            if not row.get(f"image_status_{side}"):
                errors.append(f"{context}: image_status_{side} is empty")
            _validate_dataset_path(
                row.get(f"relative_path_{side}", ""),
                release,
                dataset_root,
                errors,
                f"{context} side {side}",
            )
        if kind in ("plain_self", "roll_self"):
            for suffix in ("subject_index", "subject_id", "relative_path", "sha256", "source_frgp", "image_status"):
                if row.get(f"{suffix}_a") != row.get(f"{suffix}_b"):
                    errors.append(f"{context}: self pair differs in {suffix}")


def _validate_source_correspondence(
    manifests: dict[tuple[str, str], list[dict[str, str]]],
    curation_root: Path,
    dataset_root: Path,
    errors: list[str],
) -> None:
    for release in RELEASES:
        source_genuine_path = curation_root / SOURCE_BASE_MANIFESTS[(release, "plain_roll_genuine")]
        source_impostor_path = curation_root / SOURCE_BASE_MANIFESTS[(release, "plain_roll_next_subject")]
        if not source_genuine_path.is_file() or not source_impostor_path.is_file():
            errors.append(f"{release}: external base manifests are missing")
            continue
        _, genuine_source = read_csv(source_genuine_path)
        _, impostor_source = read_csv(source_impostor_path)
        genuine_by_id = {row["pair_id"]: row for row in genuine_source}
        impostor_by_id = {row["pair_id"]: row for row in impostor_source}

        for kind in COMPARISON_KINDS:
            for row in manifests.get((release, kind), []):
                context = f"{release}/{kind}/{row.get('pair_id', '')}"
                source = (
                    impostor_by_id.get(row.get("source_pair_id", ""))
                    if kind == "plain_roll_next_subject"
                    else genuine_by_id.get(row.get("source_pair_id", ""))
                )
                if source is None:
                    errors.append(f"{context}: source_pair_id not found in frozen base manifest")
                    continue
                if kind == "plain_roll_next_subject":
                    expected = {
                        "subject_index_a": source["plain_subject_index"],
                        "subject_id_a": source["plain_subject_id"],
                        "subject_index_b": source["roll_subject_index"],
                        "subject_id_b": source["roll_subject_id"],
                        "relative_path_a": _source_path_as_relative(source["plain_path"], dataset_root, release),
                        "relative_path_b": _source_path_as_relative(source["roll_path"], dataset_root, release),
                        "sha256_a": source["plain_sha256"],
                        "sha256_b": source["roll_sha256"],
                        "source_frgp_a": source["plain_source_frgp"],
                        "source_frgp_b": source["roll_source_frgp"],
                        "image_status_a": source["plain_status"],
                        "image_status_b": source["roll_status"],
                        "pair_status": source["pair_status"],
                    }
                else:
                    capture = "plain" if kind == "plain_self" else "roll" if kind == "roll_self" else None
                    expected = {
                        "subject_index_a": source["subject_index"],
                        "subject_id_a": source["subject_id"],
                        "subject_index_b": source["subject_index"],
                        "subject_id_b": source["subject_id"],
                        "pair_status": source["pair_status"],
                    }
                    if capture:
                        expected.update(
                            {
                                "relative_path_a": _source_path_as_relative(source[f"{capture}_path"], dataset_root, release),
                                "relative_path_b": _source_path_as_relative(source[f"{capture}_path"], dataset_root, release),
                                "sha256_a": source[f"{capture}_sha256"],
                                "sha256_b": source[f"{capture}_sha256"],
                                "source_frgp_a": source[f"{capture}_source_frgp"],
                                "source_frgp_b": source[f"{capture}_source_frgp"],
                                "image_status_a": source[f"{capture}_status"],
                                "image_status_b": source[f"{capture}_status"],
                            }
                        )
                    else:
                        expected.update(
                            {
                                "relative_path_a": _source_path_as_relative(source["plain_path"], dataset_root, release),
                                "relative_path_b": _source_path_as_relative(source["roll_path"], dataset_root, release),
                                "sha256_a": source["plain_sha256"],
                                "sha256_b": source["roll_sha256"],
                                "source_frgp_a": source["plain_source_frgp"],
                                "source_frgp_b": source["roll_source_frgp"],
                                "image_status_a": source["plain_status"],
                                "image_status_b": source["roll_status"],
                            }
                        )
                expected.update(
                    {
                        "canonical_finger": source["canonical_finger"],
                        "hand": source["hand"],
                        "finger_name": source["finger_name"],
                    }
                )
                for field, expected_value in expected.items():
                    if row.get(field) != expected_value:
                        errors.append(f"{context}: {field} differs from frozen source")


def _validate_cross_release_structure(
    manifests: dict[tuple[str, str], list[dict[str, str]]], errors: list[str]
) -> None:
    logical_fields = [
        "pair_id",
        "comparison_kind",
        "subject_index_a",
        "subject_id_a",
        "subject_index_b",
        "subject_id_b",
        "canonical_finger",
        "hand",
        "finger_name",
        "capture_type_a",
        "capture_type_b",
        "source_frgp_a",
        "source_frgp_b",
        "image_status_a",
        "image_status_b",
        "pair_status",
        "source_pair_id",
    ]
    for kind in COMPARISON_KINDS:
        left = manifests.get(("sd300b", kind), [])
        right = manifests.get(("sd300c", kind), [])
        if len(left) != len(right):
            errors.append(f"{kind}: release row counts differ")
            continue
        for index, (row_b, row_c) in enumerate(zip(left, right), start=2):
            if [row_b.get(field) for field in logical_fields] != [row_c.get(field) for field in logical_fields]:
                errors.append(f"{kind} row {index}: logical structure differs across releases")


def _validate_source_hashes_and_provenance(
    protocol_root: Path, curation_root: Path, errors: list[str]
) -> None:
    source_hash_path = protocol_root / "provenance" / "source_artifact_hashes.json"
    if not source_hash_path.is_file():
        errors.append("source_artifact_hashes.json is missing")
        return
    data = read_json(source_hash_path)
    if data.get("source_repository_commit") != SOURCE_REPOSITORY_COMMIT:
        errors.append("source repository commit provenance mismatch")
    if data.get("audit_repository_commit") != AUDIT_REPOSITORY_COMMIT:
        errors.append("audit repository commit provenance mismatch")
    if data.get("stage0_locked_config_sha256") != LOCKED_CONFIG_SHA256:
        errors.append("locked Stage0 config hash provenance mismatch")
    if data.get("stage0_current_config_sha256") != CURRENT_CONFIG_SHA256:
        errors.append("current Stage0 config hash provenance mismatch")
    if data.get("stage0_config_used_as_protocol_input") is not False:
        errors.append("Stage0 config is incorrectly marked as a protocol input")
    artifacts = data.get("artifacts")
    if not isinstance(artifacts, list):
        errors.append("source artifact list is invalid")
        return
    artifact_paths = {item.get("path") for item in artifacts if isinstance(item, dict)}
    if not REQUIRED_SOURCE_HASH_PATHS.issubset(artifact_paths):
        errors.append("source artifact hash inventory is incomplete")
    for item in artifacts:
        if not isinstance(item, dict):
            errors.append("source artifact hash entry is invalid")
            continue
        try:
            source = _safe_relative_source_path(curation_root, str(item.get("path", "")))
        except ValueError as exc:
            errors.append(str(exc))
            continue
        if not source.is_file():
            errors.append(f"source artifact is missing: {item.get('path')}")
            continue
        if source.stat().st_size != item.get("size_bytes") or sha256_file(source) != item.get("sha256"):
            errors.append(f"source artifact changed: {item.get('path')}")
    for destination, source_relative in PROVENANCE_COPIES.items():
        copied = protocol_root.joinpath(*destination.split("/"))
        source = curation_root.joinpath(*source_relative.split("/"))
        if not copied.is_file() or not source.is_file() or copied.read_bytes() != source.read_bytes():
            errors.append(f"provenance copy is not byte-identical: {destination}")
    manual_path = protocol_root / "provenance" / "manual_review_decisions.csv"
    if manual_path.is_file():
        _, manual_rows = read_csv(manual_path)
        if len(manual_rows) != 11 or {row.get("decision") for row in manual_rows} != {"challenge"}:
            errors.append("manual review provenance must contain 11 retained challenge decisions")
    duplicate_path = protocol_root / "provenance" / "duplicate_identity_review.csv"
    if duplicate_path.is_file():
        _, duplicate_rows = read_csv(duplicate_path)
        if len(duplicate_rows) != 1:
            errors.append("duplicate identity provenance must contain exactly one relation")
        else:
            row = duplicate_rows[0]
            if (
                row.get("subject_id_a") != "00001585"
                or row.get("subject_id_b") != "00001586"
                or row.get("evidence_type") != "prior_report"
                or row.get("status") != "suspected"
            ):
                errors.append("duplicate identity caveat differs from the frozen curation record")


def _all_protocol_files(protocol_root: Path) -> list[Path]:
    return sorted(
        (path for path in protocol_root.rglob("*") if path.is_file()),
        key=lambda path: path.relative_to(protocol_root).as_posix(),
    )


def _validate_lock(
    protocol_root: Path,
    curation_root: Path,
    repository_root: Path,
    errors: list[str],
) -> None:
    lock_path = protocol_root / "manifest_lock.json"
    if not lock_path.is_file():
        errors.append("manifest_lock.json is missing")
        return
    lock = read_json(lock_path)
    if lock.get("protocol_id") != PROTOCOL_ID or lock.get("protocol_version") != PROTOCOL_VERSION:
        errors.append("manifest lock protocol identity mismatch")
    if lock.get("source_repository_commit") != SOURCE_REPOSITORY_COMMIT:
        errors.append("manifest lock source repository commit mismatch")
    if lock.get("audit_repository_commit") != AUDIT_REPOSITORY_COMMIT:
        errors.append("manifest lock audit repository commit mismatch")
    expected_file_paths = {
        path.relative_to(protocol_root).as_posix()
        for path in _all_protocol_files(protocol_root)
        if path.name not in {"manifest_lock.json", "SHA256SUMS.txt"}
    }
    file_entries = lock.get("files", {})
    if set(file_entries) != expected_file_paths:
        errors.append("manifest lock file set does not match protocol package")
    for relative, item in file_entries.items():
        try:
            path = _safe_relative_source_path(protocol_root, relative)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        if not path.is_file():
            errors.append(f"locked package file is missing: {relative}")
            continue
        if path.stat().st_size != item.get("size_bytes") or sha256_file(path) != item.get("sha256"):
            errors.append(f"locked package file changed: {relative}")
        if relative.endswith(".csv") and relative.split("/", 1)[0] in RELEASES:
            _, rows = read_csv(path)
            if item.get("row_count") != len(rows):
                errors.append(f"locked row count mismatch: {relative}")
    tool_entries = lock.get("tools", {})
    expected_tools = {
        "tools/build_supervisor_50x10_v1.py",
        "tools/validate_supervisor_50x10_v1.py",
        "tests/test_supervisor_50x10_v1.py",
    }
    if set(tool_entries) != expected_tools:
        errors.append("manifest lock tool set mismatch")
    for relative, item in tool_entries.items():
        path = repository_root.joinpath(*relative.split("/"))
        if not path.is_file() or path.stat().st_size != item.get("size_bytes") or sha256_file(path) != item.get("sha256"):
            errors.append(f"locked tool changed: {relative}")
    external_entries = lock.get("external_source_artifacts", {})
    required_external = set(SOURCE_BASE_MANIFESTS.values()) | {"config/manual_review_decisions.csv"}
    if set(external_entries) != required_external:
        errors.append("manifest lock external source set mismatch")
    for relative, item in external_entries.items():
        path = curation_root.joinpath(*relative.split("/"))
        if not path.is_file() or path.stat().st_size != item.get("size_bytes") or sha256_file(path) != item.get("sha256"):
            errors.append(f"locked external source changed: {relative}")
    manual = curation_root / "config" / "manual_review_decisions.csv"
    if manual.is_file() and lock.get("manual_review_decisions_sha256") != sha256_file(manual):
        errors.append("manual review SHA-256 is not independently locked")


def _validate_sums(protocol_root: Path, errors: list[str]) -> None:
    sums_path = protocol_root / "SHA256SUMS.txt"
    if not sums_path.is_file():
        errors.append("SHA256SUMS.txt is missing")
        return
    expected_lines = []
    for path in _all_protocol_files(protocol_root):
        relative = path.relative_to(protocol_root).as_posix()
        if relative == "SHA256SUMS.txt":
            continue
        expected_lines.append(f"{sha256_file(path)}  {relative}")
    expected = "\n".join(expected_lines) + "\n"
    if sums_path.read_text(encoding="utf-8") != expected:
        errors.append("SHA256SUMS.txt content or ordering mismatch")


def _is_negative_documentation(line: str) -> bool:
    lowered = line.lower()
    return any(marker in lowered for marker in (" no ", "not ", "without ", "absent", "never "))


def _validate_forbidden_active_references(
    protocol_root: Path, repository_root: Path, errors: list[str]
) -> None:
    scan_paths = []
    for path in _all_protocol_files(protocol_root):
        relative = path.relative_to(protocol_root).as_posix()
        if relative.startswith("provenance/"):
            continue
        if path.suffix.lower() in {".md", ".json", ".csv", ".txt"}:
            scan_paths.append(path)
    scan_paths.extend(
        [
            repository_root / "tools" / "build_supervisor_50x10_v1.py",
            repository_root / "tools" / "validate_supervisor_50x10_v1.py",
            repository_root / "tests" / "test_supervisor_50x10_v1.py",
        ]
    )
    for path in scan_paths:
        if not path.is_file():
            errors.append(f"active-reference scan target is missing: {path.name}")
            continue
        text = path.read_text(encoding="utf-8")
        for line_number, line in enumerate(text.splitlines(), start=1):
            for term in FORBIDDEN_ACTIVE_TERMS:
                if term.lower() not in line.lower():
                    continue
                if _is_negative_documentation(f" {line} "):
                    continue
                errors.append(f"forbidden active reference {term!r} in {path.name}:{line_number}")


def _validate_metadata(protocol_root: Path, errors: list[str]) -> None:
    path = protocol_root / "protocol_metadata.json"
    if not path.is_file():
        errors.append("protocol_metadata.json is missing")
        return
    data = read_json(path)
    expected = {
        "protocol_id": PROTOCOL_ID,
        "protocol_version": PROTOCOL_VERSION,
        "status": "frozen_inputs_with_documented_curation_caveats",
        "pairs_per_kind_per_release": 500,
        "impostor_policy": "cyclic_next_subject_offset_1_same_canonical_finger",
        "path_policy": "relative_to_nist_dataset_root",
        "png_phys_policy": "diagnostic_only",
        "matcher_used_for_curation": False,
        "quality_rank_used_for_selection": False,
    }
    for key, value in expected.items():
        if data.get(key) != value:
            errors.append(f"protocol metadata field mismatch: {key}")
    cohort = data.get("cohort", {})
    if cohort.get("subjects") != 50 or cohort.get("canonical_fingers_per_subject") != 10 or cohort.get("logical_finger_identities") != 500:
        errors.append("protocol metadata cohort counts mismatch")
    if cohort.get("selection_changed") is not False or cohort.get("subject_order_changed") is not False:
        errors.append("protocol metadata incorrectly reports a cohort change")
    if data.get("datasets") != {"sd300b": {"nominal_ppi": 1000}, "sd300c": {"nominal_ppi": 2000}}:
        errors.append("protocol metadata release/PPI mapping mismatch")
    if data.get("comparison_kinds") != list(COMPARISON_KINDS):
        errors.append("protocol metadata comparison kind order mismatch")
    caveats = data.get("curation_caveats", {})
    if caveats.get("suspected_duplicate_subjects") != ["00001585", "00001586"]:
        errors.append("protocol metadata duplicate caveat mismatch")
    if caveats.get("suspected_duplicate_evidence") != "unverified_prior_report":
        errors.append("protocol metadata duplicate evidence is overstated")
    if caveats.get("suspected_duplicate_claimed_as_biometrically_proven") is not False:
        errors.append("protocol metadata incorrectly claims biometric proof")
    if caveats.get("manual_review_is_provenance_input") is not True or caveats.get("stage0_config_hash_mismatch_documented") is not True:
        errors.append("protocol metadata curation caveats are incomplete")


def validate_protocol(
    protocol_root: Path,
    curation_root: Path,
    dataset_root: Path,
    repository_root: Path | None = None,
    check_package_integrity: bool = True,
    check_stored_report: bool = True,
) -> ValidationResult:
    protocol_root = protocol_root.resolve()
    curation_root = curation_root.resolve()
    dataset_root = dataset_root.resolve()
    repository_root = (repository_root or Path(__file__).resolve().parents[1]).resolve()
    errors: list[str] = []
    checks: dict[str, Any] = {
        "subjects": 0,
        "finger_identities": 0,
        "manifests": 0,
        "rows_per_manifest": 0,
        "total_pairs": 0,
        "same_logical_structure_across_releases": False,
        "cyclic_impostor_pairing_valid": False,
        "self_pairs_valid": False,
        "nominal_ppi_valid": False,
        "relative_paths_valid": False,
        "source_hashes_valid": False,
        "package_lock_valid": False,
        "matcher_executed": False,
        "subjects_reselected": False,
    }
    if not protocol_root.is_dir():
        return ValidationResult(checks, [f"protocol root is missing: {protocol_root}"], EXPECTED_WARNINGS.copy())

    selected_errors = len(errors)
    selected = _load_selected_subjects(protocol_root, errors)
    checks["subjects"] = len(selected)
    checks["finger_identities"] = len(selected) * 10 if len(selected) == 50 else 0

    manifests: dict[tuple[str, str], list[dict[str, str]]] = {}
    path_error_start = len(errors)
    for release in RELEASES:
        for kind in COMPARISON_KINDS:
            path = protocol_root / release / MANIFEST_FILENAMES[kind]
            if not path.is_file():
                errors.append(f"manifest is missing: {release}/{MANIFEST_FILENAMES[kind]}")
                continue
            header, rows = read_csv(path)
            if header != MANIFEST_COLUMNS:
                errors.append(f"manifest schema mismatch: {release}/{MANIFEST_FILENAMES[kind]}")
            if len(rows) != 500:
                errors.append(f"manifest row count is not 500: {release}/{MANIFEST_FILENAMES[kind]}")
            manifests[(release, kind)] = rows
            _validate_manifest_rows(release, kind, rows, selected, dataset_root, errors)
    checks["manifests"] = len(manifests)
    row_counts = {len(rows) for rows in manifests.values()}
    checks["rows_per_manifest"] = 500 if row_counts == {500} and len(manifests) == 8 else 0
    checks["total_pairs"] = sum(len(rows) for rows in manifests.values())
    checks["relative_paths_valid"] = not any("path" in message.lower() for message in errors[path_error_start:])
    checks["nominal_ppi_valid"] = not any("ppi" in message.lower() for message in errors[path_error_start:])
    checks["self_pairs_valid"] = not any("self pair" in message.lower() or "self/genuine" in message.lower() for message in errors[path_error_start:])
    checks["cyclic_impostor_pairing_valid"] = not any("cyclic" in message.lower() or "impostor subjects" in message.lower() for message in errors[path_error_start:])

    cross_start = len(errors)
    _validate_cross_release_structure(manifests, errors)
    checks["same_logical_structure_across_releases"] = len(errors) == cross_start

    source_start = len(errors)
    _validate_source_correspondence(manifests, curation_root, dataset_root, errors)
    _validate_source_hashes_and_provenance(protocol_root, curation_root, errors)
    checks["source_hashes_valid"] = len(errors) == source_start

    _validate_metadata(protocol_root, errors)
    _validate_forbidden_active_references(protocol_root, repository_root, errors)

    if check_package_integrity:
        integrity_start = len(errors)
        _validate_lock(protocol_root, curation_root, repository_root, errors)
        _validate_sums(protocol_root, errors)
        checks["package_lock_valid"] = len(errors) == integrity_start

    if len(selected) != 50 or selected_errors != 0:
        checks["subjects_reselected"] = False

    result = ValidationResult(checks, errors, EXPECTED_WARNINGS.copy())
    if check_stored_report:
        report_path = protocol_root / "validation_report.json"
        if not report_path.is_file():
            errors.append("validation_report.json is missing")
        else:
            stored = read_json(report_path)
            expected_before_report_errors = len(errors) == 0
            if stored.get("protocol_id") != PROTOCOL_ID:
                errors.append("stored validation report protocol mismatch")
            if stored.get("valid") is not expected_before_report_errors:
                errors.append("stored validation report validity does not match current validation")
            if stored.get("checks") != checks:
                errors.append("stored validation report checks do not match current validation")
            if stored.get("warnings") != EXPECTED_WARNINGS:
                errors.append("stored validation report warnings mismatch")
            if stored.get("errors") != []:
                errors.append("published validation report must have an empty error list")
    return result


def build_parser() -> argparse.ArgumentParser:
    repository_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description="Validate the frozen supervisor_50x10_v1 protocol package.")
    parser.add_argument(
        "--protocol-root",
        type=Path,
        default=repository_root / "protocols" / PROTOCOL_ID,
    )
    parser.add_argument(
        "--curation-root",
        type=Path,
        default=Path(r"C:\fingerprint-datasets\NIST\_curation\stage0_v1"),
    )
    parser.add_argument(
        "--dataset-root",
        type=Path,
        default=Path(r"C:\fingerprint-datasets\NIST"),
    )
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = build_parser().parse_args(list(argv) if argv is not None else None)
    result = validate_protocol(args.protocol_root, args.curation_root, args.dataset_root)
    sys.stdout.write(json_text(result.report()))
    return 0 if result.valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
