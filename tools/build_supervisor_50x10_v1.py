"""Deterministically build the supervisor_50x10_v1 protocol package."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import shutil
import sys
from pathlib import Path
from typing import Any, Iterable

from validate_supervisor_50x10_v1 import (
    AUDIT_REPOSITORY_COMMIT,
    COMPARISON_KINDS,
    CURRENT_CONFIG_SHA256,
    EXPECTED_WARNINGS,
    LOCKED_CONFIG_SHA256,
    MANIFEST_COLUMNS,
    MANIFEST_FILENAMES,
    PROTOCOL_ID,
    PROTOCOL_VERSION,
    PROVENANCE_COPIES,
    RELEASES,
    SOURCE_BASE_MANIFESTS,
    SOURCE_REPOSITORY_COMMIT,
    json_text,
    read_csv,
    read_json,
    sha256_file,
    validate_protocol,
)


SOURCE_ARTIFACT_ROLES = {
    "config/manual_review_decisions.csv": "selection_provenance",
    "config/stage0_config.yaml": "historical_configuration_not_protocol_input",
    "outputs/MANIFEST_SHA256SUMS.txt": "historical_stage0_checksum_index",
    "outputs/base_500_genuine_sd300b.csv": "frozen_genuine_source_manifest",
    "outputs/base_500_genuine_sd300c.csv": "frozen_genuine_source_manifest",
    "outputs/base_500_impostor_sd300b.csv": "frozen_impostor_source_manifest",
    "outputs/base_500_impostor_sd300c.csv": "frozen_impostor_source_manifest",
    "outputs/duplicate_identity_review.csv": "conservative_duplicate_policy_provenance",
    "outputs/duplicate_identity_summary.json": "conservative_duplicate_policy_summary",
    "outputs/manifest_lock.json": "historical_stage0_lock",
    "outputs/raw_data_verification.json": "raw_data_verification_provenance",
    "outputs/selected_50_subjects.csv": "frozen_ordered_cohort",
    "outputs/selected_50_subjects.txt": "frozen_ordered_cohort_text",
    "outputs/selection_provenance.json": "selection_provenance",
}

README_TEXT = """# supervisor_50x10_v1

This package freezes the supervisor-approved 50-subject, 10-canonical-finger evaluation protocol derived from the historical `stage0_v1` curation outputs. It is a data/protocol artifact, not a benchmark implementation.

## Frozen cohort and comparisons

- The exact 50 selected subjects and their existing `subject_index` order are copied byte-for-byte from Stage 0. No subject was reselected, replaced, added, removed, or reordered.
- Every release contains 500 logical finger identities: 50 subjects times 10 canonical fingers.
- Each release contains four 500-row manifests: `plain_self`, `roll_self`, `plain_roll_genuine`, and `plain_roll_next_subject`.
- Self manifests are deterministic projections of the frozen genuine manifests. They do not perform discovery or selection.
- The next-subject comparison uses cyclic offset 1 in frozen subject order: subject 1 to 2 through subject 50 to 1, always at the same canonical finger.

## Dataset and PPI policy

- `sd300b` uses nominal PPI 1000.
- `sd300c` uses nominal PPI 2000.
- PNG metadata is diagnostic only and is never used as the protocol PPI source.
- Manifest paths are normalized with `/` and are relative to the NIST dataset root.
- Existing image hashes and statuses come from the frozen base manifests; images are not decoded or rehashed.
- Challenge records are retained without filtering or status improvement.

## Curation provenance and caveats

- No matcher was executed and no biometric result influenced this protocol freeze.
- No SourceAFIS code, adapter, sidecar, execution, or run instruction is part of this package.
- `manual_review_decisions.csv` is copied byte-for-byte, hashed, and treated as mandatory selection provenance. All 11 recorded decisions retain their `challenge` classification.
- Subjects `00001585` and `00001586` were conservatively blocked by Stage 0 based on an unverified prior report. They are not among the frozen 50, no new biometric evidence was produced, and the suspicion is not claimed as biometrically proven.
- The historical locked Stage 0 config hash and current config hash differ. Both hashes are recorded, but the old Stage 0 config is not an authority or runtime input for this package.
- `_analysis` remains external corroborating evidence and is not a protocol input.

## Read-only validation

From the repository root, run only the validator:

```text
python tools/validate_supervisor_50x10_v1.py --protocol-root protocols/supervisor_50x10_v1 --curation-root C:\\fingerprint-datasets\\NIST\\_curation\\stage0_v1 --dataset-root C:\\fingerprint-datasets\\NIST
```

The validator reads manifests, provenance, locks, and referenced file existence only. It performs no image decoding, image processing, matching, sampling, scoring, or calibration.
"""


def write_json(path: Path, value: Any) -> None:
    path.write_text(json_text(value), encoding="utf-8", newline="")


def write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=MANIFEST_COLUMNS, lineterminator="\n", extrasaction="raise")
        writer.writeheader()
        writer.writerows(rows)


def _source_path(root: Path, relative: str) -> Path:
    if not relative or "\\" in relative or ":" in relative or relative.startswith("/"):
        raise ValueError(f"unsafe curation-relative path: {relative!r}")
    parts = relative.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise ValueError(f"unsafe curation-relative path: {relative!r}")
    resolved_root = root.resolve()
    resolved = resolved_root.joinpath(*parts).resolve()
    resolved.relative_to(resolved_root)
    return resolved


def _image_relative(source_path: str, dataset_root: Path, release: str) -> str:
    root = dataset_root.resolve()
    path = Path(source_path).resolve()
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"image path escapes dataset root: {source_path}") from exc
    normalized = relative.as_posix()
    if ".." in relative.parts or normalized.split("/", 1)[0].lower() != release:
        raise ValueError(f"image path is not under {release}: {source_path}")
    if not path.is_file():
        raise ValueError(f"referenced image does not exist: {source_path}")
    return normalized


def _validate_old_freeze(curation_root: Path) -> dict[str, Any]:
    outputs = curation_root / "outputs"
    old_lock_path = outputs / "manifest_lock.json"
    old_sums_path = outputs / "MANIFEST_SHA256SUMS.txt"
    if not old_lock_path.is_file() or not old_sums_path.is_file():
        raise ValueError("historical Stage0 lock or checksum index is missing")
    old_lock = read_json(old_lock_path)
    if old_lock.get("config_sha256") != LOCKED_CONFIG_SHA256:
        raise ValueError("historical locked config hash differs from the approved audit value")
    config_path = curation_root / "config" / "stage0_config.yaml"
    if not config_path.is_file() or sha256_file(config_path) != CURRENT_CONFIG_SHA256:
        raise ValueError("current Stage0 config hash differs from the approved audit value")

    for name, item in old_lock.get("artifact_sha256", {}).items():
        path = outputs / name
        if not path.is_file():
            raise ValueError(f"historical locked artifact is missing: {name}")
        if path.stat().st_size != item.get("bytes") or sha256_file(path) != item.get("sha256"):
            raise ValueError(f"historical locked artifact changed: {name}")
    for name, expected_hash in old_lock.get("script_sha256", {}).items():
        path = curation_root / "scripts" / name
        if not path.is_file() or sha256_file(path) != expected_hash:
            raise ValueError(f"historical locked script changed: {name}")

    checksum_lines = old_sums_path.read_text(encoding="utf-8").splitlines()
    for line in checksum_lines:
        parts = line.split("  ", 1)
        if len(parts) != 2 or len(parts[0]) != 64:
            raise ValueError(f"invalid historical checksum line: {line!r}")
        path = outputs / parts[1]
        if not path.is_file() or sha256_file(path) != parts[0]:
            raise ValueError(f"historical checksum mismatch: {parts[1]}")

    required_paths = set(SOURCE_ARTIFACT_ROLES)
    for relative in sorted(required_paths):
        if not _source_path(curation_root, relative).is_file():
            raise ValueError(f"required source artifact is missing: {relative}")

    for (release, kind), relative in SOURCE_BASE_MANIFESTS.items():
        path = _source_path(curation_root, relative)
        name = path.name
        expected_hash = old_lock.get("manifest_sha256", {}).get(name)
        expected_item = old_lock.get("artifact_sha256", {}).get(name, {})
        _, rows = read_csv(path)
        if len(rows) != 500:
            raise ValueError(f"{name} must contain exactly 500 rows")
        if sha256_file(path) != expected_hash or path.stat().st_size != expected_item.get("bytes"):
            raise ValueError(f"{name} differs from the historical lock")

    _, selected_rows = read_csv(outputs / "selected_50_subjects.csv")
    selected_ids = [row["subject_id"] for row in selected_rows]
    selected_text = [
        line.strip()
        for line in (outputs / "selected_50_subjects.txt").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if len(selected_ids) != 50 or len(set(selected_ids)) != 50 or selected_ids != selected_text:
        raise ValueError("selected-subject files do not contain the same 50-subject order")
    if [row["subject_index"] for row in selected_rows] != [str(index) for index in range(1, 51)]:
        raise ValueError("selected-subject indices are not exactly 1..50")
    if old_lock.get("selected_subject_ids") != selected_ids:
        raise ValueError("selected-subject order differs from the historical lock")
    if "00001585" in selected_ids or "00001586" in selected_ids:
        raise ValueError("blocked duplicate-suspicion subjects appear in the frozen cohort")

    _, manual_rows = read_csv(curation_root / "config" / "manual_review_decisions.csv")
    if len(manual_rows) != 11 or {row.get("decision") for row in manual_rows} != {"challenge"}:
        raise ValueError("manual review decisions are not the 11 retained challenge records")
    _, duplicate_rows = read_csv(outputs / "duplicate_identity_review.csv")
    if len(duplicate_rows) != 1:
        raise ValueError("duplicate identity review must contain exactly one suspected relation")
    duplicate = duplicate_rows[0]
    if (
        duplicate.get("subject_id_a") != "00001585"
        or duplicate.get("subject_id_b") != "00001586"
        or duplicate.get("evidence_type") != "prior_report"
        or duplicate.get("status") != "suspected"
        or duplicate.get("selection_blocked") != "true"
    ):
        raise ValueError("duplicate identity caveat differs from the approved curation record")
    return old_lock


def _validate_source_manifest_order(
    rows: list[dict[str, str]],
    selected: list[str],
    release: str,
    kind: str,
) -> None:
    expected_release = release.upper()
    expected_ppi = str(RELEASES[release])
    for position, row in enumerate(rows):
        subject_index = position // 10 + 1
        finger = position % 10 + 1
        if kind == "plain_roll_genuine":
            actual_a = row["subject_id"]
            actual_b = row["subject_id"]
            index_a = row["subject_index"]
            index_b = row["subject_index"]
        else:
            actual_a = row["plain_subject_id"]
            actual_b = row["roll_subject_id"]
            index_a = row["plain_subject_index"]
            index_b = row["roll_subject_index"]
            expected_b_index = subject_index % 50 + 1
            if row.get("cyclic_offset") != "1" or index_b != str(expected_b_index) or actual_b != selected[expected_b_index - 1]:
                raise ValueError(f"{release} impostor manifest violates cyclic offset 1 at row {position + 2}")
        if (
            index_a != str(subject_index)
            or actual_a != selected[subject_index - 1]
            or row["canonical_finger"] != str(finger)
            or row["dataset_release"] != expected_release
            or row["nominal_ppi"] != expected_ppi
        ):
            raise ValueError(f"{release} {kind} source order/identity/PPI mismatch at row {position + 2}")
        if kind == "plain_roll_genuine" and (actual_a != actual_b or index_a != index_b):
            raise ValueError(f"{release} genuine identity mismatch at row {position + 2}")
        if kind == "plain_roll_next_subject" and actual_a == actual_b:
            raise ValueError(f"{release} impostor identity mismatch at row {position + 2}")


def _logical_source_projection(row: dict[str, str], kind: str) -> tuple[str, ...]:
    if kind == "plain_roll_genuine":
        fields = (
            "pair_id", "subject_index", "subject_id", "canonical_finger", "hand", "finger_name",
            "plain_source_frgp", "roll_source_frgp", "plain_status", "roll_status", "pair_status",
        )
    else:
        fields = (
            "pair_id", "plain_subject_index", "plain_subject_id", "roll_subject_index", "roll_subject_id",
            "cyclic_offset", "canonical_finger", "hand", "finger_name", "plain_source_frgp",
            "roll_source_frgp", "plain_status", "roll_status", "pair_status",
        )
    return tuple(row[field] for field in fields)


def _common_output_fields(
    source: dict[str, str],
    kind: str,
    release: str,
    dataset_root: Path,
) -> dict[str, str]:
    if kind == "plain_roll_next_subject":
        subject_index_a = source["plain_subject_index"]
        subject_id_a = source["plain_subject_id"]
        subject_index_b = source["roll_subject_index"]
        subject_id_b = source["roll_subject_id"]
    else:
        subject_index_a = source["subject_index"]
        subject_id_a = source["subject_id"]
        subject_index_b = source["subject_index"]
        subject_id_b = source["subject_id"]
    return {
        "comparison_kind": kind,
        "dataset_release": release,
        "subject_index_a": subject_index_a,
        "subject_id_a": subject_id_a,
        "subject_index_b": subject_index_b,
        "subject_id_b": subject_id_b,
        "canonical_finger": source["canonical_finger"],
        "hand": source["hand"],
        "finger_name": source["finger_name"],
        "nominal_ppi_a": str(RELEASES[release]),
        "nominal_ppi_b": str(RELEASES[release]),
        "pair_status": source["pair_status"],
        "source_pair_id": source["pair_id"],
    }


def _genuine_row(source: dict[str, str], release: str, dataset_root: Path) -> dict[str, str]:
    row = _common_output_fields(source, "plain_roll_genuine", release, dataset_root)
    finger = int(source["canonical_finger"])
    row.update(
        {
            "pair_id": f"GEN_{source['subject_id']}_F{finger:02d}",
            "capture_type_a": "PLAIN",
            "capture_type_b": "ROLL",
            "relative_path_a": _image_relative(source["plain_path"], dataset_root, release),
            "relative_path_b": _image_relative(source["roll_path"], dataset_root, release),
            "sha256_a": source["plain_sha256"],
            "sha256_b": source["roll_sha256"],
            "source_frgp_a": source["plain_source_frgp"],
            "source_frgp_b": source["roll_source_frgp"],
            "image_status_a": source["plain_status"],
            "image_status_b": source["roll_status"],
        }
    )
    return row


def _impostor_row(source: dict[str, str], release: str, dataset_root: Path) -> dict[str, str]:
    row = _common_output_fields(source, "plain_roll_next_subject", release, dataset_root)
    finger = int(source["canonical_finger"])
    row.update(
        {
            "pair_id": f"IMP_{source['plain_subject_id']}_{source['roll_subject_id']}_F{finger:02d}",
            "capture_type_a": "PLAIN",
            "capture_type_b": "ROLL",
            "relative_path_a": _image_relative(source["plain_path"], dataset_root, release),
            "relative_path_b": _image_relative(source["roll_path"], dataset_root, release),
            "sha256_a": source["plain_sha256"],
            "sha256_b": source["roll_sha256"],
            "source_frgp_a": source["plain_source_frgp"],
            "source_frgp_b": source["roll_source_frgp"],
            "image_status_a": source["plain_status"],
            "image_status_b": source["roll_status"],
        }
    )
    return row


def _self_row(
    source: dict[str, str],
    release: str,
    capture: str,
    dataset_root: Path,
) -> dict[str, str]:
    kind = "plain_self" if capture == "plain" else "roll_self"
    row = _common_output_fields(source, kind, release, dataset_root)
    finger = int(source["canonical_finger"])
    prefix = "PSELF" if capture == "plain" else "RSELF"
    capture_name = capture.upper()
    relative = _image_relative(source[f"{capture}_path"], dataset_root, release)
    digest = source[f"{capture}_sha256"]
    frgp = source[f"{capture}_source_frgp"]
    status = source[f"{capture}_status"]
    row.update(
        {
            "pair_id": f"{prefix}_{source['subject_id']}_F{finger:02d}",
            "capture_type_a": capture_name,
            "capture_type_b": capture_name,
            "relative_path_a": relative,
            "relative_path_b": relative,
            "sha256_a": digest,
            "sha256_b": digest,
            "source_frgp_a": frgp,
            "source_frgp_b": frgp,
            "image_status_a": status,
            "image_status_b": status,
        }
    )
    return row


def _build_manifests(
    candidate: Path,
    curation_root: Path,
    dataset_root: Path,
    selected: list[str],
) -> None:
    source_rows: dict[tuple[str, str], list[dict[str, str]]] = {}
    for key, relative in SOURCE_BASE_MANIFESTS.items():
        _, rows = read_csv(_source_path(curation_root, relative))
        _validate_source_manifest_order(rows, selected, key[0], key[1])
        source_rows[key] = rows
    for kind in ("plain_roll_genuine", "plain_roll_next_subject"):
        left = [_logical_source_projection(row, kind) for row in source_rows[("sd300b", kind)]]
        right = [_logical_source_projection(row, kind) for row in source_rows[("sd300c", kind)]]
        if left != right:
            raise ValueError(f"frozen {kind} logical structure differs between releases")

    for release in RELEASES:
        release_dir = candidate / release
        release_dir.mkdir(parents=True, exist_ok=False)
        genuine_source = source_rows[(release, "plain_roll_genuine")]
        impostor_source = source_rows[(release, "plain_roll_next_subject")]
        outputs = {
            "plain_self": [_self_row(row, release, "plain", dataset_root) for row in genuine_source],
            "roll_self": [_self_row(row, release, "roll", dataset_root) for row in genuine_source],
            "plain_roll_genuine": [_genuine_row(row, release, dataset_root) for row in genuine_source],
            "plain_roll_next_subject": [_impostor_row(row, release, dataset_root) for row in impostor_source],
        }
        for kind in COMPARISON_KINDS:
            write_csv(release_dir / MANIFEST_FILENAMES[kind], outputs[kind])


def _copy_provenance(candidate: Path, curation_root: Path) -> None:
    provenance = candidate / "provenance"
    provenance.mkdir(parents=True, exist_ok=False)
    for destination, source_relative in PROVENANCE_COPIES.items():
        source = _source_path(curation_root, source_relative)
        target = candidate.joinpath(*destination.split("/"))
        shutil.copyfile(source, target)
        if target.read_bytes() != source.read_bytes():
            raise ValueError(f"provenance copy failed byte-for-byte verification: {destination}")


def _write_source_artifact_hashes(candidate: Path, curation_root: Path) -> None:
    artifacts = []
    for relative in sorted(SOURCE_ARTIFACT_ROLES):
        path = _source_path(curation_root, relative)
        artifacts.append(
            {
                "path": relative,
                "role": SOURCE_ARTIFACT_ROLES[relative],
                "sha256": sha256_file(path),
                "size_bytes": path.stat().st_size,
            }
        )
    value = {
        "artifacts": artifacts,
        "audit_repository_commit": AUDIT_REPOSITORY_COMMIT,
        "source_curation_root": str(curation_root.resolve()),
        "source_repository_commit": SOURCE_REPOSITORY_COMMIT,
        "stage0_config_used_as_protocol_input": False,
        "stage0_current_config_sha256": CURRENT_CONFIG_SHA256,
        "stage0_locked_config_sha256": LOCKED_CONFIG_SHA256,
    }
    write_json(candidate / "provenance" / "source_artifact_hashes.json", value)


def _write_metadata(candidate: Path) -> None:
    value = {
        "cohort": {
            "canonical_fingers_per_subject": 10,
            "logical_finger_identities": 500,
            "selection_changed": False,
            "subject_order_changed": False,
            "subjects": 50,
        },
        "comparison_kinds": list(COMPARISON_KINDS),
        "curation_caveats": {
            "manual_review_is_provenance_input": True,
            "stage0_config_hash_mismatch_documented": True,
            "suspected_duplicate_claimed_as_biometrically_proven": False,
            "suspected_duplicate_evidence": "unverified_prior_report",
            "suspected_duplicate_subjects": ["00001585", "00001586"],
        },
        "datasets": {
            "sd300b": {"nominal_ppi": 1000},
            "sd300c": {"nominal_ppi": 2000},
        },
        "impostor_policy": "cyclic_next_subject_offset_1_same_canonical_finger",
        "matcher_used_for_curation": False,
        "pairs_per_kind_per_release": 500,
        "path_policy": "relative_to_nist_dataset_root",
        "png_phys_policy": "diagnostic_only",
        "protocol_id": PROTOCOL_ID,
        "protocol_version": PROTOCOL_VERSION,
        "quality_rank_used_for_selection": False,
        "status": "frozen_inputs_with_documented_curation_caveats",
    }
    write_json(candidate / "protocol_metadata.json", value)


def _all_files(root: Path) -> list[Path]:
    return sorted(
        (path for path in root.rglob("*") if path.is_file()),
        key=lambda path: path.relative_to(root).as_posix(),
    )


def _file_record(path: Path, row_count: int | None = None) -> dict[str, Any]:
    value: dict[str, Any] = {
        "sha256": sha256_file(path),
        "size_bytes": path.stat().st_size,
    }
    if row_count is not None:
        value["row_count"] = row_count
    return value


def _write_lock_and_sums(
    candidate: Path,
    curation_root: Path,
    repository_root: Path,
) -> None:
    files: dict[str, Any] = {}
    for path in _all_files(candidate):
        relative = path.relative_to(candidate).as_posix()
        row_count = None
        if relative.endswith(".csv") and relative.split("/", 1)[0] in RELEASES:
            _, rows = read_csv(path)
            row_count = len(rows)
        files[relative] = _file_record(path, row_count)

    tool_paths = (
        "tools/build_supervisor_50x10_v1.py",
        "tools/validate_supervisor_50x10_v1.py",
        "tests/test_supervisor_50x10_v1.py",
    )
    tools: dict[str, Any] = {}
    for relative in tool_paths:
        path = repository_root.joinpath(*relative.split("/"))
        if not path.is_file():
            raise ValueError(f"required protocol tool is missing: {relative}")
        tools[relative] = _file_record(path)

    external_source_artifacts: dict[str, Any] = {}
    for relative in sorted(set(SOURCE_BASE_MANIFESTS.values()) | {"config/manual_review_decisions.csv"}):
        path = _source_path(curation_root, relative)
        external_source_artifacts[relative] = _file_record(path)

    manual_path = curation_root / "config" / "manual_review_decisions.csv"
    lock = {
        "audit_repository_commit": AUDIT_REPOSITORY_COMMIT,
        "external_source_artifacts": external_source_artifacts,
        "files": files,
        "manual_review_decisions_sha256": sha256_file(manual_path),
        "protocol_id": PROTOCOL_ID,
        "protocol_version": PROTOCOL_VERSION,
        "source_repository_commit": SOURCE_REPOSITORY_COMMIT,
        "stage0_config_used_as_protocol_input": False,
        "stage0_current_config_sha256": CURRENT_CONFIG_SHA256,
        "stage0_locked_config_sha256": LOCKED_CONFIG_SHA256,
        "tools": tools,
    }
    write_json(candidate / "manifest_lock.json", lock)

    lines = []
    for path in _all_files(candidate):
        relative = path.relative_to(candidate).as_posix()
        if relative == "SHA256SUMS.txt":
            continue
        lines.append(f"{sha256_file(path)}  {relative}")
    (candidate / "SHA256SUMS.txt").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="")


def _build_candidate(
    candidate: Path,
    curation_root: Path,
    dataset_root: Path,
    repository_root: Path,
) -> None:
    _validate_old_freeze(curation_root)
    candidate.mkdir(parents=True, exist_ok=False)
    _copy_provenance(candidate, curation_root)
    _write_source_artifact_hashes(candidate, curation_root)
    _, selected_rows = read_csv(curation_root / "outputs" / "selected_50_subjects.csv")
    selected = [row["subject_id"] for row in selected_rows]
    _build_manifests(candidate, curation_root, dataset_root, selected)
    _write_metadata(candidate)
    (candidate / "README.md").write_text(README_TEXT, encoding="utf-8", newline="")

    preliminary = validate_protocol(
        candidate,
        curation_root,
        dataset_root,
        repository_root=repository_root,
        check_package_integrity=False,
        check_stored_report=False,
    )
    if preliminary.errors:
        raise ValueError("candidate structure validation failed: " + "; ".join(preliminary.errors))
    preliminary.checks["package_lock_valid"] = True
    report = {
        "protocol_id": PROTOCOL_ID,
        "valid": True,
        "checks": preliminary.checks,
        "errors": [],
        "warnings": EXPECTED_WARNINGS,
    }
    write_json(candidate / "validation_report.json", report)
    _write_lock_and_sums(candidate, curation_root, repository_root)
    final = validate_protocol(candidate, curation_root, dataset_root, repository_root=repository_root)
    if not final.valid:
        raise ValueError("candidate final validation failed: " + "; ".join(final.errors))


def build_package(
    curation_root: Path,
    dataset_root: Path,
    output_root: Path,
    replace: bool = False,
    repository_root: Path | None = None,
) -> Path:
    curation_root = curation_root.resolve()
    dataset_root = dataset_root.resolve()
    output_root = output_root.resolve()
    repository_root = (repository_root or Path(__file__).resolve().parents[1]).resolve()
    if output_root.exists() and not replace:
        raise FileExistsError(f"output package already exists; use --replace: {output_root}")
    output_root.parent.mkdir(parents=True, exist_ok=True)
    candidate = output_root.parent / f".{output_root.name}.candidate"
    backup = output_root.parent / f".{output_root.name}.backup"
    if candidate.exists():
        shutil.rmtree(candidate)
    if backup.exists():
        shutil.rmtree(backup)
    try:
        _build_candidate(candidate, curation_root, dataset_root, repository_root)
        if output_root.exists():
            output_root.replace(backup)
            try:
                candidate.replace(output_root)
            except BaseException:
                if output_root.exists():
                    shutil.rmtree(output_root)
                backup.replace(output_root)
                raise
            shutil.rmtree(backup)
        else:
            candidate.replace(output_root)
    except BaseException:
        if candidate.exists():
            shutil.rmtree(candidate)
        raise
    return output_root


def build_parser() -> argparse.ArgumentParser:
    repository_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description="Build the frozen supervisor_50x10_v1 protocol package.")
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
    parser.add_argument(
        "--output-root",
        type=Path,
        default=repository_root / "protocols" / PROTOCOL_ID,
    )
    parser.add_argument("--replace", action="store_true")
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = build_parser().parse_args(list(argv) if argv is not None else None)
    try:
        output = build_package(args.curation_root, args.dataset_root, args.output_root, args.replace)
    except (FileExistsError, OSError, ValueError) as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 1
    sys.stdout.write(f"Protocol package built and validated: {output}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
