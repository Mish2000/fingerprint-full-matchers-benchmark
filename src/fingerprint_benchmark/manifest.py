"""Strict reader for a single frozen supervisor protocol manifest."""

from __future__ import annotations

import csv
import json
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .hashing import file_sha256

MANIFEST_COLUMNS = (
    "pair_id", "comparison_kind", "dataset_release", "subject_index_a", "subject_id_a",
    "subject_index_b", "subject_id_b", "canonical_finger", "hand", "finger_name",
    "capture_type_a", "capture_type_b", "nominal_ppi_a", "nominal_ppi_b",
    "relative_path_a", "relative_path_b", "sha256_a", "sha256_b", "source_frgp_a",
    "source_frgp_b", "image_status_a", "image_status_b", "pair_status", "source_pair_id",
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ManifestValidationError(ValueError):
    pass


@dataclass(frozen=True)
class PairRecord:
    pair_id: str
    comparison_kind: str
    dataset_release: str
    subject_index_a: int
    subject_id_a: str
    subject_index_b: int
    subject_id_b: str
    canonical_finger: int
    hand: str
    finger_name: str
    capture_type_a: str
    capture_type_b: str
    nominal_ppi_a: int
    nominal_ppi_b: int
    relative_path_a: str
    relative_path_b: str
    sha256_a: str
    sha256_b: str
    source_frgp_a: str
    source_frgp_b: str
    image_status_a: str
    image_status_b: str
    pair_status: str
    source_pair_id: str
    path_a: Path
    path_b: Path


@dataclass(frozen=True)
class ProtocolManifest:
    protocol_root: Path
    protocol_id: str
    protocol_version: int
    path: Path
    relative_path: str
    sha256: str
    protocol_lock_sha256: str
    records: tuple[PairRecord, ...]


def _protocol_root(manifest_path: Path) -> Path:
    for parent in (manifest_path.parent, *manifest_path.parents):
        if (parent / "manifest_lock.json").is_file() and (parent / "SHA256SUMS.txt").is_file():
            return parent
    raise ManifestValidationError("manifest is not inside a locked protocol package")


def _verify_lock(protocol_root: Path) -> tuple[dict, str]:
    lock_path = protocol_root / "manifest_lock.json"
    sums_path = protocol_root / "SHA256SUMS.txt"
    try:
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ManifestValidationError(f"invalid protocol lock: {exc}") from exc
    expected_sums: dict[str, str] = {}
    sum_order: list[str] = []
    for line in sums_path.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        digest, separator, relative = line.partition("  ")
        if not separator or not _SHA256.fullmatch(digest) or not relative:
            raise ManifestValidationError("invalid SHA256SUMS entry")
        checksum_path = PurePosixPath(relative)
        if checksum_path.is_absolute() or ".." in checksum_path.parts or relative in expected_sums:
            raise ManifestValidationError("unsafe or duplicate SHA256SUMS entry")
        expected_sums[relative] = digest
        sum_order.append(relative)
    expected_paths = set(lock.get("files", {})) | {"manifest_lock.json"}
    if set(expected_sums) != expected_paths or sum_order != sorted(sum_order):
        raise ManifestValidationError("SHA256SUMS is incomplete, excessive, or unsorted")
    for relative, digest in expected_sums.items():
        target = protocol_root / PurePosixPath(relative)
        if not target.is_file() or file_sha256(target) != digest:
            raise ManifestValidationError(f"protocol checksum mismatch: {relative}")
    for relative, metadata in lock.get("files", {}).items():
        target = protocol_root / PurePosixPath(relative)
        if not target.is_file():
            raise ManifestValidationError(f"locked file is missing: {relative}")
        if file_sha256(target) != metadata.get("sha256") or target.stat().st_size != metadata.get("size_bytes"):
            raise ManifestValidationError(f"protocol lock mismatch: {relative}")
    return lock, file_sha256(lock_path)


def _resolve_dataset_path(dataset_root: Path, relative: str, release: str) -> Path:
    posix = PurePosixPath(relative)
    if posix.is_absolute() or not posix.parts or ".." in posix.parts or "." in posix.parts:
        raise ManifestValidationError(f"unsafe relative image path: {relative}")
    if ":" in posix.parts[0] or posix.parts[0].lower() != release.lower():
        raise ManifestValidationError(f"image path does not match release: {relative}")
    root = dataset_root.resolve()
    resolved = (root / Path(*posix.parts)).resolve()
    if resolved != root and root not in resolved.parents:
        raise ManifestValidationError(f"image path escapes dataset root: {relative}")
    if not resolved.is_file():
        raise ManifestValidationError(f"image file does not exist: {relative}")
    return resolved


def read_protocol_manifest(manifest_path: Path, dataset_root: Path) -> ProtocolManifest:
    manifest_path = Path(manifest_path).resolve()
    dataset_root = Path(dataset_root)
    protocol_root = _protocol_root(manifest_path)
    lock, lock_hash = _verify_lock(protocol_root)
    try:
        relative = manifest_path.relative_to(protocol_root).as_posix()
    except ValueError as exc:
        raise ManifestValidationError("manifest escapes protocol root") from exc
    locked = lock.get("files", {}).get(relative)
    if not locked:
        raise ManifestValidationError(f"manifest is not present in protocol lock: {relative}")
    actual_hash = file_sha256(manifest_path)
    if actual_hash != locked.get("sha256") or manifest_path.stat().st_size != locked.get("size_bytes"):
        raise ManifestValidationError("manifest hash or size differs from protocol lock")
    metadata_path = protocol_root / "protocol_metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    allowed_kinds = set(metadata.get("comparison_kinds", ()))
    datasets = metadata.get("datasets", {})
    records: list[PairRecord] = []
    seen: set[str] = set()
    with manifest_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if tuple(reader.fieldnames or ()) != MANIFEST_COLUMNS:
            raise ManifestValidationError("manifest header does not exactly match the 24-column schema")
        for row_index, row in enumerate(reader, start=1):
            try:
                kind = row["comparison_kind"]
                release = row["dataset_release"]
                pair_id = row["pair_id"]
                if kind not in allowed_kinds:
                    raise ManifestValidationError(f"row {row_index}: unknown comparison kind")
                if release not in datasets:
                    raise ManifestValidationError(f"row {row_index}: unknown dataset release")
                if pair_id in seen:
                    raise ManifestValidationError(f"row {row_index}: duplicate pair ID")
                seen.add(pair_id)
                ppi_a, ppi_b = int(row["nominal_ppi_a"]), int(row["nominal_ppi_b"])
                expected_ppi = int(datasets[release]["nominal_ppi"])
                if ppi_a not in (1000, 2000) or ppi_b not in (1000, 2000) or ppi_a != expected_ppi or ppi_b != expected_ppi:
                    raise ManifestValidationError(f"row {row_index}: invalid nominal PPI")
                if not _SHA256.fullmatch(row["sha256_a"]) or not _SHA256.fullmatch(row["sha256_b"]):
                    raise ManifestValidationError(f"row {row_index}: invalid lowercase image SHA-256")
                path_a = _resolve_dataset_path(dataset_root, row["relative_path_a"], release)
                path_b = _resolve_dataset_path(dataset_root, row["relative_path_b"], release)
                records.append(PairRecord(
                    pair_id=pair_id, comparison_kind=kind, dataset_release=release,
                    subject_index_a=int(row["subject_index_a"]), subject_id_a=row["subject_id_a"],
                    subject_index_b=int(row["subject_index_b"]), subject_id_b=row["subject_id_b"],
                    canonical_finger=int(row["canonical_finger"]), hand=row["hand"], finger_name=row["finger_name"],
                    capture_type_a=row["capture_type_a"], capture_type_b=row["capture_type_b"],
                    nominal_ppi_a=ppi_a, nominal_ppi_b=ppi_b,
                    relative_path_a=row["relative_path_a"], relative_path_b=row["relative_path_b"],
                    sha256_a=row["sha256_a"], sha256_b=row["sha256_b"],
                    source_frgp_a=row["source_frgp_a"], source_frgp_b=row["source_frgp_b"],
                    image_status_a=row["image_status_a"], image_status_b=row["image_status_b"],
                    pair_status=row["pair_status"], source_pair_id=row["source_pair_id"],
                    path_a=path_a, path_b=path_b,
                ))
            except (KeyError, TypeError, ValueError) as exc:
                if isinstance(exc, ManifestValidationError):
                    raise
                raise ManifestValidationError(f"row {row_index}: malformed field: {exc}") from exc
    if len(records) != locked.get("row_count"):
        raise ManifestValidationError("manifest row count differs from protocol lock")
    return ProtocolManifest(
        protocol_root=protocol_root, protocol_id=str(lock["protocol_id"]),
        protocol_version=int(lock["protocol_version"]), path=manifest_path,
        relative_path=relative, sha256=actual_hash, protocol_lock_sha256=lock_hash,
        records=tuple(records),
    )
