"""Recompute the canonical NBIS 5.0.0 source-tree identity directly from ZIP.

The tool uses only the Python standard library.  It does not download,
extract, build, or execute anything.  By default it only prints a compact
summary; output files are written solely when explicitly requested.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


ALGORITHM_ID = "nbis_source_tree_identity_v2"
TOP_LEVEL_DIRECTORY = "Rel_5.0.0"
TOP_LEVEL_PREFIX = TOP_LEVEL_DIRECTORY + "/"
OFFICIAL_ARCHIVE_SHA256 = "0adf8ab0f6b0e4208de50ca00ba21d3d77112ecd66288757ddfed21f6bee92c3"
OFFICIAL_ARCHIVE_SIZE = 52_595_795
OFFICIAL_FILE_COUNT = 3_879
CANONICAL_TREE_SHA256 = "00ae5eff70693fa5647e3ff57232eff7abd623e4786c110a3286ac8614ac7f3e"
ARCHIVE_LAYOUT_TREE_SHA256 = "1338ea21b50a084ec4d724449af226b129aedaf70a184109590f7cb64251d2d8"
MINDTCT_TREE_SHA256 = "6271302a7a049102d7cc0fa078d2d393cbd3647d6cc59c037bf71d915e51ed2f"
BOZORTH3_TREE_SHA256 = "ae2ac6cefee221a62716d941498d64e06e39eb60716936243459756cb5cb1ef8"
NON_REPRODUCIBLE_V1_HASH = "058aeb4638644f998109371c821acb75649d39ee411429fef268f6e4c1ae5bc9"
_DRIVE_PREFIX = re.compile(r"^[A-Za-z]:")


class IdentityError(ValueError):
    """Raised when an archive violates the canonical identity contract."""


@dataclass(frozen=True)
class FileRecord:
    sha256: str
    byte_size: int
    relative_path: str


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode("utf-8")


def manifest_bytes(records: Iterable[FileRecord], *, include_top_level: bool = False) -> bytes:
    """Create the specified UTF-8/LF payload with ordinal path sorting."""

    ordered = sorted(records, key=lambda record: record.relative_path)
    lines = []
    for record in ordered:
        path = TOP_LEVEL_PREFIX + record.relative_path if include_top_level else record.relative_path
        lines.append(f"{record.sha256}  {record.byte_size}  {path}\n")
    return "".join(lines).encode("utf-8")


def tree_sha256(records: Iterable[FileRecord], *, include_top_level: bool = False) -> str:
    return hashlib.sha256(manifest_bytes(records, include_top_level=include_top_level)).hexdigest()


def _safe_relative_path(archive_path: str) -> str:
    if "\\" in archive_path:
        raise IdentityError(f"backslash path separator is prohibited: {archive_path!r}")
    if archive_path.startswith("/") or _DRIVE_PREFIX.match(archive_path):
        raise IdentityError(f"absolute or drive-prefixed archive path is prohibited: {archive_path!r}")
    if not archive_path.startswith(TOP_LEVEL_PREFIX):
        raise IdentityError(f"file entry is outside {TOP_LEVEL_PREFIX}: {archive_path!r}")
    relative = archive_path[len(TOP_LEVEL_PREFIX):]
    if not relative:
        raise IdentityError("empty path after top-level prefix removal")
    if relative.startswith("/") or _DRIVE_PREFIX.match(relative):
        raise IdentityError(f"absolute or drive-prefixed relative path is prohibited: {relative!r}")
    raw_parts = relative.split("/")
    if ".." in raw_parts:
        raise IdentityError(f"path traversal is prohibited: {archive_path!r}")
    normalized = PurePosixPath(relative).as_posix()
    if normalized in {"", "."} or normalized.startswith("../"):
        raise IdentityError(f"invalid normalized relative path: {archive_path!r}")
    return normalized


def _archive_roots(infos: Iterable[zipfile.ZipInfo]) -> set[str]:
    roots: set[str] = set()
    for info in infos:
        name = info.filename
        if "\\" in name:
            raise IdentityError(f"backslash path separator is prohibited: {name!r}")
        if name.startswith("/") or _DRIVE_PREFIX.match(name):
            raise IdentityError(f"absolute or drive-prefixed archive path is prohibited: {name!r}")
        root = name.split("/", 1)[0]
        if root:
            roots.add(root)
    return roots


def _entry_digest(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> tuple[str, int]:
    digest = hashlib.sha256()
    byte_size = 0
    with archive.open(info, "r") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
            byte_size += len(chunk)
    if byte_size != info.file_size:
        raise IdentityError(f"uncompressed size mismatch: {info.filename!r}")
    return digest.hexdigest(), byte_size


def _subtree_identity(records: Iterable[FileRecord], component: str) -> dict[str, Any]:
    prefix = component + "/"
    selected = [
        FileRecord(record.sha256, record.byte_size, record.relative_path[len(prefix):])
        for record in records
        if record.relative_path.startswith(prefix)
    ]
    return {"file_count": len(selected), "sha256": tree_sha256(selected)}


def compute_identity(
    archive_path: Path, expected_archive_sha256: str | None = None
) -> tuple[dict[str, Any], bytes]:
    """Return a compact identity summary and the full canonical manifest."""

    archive_path = Path(archive_path)
    archive_hash = file_sha256(archive_path)
    if expected_archive_sha256 is not None and archive_hash != expected_archive_sha256.casefold():
        raise IdentityError(
            f"archive SHA-256 mismatch: expected {expected_archive_sha256.casefold()}, got {archive_hash}"
        )

    records: list[FileRecord] = []
    normalized_paths: set[str] = set()
    with zipfile.ZipFile(archive_path, "r") as archive:
        infos = archive.infolist()
        roots = _archive_roots(infos)
        if roots != {TOP_LEVEL_DIRECTORY}:
            raise IdentityError(
                f"archive must have exactly one top-level directory named {TOP_LEVEL_DIRECTORY}; got {sorted(roots)}"
            )
        for info in infos:
            if info.is_dir():
                continue
            relative = _safe_relative_path(info.filename)
            if relative in normalized_paths:
                raise IdentityError(f"duplicate normalized path: {relative!r}")
            normalized_paths.add(relative)
            digest, byte_size = _entry_digest(archive, info)
            records.append(FileRecord(digest, byte_size, relative))

    canonical_manifest = manifest_bytes(records)
    canonical_hash = hashlib.sha256(canonical_manifest).hexdigest()
    layout_hash = tree_sha256(records, include_top_level=True)
    summary = {
        "algorithm_id": ALGORITHM_ID,
        "archive": {
            "filename": archive_path.name,
            "sha256": archive_hash,
            "size_bytes": archive_path.stat().st_size,
        },
        "top_level_directory": TOP_LEVEL_DIRECTORY,
        "file_count": len(records),
        "canonical_release_root_tree_sha256": canonical_hash,
        "archive_layout_tree_sha256": layout_hash,
        "mindtct_subtree": _subtree_identity(records, "mindtct"),
        "bozorth3_subtree": _subtree_identity(records, "bozorth3"),
        "manifest_sha256": canonical_hash,
        "manifest_bytes": len(canonical_manifest),
        "source_extracted_to_disk": False,
    }
    return summary, canonical_manifest


def validate_official_identity(summary: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    archive = summary.get("archive", {})
    expected = {
        "archive SHA-256": (archive.get("sha256"), OFFICIAL_ARCHIVE_SHA256),
        "archive size": (archive.get("size_bytes"), OFFICIAL_ARCHIVE_SIZE),
        "file count": (summary.get("file_count"), OFFICIAL_FILE_COUNT),
        "canonical tree SHA-256": (
            summary.get("canonical_release_root_tree_sha256"), CANONICAL_TREE_SHA256
        ),
        "archive-layout tree SHA-256": (
            summary.get("archive_layout_tree_sha256"), ARCHIVE_LAYOUT_TREE_SHA256
        ),
        "MINDTCT subtree SHA-256": (
            summary.get("mindtct_subtree", {}).get("sha256"), MINDTCT_TREE_SHA256
        ),
        "BOZORTH3 subtree SHA-256": (
            summary.get("bozorth3_subtree", {}).get("sha256"), BOZORTH3_TREE_SHA256
        ),
    }
    for label, (actual, wanted) in expected.items():
        if actual != wanted:
            errors.append(f"{label} mismatch: expected {wanted}, got {actual}")
    if summary.get("canonical_release_root_tree_sha256") == NON_REPRODUCIBLE_V1_HASH:
        errors.append("the non-reproducible v1 tree hash is prohibited as an accepted alias")
    return errors


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument(
        "--expected-archive-sha256",
        default=OFFICIAL_ARCHIVE_SHA256,
        help="expected archive SHA-256; defaults to the official locked archive",
    )
    parser.add_argument("--output-summary", type=Path)
    parser.add_argument("--output-manifest", type=Path)
    parser.add_argument("--validate-only", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.validate_only and (args.output_summary or args.output_manifest):
        parser.error("--validate-only cannot be combined with output files")
    try:
        summary, manifest = compute_identity(args.archive, args.expected_archive_sha256)
    except (OSError, zipfile.BadZipFile, IdentityError) as exc:
        print(f"NBIS source-tree identity v2: FAIL: {exc}", file=sys.stderr)
        return 1

    if args.validate_only:
        errors = validate_official_identity(summary)
        if errors:
            print("NBIS source-tree identity v2: FAIL", file=sys.stderr)
            for error in errors:
                print(f"- {error}", file=sys.stderr)
            return 1
        print("NBIS source-tree identity v2: PASS")
        return 0

    if args.output_summary:
        args.output_summary.write_bytes(canonical_json_bytes(summary))
    if args.output_manifest:
        args.output_manifest.write_bytes(manifest)
    print(json.dumps(summary, ensure_ascii=True, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
