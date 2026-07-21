from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path, PurePosixPath

import pytest

from fingerprint_benchmark.manifest import MANIFEST_COLUMNS


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def protocol_factory(tmp_path):
    def create(*, header=MANIFEST_COLUMNS, ppi=1000, relative_path="sd300b/images/a.bin"):
        protocol = tmp_path / "protocol"
        dataset = tmp_path / "dataset"
        (protocol / "sd300b").mkdir(parents=True)
        posix = PurePosixPath(relative_path)
        safe_parts = ("sd300b", "images", "a.bin") if posix.is_absolute() or ".." in posix.parts or ":" in posix.parts[0] else posix.parts
        image = dataset / Path(*safe_parts)
        image.parent.mkdir(parents=True)
        image.write_bytes(b"ordinary-test-bytes")
        metadata = {
            "protocol_id": "synthetic_protocol", "protocol_version": 1,
            "comparison_kinds": ["plain_self"], "datasets": {"sd300b": {"nominal_ppi": 1000}},
        }
        metadata_path = protocol / "protocol_metadata.json"
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
        row = {
            "pair_id": "PAIR_1", "comparison_kind": "plain_self", "dataset_release": "sd300b",
            "subject_index_a": "1", "subject_id_a": "A", "subject_index_b": "2", "subject_id_b": "B",
            "canonical_finger": "1", "hand": "right", "finger_name": "thumb",
            "capture_type_a": "PLAIN", "capture_type_b": "PLAIN", "nominal_ppi_a": str(ppi), "nominal_ppi_b": str(ppi),
            "relative_path_a": relative_path, "relative_path_b": relative_path,
            "sha256_a": "a" * 64, "sha256_b": "b" * 64, "source_frgp_a": "11", "source_frgp_b": "12",
            "image_status_a": "valid", "image_status_b": "valid", "pair_status": "valid", "source_pair_id": "SOURCE_1",
        }
        manifest = protocol / "sd300b" / "plain_self.csv"
        with manifest.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=header, lineterminator="\n", extrasaction="ignore")
            writer.writeheader()
            writer.writerow(row)
        files = {
            "protocol_metadata.json": {"sha256": _sha(metadata_path), "size_bytes": metadata_path.stat().st_size},
            "sd300b/plain_self.csv": {"sha256": _sha(manifest), "size_bytes": manifest.stat().st_size, "row_count": 1},
        }
        lock = {"protocol_id": "synthetic_protocol", "protocol_version": 1, "files": files}
        lock_path = protocol / "manifest_lock.json"
        lock_path.write_text(json.dumps(lock), encoding="utf-8")
        sums = {
            "manifest_lock.json": _sha(lock_path), "protocol_metadata.json": _sha(metadata_path),
            "sd300b/plain_self.csv": _sha(manifest),
        }
        (protocol / "SHA256SUMS.txt").write_text("".join(f"{digest}  {path}\n" for path, digest in sums.items()), encoding="utf-8")
        return protocol, dataset, manifest
    return create
