"""Read-only protocol preflight."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .manifest import read_protocol_manifest


def validate_protocol(protocol_root: Path, dataset_root: Path) -> dict[str, Any]:
    root = Path(protocol_root)
    manifests = sorted(root.glob("*/*.csv"))
    if not manifests:
        raise ValueError("protocol package contains no manifests")
    summaries = []
    for path in manifests:
        loaded = read_protocol_manifest(path, dataset_root)
        summaries.append({"manifest": loaded.relative_path, "sha256": loaded.sha256, "rows": len(loaded.records)})
    first = read_protocol_manifest(manifests[0], dataset_root)
    return {
        "valid": True,
        "protocol_id": first.protocol_id,
        "protocol_version": first.protocol_version,
        "protocol_lock_sha256": first.protocol_lock_sha256,
        "manifest_count": len(summaries),
        "row_count": sum(item["rows"] for item in summaries),
        "manifests": summaries,
    }
