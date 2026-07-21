"""Runtime and source provenance capture."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable

from .hashing import file_sha256, stable_sha256


def _git(repo_root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args], cwd=repo_root, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    return completed.stdout.strip()


def collect_provenance(
    *, repo_root: Path, implementation_files: Iterable[Path], manifest_sha256: str,
    protocol_lock_sha256: str, method_config: dict[str, Any], sidecar_health: dict[str, Any], jar_path: Path,
) -> dict[str, Any]:
    repo_root = Path(repo_root).resolve()
    sources = []
    for path in sorted((Path(p).resolve() for p in implementation_files), key=str):
        sources.append({"path": path.relative_to(repo_root).as_posix(), "sha256": file_sha256(path)})
    return {
        "git": {"commit": _git(repo_root, "rev-parse", "HEAD"), "dirty": bool(_git(repo_root, "status", "--porcelain"))},
        "python_version": sys.version.split()[0],
        "implementation_files": sources,
        "implementation_sha256": stable_sha256(sources),
        "manifest_sha256": manifest_sha256,
        "protocol_lock_sha256": protocol_lock_sha256,
        "method_config": method_config,
        "method_config_sha256": stable_sha256(method_config),
        "java_version": sidecar_health["java_runtime_version"],
        "sourceafis_maven_coordinates": sidecar_health["sourceafis_maven_coordinates"],
        "sourceafis_version": sidecar_health["sourceafis_version"],
        "sidecar_contract_version": sidecar_health["contract_version"],
        "sidecar_implementation_version": sidecar_health["implementation_version"],
        "jar_sha256": file_sha256(jar_path),
    }
