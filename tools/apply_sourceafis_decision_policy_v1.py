"""Apply the frozen SourceAFIS decision policy to the frozen raw cohort.

This program is deliberately standard-library only.  It never starts Java, Maven,
the SourceAFIS sidecar, a matcher, a manifest runner, or a network client.  Raw
scores are read only after every frozen input, Git, archive, and file-hash
precondition has passed.  Scores are parsed with Decimal and are never printed.
"""

from __future__ import annotations

import argparse
import csv
import fnmatch
import hashlib
import json
import os
import re
import shutil
import struct
import sys
import uuid
import zlib
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable


APPLICATION_ID = "sourceafis_policy_application_v1"
APPLICATION_VERSION = 1
EXECUTION_ID = "sourceafis_frozen_cohort_v1"
POLICY_ID = "sourceafis_decision_policy_v1"
POLICY_VERSION = 1
SOURCEAFIS_VERSION = "3.18.1"
THRESHOLD_TEXT = "40.0"
OPERATOR = ">="
EXPECTED_ROWS = 4000
EXPECTED_ROWS_PER_BUNDLE = 500
EXPECTED_BUNDLES = 8
EXPECTED_PRIMARY_UNITS = 8
EXPECTED_AGGREGATES = 2
JAR_SHA256 = "1a1a82a079570ecbd10ea95a839acb6f9b670f5703c990029ad6c62881660760"

# The prompt named an obsolete execution object (4c9640b...).  The user explicitly
# authorized continuing through that one gate.  This is the commit to which the
# existing immutable execution tag resolves in the repository being evaluated.
SOURCE_EXECUTION_COMMIT = "173ff0299537bdccb0f609f06114b2d0d22a14d6"
SOURCE_EXECUTION_TAG = "sourceafis-frozen-cohort-v1"
SOURCE_EXECUTION_PROMPT_COMMIT = "4c9640bb95e39f3e44cefbd33db10d6c67bf67b1"
POLICY_COMMIT = "fdef2e36a347e952a0509c07725a222e47aca9c3"
POLICY_TAG = "sourceafis-decision-policy-v1"

REQUIRED_TAGS = {
    "protocol-supervisor-50x10-v1": "29d8de0180403e9aa8a5e81cc468664b96dc8932",
    "sourceafis-runtime-v1": "db1e499f0ee3a5457ec71fbc7feba22214d34116",
    "sourceafis-runtime-qualified-v1": "78af9d227a68456f96f1d63d2547222d5435bb5f",
    POLICY_TAG: POLICY_COMMIT,
    SOURCE_EXECUTION_TAG: SOURCE_EXECUTION_COMMIT,
}

PROTECTED_GIT_TREES = {
    "protocols/supervisor_50x10_v1": "0a49db320b18c42dd6834e285389383b3093ef1f",
    "qualification/sourceafis_runtime_v1": "e6b1984af446d161623bdaa9fc4df921ed302aa5",
    "policies/sourceafis_decision_policy_v1": "ef83b019a432492eb9a955ef893084e49e797714",
    "executions/sourceafis_frozen_cohort_v1": "1eb4117ba6f71dd2ea6ad5be6b7e34138db2e1a9",
    "migration": "b87594670719a3be49f7980939de40deeaf64b97",
    "migration-audit": "8b72dd0607c65e0e5ff7eec3a5bf9824adb07ed2",
    "src/fingerprint_benchmark": "763a5f5057a1d3e7603d13b3db5b28c367917a38",
    "apps/sourceafis-sidecar": "d01aab7cb620699b2168cff0bd93a3e1cc62b68d",
}

FROZEN_TREE_SHA256 = {
    "protocol": "b88ce7ef428ab6bbb6ecc36e547ad05fddc0d536f3498159fbf6357d2ea3138e",
    "runtime": "7886827be3775d19d8eaecc89294727efb9a1046633b40cd141588b12d6870f7",
    "qualification": "b2b9494c9d3e3a1246cd2e42644d9ee864ecccc806dc07be576a8b5af4682f03",
    "policy": "3b207a950b54e29db88c38239122717d4a7544865c713a963df777ed2c73a0d7",
}

EXPECTED_CLASS = {
    "plain_self": "same",
    "roll_self": "same",
    "plain_roll_genuine": "same",
    "plain_roll_next_subject": "different",
}
REPORTING_CATEGORY = {
    "plain_self": "self_consistency",
    "roll_self": "self_consistency",
    "plain_roll_genuine": "verification_genuine",
    "plain_roll_next_subject": "verification_impostor",
}

RESULT_COLUMNS = (
    "run_id", "method", "method_version", "protocol_id", "protocol_version",
    "manifest_relative_path", "manifest_sha256", "pair_index", "pair_id", "comparison_kind",
    "dataset_release", "subject_index_a", "subject_id_a", "subject_index_b", "subject_id_b",
    "canonical_finger", "hand", "finger_name", "capture_type_a", "capture_type_b",
    "nominal_ppi_a", "nominal_ppi_b", "relative_path_a", "relative_path_b", "sha256_a", "sha256_b",
    "source_frgp_a", "source_frgp_b", "image_status_a", "image_status_b", "pair_status", "source_pair_id",
    "prepare_a_status", "prepare_b_status", "comparison_status", "status", "error_code", "error_message",
    "raw_score", "score_direction", "score_semantics", "prepare_a_wall_ms", "prepare_b_wall_ms",
    "compare_wall_ms", "method_internal_prepare_a_ms", "method_internal_prepare_b_ms",
    "method_internal_compare_ms", "score_payload_sha256",
)

DERIVED_COLUMNS = (
    "application_id", "application_code_commit", "source_execution_id", "source_run_id",
    "source_results_sha256", "pair_index", "pair_id", "dataset_release", "comparison_kind",
    "expected_class", "source_status", "decision", "outcome", "decision_payload_sha256",
)

EVALUATION_FILES = (
    "README.md", "application_plan.json", "input_bundle_registry.json",
    "primary_results.json", "primary_results.csv", "verification_aggregates.json",
    "application_validation_report.json", "application_lock.json", "SHA256SUMS.txt",
)

PROCESS_NOTE_QUALIFICATION_DISPLAY = (
    "During the preceding execution-stage session, qualification scores were unintentionally "
    "displayed by a redaction script. The frozen decision policy had already been committed and "
    "tagged before that display. No frozen-cohort score was used to select or modify the threshold."
)
PROCESS_NOTE_EXECUTION_IDENTITY = (
    "The task prompt named source execution commit " + SOURCE_EXECUTION_PROMPT_COMMIT +
    ", but the existing sourceafis-frozen-cohort-v1 tag resolves to " + SOURCE_EXECUTION_COMMIT +
    ". The user explicitly authorized bypassing this identity gate; the tagged commit was used and "
    "recorded without moving the tag."
)
PROCESS_NOTE_CODE_FIX_PREFIX = (
    "The first application attempt at code commit 410f88cf9eb7a9b508668856cb39fe2a5325d2fe "
    "processed all rows but published no evaluation because static candidate validation detected a "
    "missing application_id in input_bundle_registry.json. The attempt artifacts were quarantined, "
    "a synthetic regression test was added, and the application was restarted from the beginning "
    "using code commit "
)
PROCESS_NOTE_LOCAL_VALIDATOR_FIX_PREFIX = (
    "The second full application attempt at code commit "
    "96ecd63a77e0c3a6db8d2cb9c2f88007a13c872d published a complete local candidate, "
    "but the independent post-publication validator treated the expected untracked evaluation "
    "directory as unrelated worktree dirt. No result package was committed. The attempt artifacts "
    "were quarantined, a synthetic regression test was added, and the application was restarted "
    "from the beginning using code commit "
)


class ApplicationBlocked(RuntimeError):
    """A frozen precondition failed before any cohort score was read."""


class InvalidInput(ValueError):
    """A raw result row or ordered result set violates the frozen contract."""


class ApplicationFailed(RuntimeError):
    """The complete application could not be published safely."""


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")


def stable_sha256(value: Any) -> str:
    payload = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.write_bytes(canonical_json_bytes(value))


def tree_sha256(root: Path, relative_paths: Iterable[str] | None = None) -> str:
    root = Path(root)
    records: list[str] = []
    candidates = [root / PurePosixPath(item) for item in relative_paths] if relative_paths else [root]
    for candidate in candidates:
        paths = [candidate] if candidate.is_file() else sorted(candidate.rglob("*"))
        for path in paths:
            if not path.is_file():
                continue
            relative = path.relative_to(root).as_posix()
            records.append(f"{relative}|{path.stat().st_size}|{file_sha256(path)}")
    return hashlib.sha256("\n".join(sorted(records, key=str.lower)).encode("utf-8")).hexdigest()


def package_sha256(root: Path) -> str:
    return tree_sha256(Path(root))


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ApplicationBlocked(f"invalid or missing JSON: {path.name}") from exc


def _verify_checksum_index(root: Path, label: str) -> None:
    index = root / "SHA256SUMS.txt"
    if not index.is_file():
        raise ApplicationBlocked(f"{label} package has no SHA256SUMS.txt")
    seen: set[str] = set()
    for line in index.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\\]+)", line)
        if not match:
            raise ApplicationBlocked(f"{label} package has a malformed checksum line")
        digest, relative = match.groups()
        if relative in seen:
            raise ApplicationBlocked(f"{label} package checksum path is duplicated")
        seen.add(relative)
        target = root / PurePosixPath(relative)
        if not target.is_file() or file_sha256(target) != digest:
            raise ApplicationBlocked(f"{label} package checksum mismatch: {relative}")


# --------------------------------------------------------------------------- pure Git checks


def _git_dir(repository_root: Path) -> Path:
    marker = repository_root / ".git"
    if marker.is_dir():
        return marker
    if marker.is_file():
        text = marker.read_text(encoding="utf-8").strip()
        if text.startswith("gitdir: "):
            return (repository_root / text[8:]).resolve()
    raise ApplicationBlocked("repository has no readable .git directory")


def _packed_refs(git_dir: Path) -> tuple[dict[str, str], dict[str, str]]:
    direct: dict[str, str] = {}
    peeled: dict[str, str] = {}
    path = git_dir / "packed-refs"
    if not path.is_file():
        return direct, peeled
    previous: str | None = None
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        if line.startswith("^") and previous is not None:
            peeled[previous] = line[1:]
            continue
        sha, ref = line.split(" ", 1)
        direct[ref] = sha
        previous = ref
    return direct, peeled


def _read_ref(git_dir: Path, ref: str) -> str:
    path = git_dir / PurePosixPath(ref)
    if path.is_file():
        value = path.read_text(encoding="ascii").strip()
        return _read_ref(git_dir, value[5:]) if value.startswith("ref: ") else value
    packed, _peeled = _packed_refs(git_dir)
    if ref not in packed:
        raise ApplicationBlocked(f"required Git ref is missing: {ref}")
    return packed[ref]


def _read_loose_object(git_dir: Path, sha: str) -> tuple[str, bytes]:
    path = git_dir / "objects" / sha[:2] / sha[2:]
    if not path.is_file():
        raise ApplicationBlocked(f"required loose Git object is unavailable: {sha}")
    decoded = zlib.decompress(path.read_bytes())
    header, payload = decoded.split(b"\0", 1)
    object_type, _size = header.decode("ascii").split(" ", 1)
    return object_type, payload


def resolve_tag_commit(repository_root: Path, tag: str) -> str:
    git_dir = _git_dir(repository_root)
    ref = f"refs/tags/{tag}"
    direct, peeled = _packed_refs(git_dir)
    if ref in peeled:
        return peeled[ref]
    sha = _read_ref(git_dir, ref)
    for _ in range(4):
        object_type, payload = _read_loose_object(git_dir, sha)
        if object_type == "commit":
            return sha
        if object_type != "tag":
            raise ApplicationBlocked(f"tag {tag} does not resolve to a commit")
        first = payload.splitlines()[0].decode("ascii")
        if not first.startswith("object "):
            raise ApplicationBlocked(f"tag {tag} is malformed")
        sha = first[7:]
    raise ApplicationBlocked(f"tag {tag} has excessive indirection")


def _parse_index(repository_root: Path) -> list[dict[str, Any]]:
    data = (_git_dir(repository_root) / "index").read_bytes()
    if len(data) < 12 or data[:4] != b"DIRC":
        raise ApplicationBlocked("unsupported or missing Git index")
    version, count = struct.unpack(">II", data[4:12])
    if version not in (2, 3):
        raise ApplicationBlocked(f"unsupported Git index version: {version}")
    offset = 12
    entries: list[dict[str, Any]] = []
    for _ in range(count):
        start = offset
        if offset + 62 > len(data):
            raise ApplicationBlocked("truncated Git index")
        fields = struct.unpack(">10I20sH", data[offset:offset + 62])
        mode, size, blob, flags = fields[6], fields[9], fields[10].hex(), fields[11]
        offset += 62
        if flags & 0x4000:
            offset += 2
        end = data.index(b"\0", offset)
        path = data[offset:end].decode("utf-8", errors="surrogateescape")
        offset = end + 1
        offset += (8 - ((offset - start) % 8)) % 8
        if ((flags >> 12) & 3) == 0:
            entries.append({"path": path, "mode": mode, "size": size, "blob": blob})
    return entries


def _git_object_hash(object_type: str, payload: bytes) -> str:
    header = f"{object_type} {len(payload)}\0".encode("ascii")
    return hashlib.sha1(header + payload).hexdigest()  # Git repository object format is SHA-1.


def _index_tree(entries: list[dict[str, Any]]) -> tuple[str, dict[str, str]]:
    root: dict[str, Any] = {}
    for entry in entries:
        cursor = root
        parts = PurePosixPath(entry["path"]).parts
        for part in parts[:-1]:
            cursor = cursor.setdefault(part, {})
        cursor[parts[-1]] = entry
    subtree_hashes: dict[str, str] = {}

    def build(node: dict[str, Any], prefix: str = "") -> str:
        encoded: list[tuple[bytes, bytes]] = []
        for name, value in node.items():
            path = f"{prefix}/{name}" if prefix else name
            if isinstance(value, dict) and "blob" not in value:
                sha = build(value, path)
                mode = "40000"
                sort_name = (name + "/").encode("utf-8", errors="surrogateescape")
            else:
                sha = value["blob"]
                mode = format(value["mode"], "o")
                sort_name = name.encode("utf-8", errors="surrogateescape")
            raw_name = name.encode("utf-8", errors="surrogateescape")
            encoded.append((sort_name, f"{mode} ".encode("ascii") + raw_name + b"\0" + bytes.fromhex(sha)))
        payload = b"".join(record for _key, record in sorted(encoded, key=lambda item: item[0]))
        digest = _git_object_hash("tree", payload)
        if prefix:
            subtree_hashes[prefix] = digest
        return digest

    return build(root), subtree_hashes


def _head_commit_and_tree(repository_root: Path) -> tuple[str, str, str | None]:
    git_dir = _git_dir(repository_root)
    head_text = (git_dir / "HEAD").read_text(encoding="ascii").strip()
    if not head_text.startswith("ref: refs/heads/"):
        raise ApplicationBlocked("detached HEAD is not allowed")
    branch = head_text.removeprefix("ref: refs/heads/")
    head = _read_ref(git_dir, f"refs/heads/{branch}")
    try:
        object_type, payload = _read_loose_object(git_dir, head)
    except ApplicationBlocked:
        # A fresh clone commonly keeps HEAD in a pack file.  The application run is
        # still guarded by an external porcelain check, tracked-content checks below,
        # tag identities, and a locally-created loose Commit A.  Static CI validation
        # must remain usable on packed clones without executing Git.
        return branch, head, None
    if object_type != "commit":
        raise ApplicationBlocked("HEAD does not resolve to a commit")
    tree_line = next((line for line in payload.splitlines() if line.startswith(b"tree ")), None)
    if tree_line is None:
        raise ApplicationBlocked("HEAD commit has no tree")
    return branch, head, tree_line[5:].decode("ascii")


def _ignored_untracked(relative: str) -> bool:
    parts = PurePosixPath(relative).parts
    if len(parts) >= 2 and parts[:2] == ("evaluations", APPLICATION_ID):
        # The independent local validator runs after atomic publication but before
        # Commit B.  verify_repository() separately and explicitly rejects an
        # existing package at the pre-score gate, so this narrow status exemption
        # cannot permit an application overwrite or partial continuation.
        return True
    if any(part in {"__pycache__", ".pytest_cache", "target"} for part in parts):
        return True
    if parts and parts[0] == "results":
        return True
    if any(".candidate-" in part or ".rollback-" in part for part in parts):
        return True
    name = parts[-1] if parts else relative
    patterns = ("*.pyc", "*.pyo", "*.log", "*.jar", "*.egg-info")
    return any(fnmatch.fnmatch(name, pattern) for pattern in patterns)


def verify_clean_worktree(repository_root: Path) -> dict[str, str]:
    entries = _parse_index(repository_root)
    branch, head, head_tree = _head_commit_and_tree(repository_root)
    index_tree, subtrees = _index_tree(entries)
    if head_tree is not None and index_tree != head_tree:
        raise ApplicationBlocked("Git index differs from HEAD")
    tracked = {entry["path"] for entry in entries}
    for entry in entries:
        path = repository_root / PurePosixPath(entry["path"])
        if not path.is_file():
            raise ApplicationBlocked(f"tracked path is missing: {entry['path']}")
        data = path.read_bytes()
        if _git_object_hash("blob", data) != entry["blob"]:
            raise ApplicationBlocked(f"tracked path is modified: {entry['path']}")
    for path in repository_root.rglob("*"):
        if not path.is_file() or ".git" in path.parts:
            continue
        relative = path.relative_to(repository_root).as_posix()
        if relative not in tracked and not _ignored_untracked(relative):
            raise ApplicationBlocked(f"untracked path makes the worktree dirty: {relative}")
    return {"branch": branch, "head": head, "head_tree": head_tree or index_tree, **subtrees}


def verify_repository(repository_root: Path) -> dict[str, str]:
    state = verify_clean_worktree(repository_root)
    if state["branch"] != "main":
        raise ApplicationBlocked(f"application requires branch main, found {state['branch']!r}")
    for tag, expected in REQUIRED_TAGS.items():
        actual = resolve_tag_commit(repository_root, tag)
        if actual != expected:
            raise ApplicationBlocked(f"tag {tag} points at {actual}, expected {expected}")
    for path, expected in PROTECTED_GIT_TREES.items():
        if state.get(path) != expected:
            raise ApplicationBlocked(f"protected Git tree mismatch: {path}")
    if state["head"] == SOURCE_EXECUTION_COMMIT:
        raise ApplicationBlocked("application code has not been committed after the source execution")
    object_type, payload = _read_loose_object(_git_dir(repository_root), state["head"])
    parents = [line[7:].decode("ascii") for line in payload.splitlines() if line.startswith(b"parent ")]
    if SOURCE_EXECUTION_COMMIT not in parents:
        # Follow only locally-created loose commits.  Commit A (or a bug-fix descendant)
        # is required to be a direct, auditable chain above the frozen execution.
        current = parents[0] if parents else ""
        found = False
        for _ in range(16):
            if current == SOURCE_EXECUTION_COMMIT:
                found = True
                break
            try:
                kind, body = _read_loose_object(_git_dir(repository_root), current)
            except ApplicationBlocked:
                break
            if kind != "commit":
                break
            chain = [line[7:].decode("ascii") for line in body.splitlines() if line.startswith(b"parent ")]
            current = chain[0] if chain else ""
        if not found:
            raise ApplicationBlocked("source execution commit is not in the local HEAD ancestry")
    if (repository_root / "evaluations" / APPLICATION_ID).exists():
        raise ApplicationBlocked("a previous evaluation package already exists")
    return state


# --------------------------------------------------------------------------- frozen inputs and archive


def compute_bundle_set_sha256(entries: list[dict[str, Any]]) -> str:
    payload = [
        {
            "manifest_sha256": entry["manifest_sha256"],
            "metadata_sha256": entry["metadata_sha256"],
            "provenance_sha256": entry["provenance_sha256"],
            "results_csv_sha256": entry["results_csv_sha256"],
            "run_id": entry["run_id"],
        }
        for entry in sorted(entries, key=lambda item: item["execution_order"])
    ]
    return stable_sha256(payload)


def validate_frozen_packages(repository_root: Path) -> dict[str, Any]:
    roots = {
        "protocol": repository_root / "protocols" / "supervisor_50x10_v1",
        "qualification": repository_root / "qualification" / "sourceafis_runtime_v1",
        "policy": repository_root / "policies" / POLICY_ID,
        "execution": repository_root / "executions" / EXECUTION_ID,
    }
    for label, root in roots.items():
        if not root.is_dir():
            raise ApplicationBlocked(f"missing frozen {label} package")
        _verify_checksum_index(root, label)
    decision = _load_json(roots["policy"] / "decision_policy.json")
    rule = decision.get("decision_rule", {})
    if decision.get("policy_id") != POLICY_ID or decision.get("policy_version") != POLICY_VERSION:
        raise ApplicationBlocked("decision policy identity mismatch")
    if decision.get("method", {}).get("sourceafis_version") != SOURCEAFIS_VERSION:
        raise ApplicationBlocked("decision policy SourceAFIS version mismatch")
    if rule.get("threshold") != THRESHOLD_TEXT or rule.get("operator") != OPERATOR:
        raise ApplicationBlocked("decision policy threshold or operator mismatch")
    if rule.get("round_before_comparison") is not False or rule.get("epsilon_comparison") is not False:
        raise ApplicationBlocked("decision policy enables score transformation")
    if decision.get("expected_class") != EXPECTED_CLASS:
        raise ApplicationBlocked("decision policy expected-class mapping mismatch")
    registry = _load_json(roots["execution"] / "bundle_registry.json")
    entries = registry.get("bundles")
    if not isinstance(entries, list) or len(entries) != EXPECTED_BUNDLES:
        raise ApplicationBlocked("execution registry does not contain eight bundles")
    if registry.get("execution_id") != EXECUTION_ID or registry.get("total_rows") != EXPECTED_ROWS:
        raise ApplicationBlocked("execution registry identity or row count mismatch")
    lock = _load_json(roots["execution"] / "execution_lock.json")
    if lock.get("bundle_set_sha256") != compute_bundle_set_sha256(entries):
        raise ApplicationBlocked("execution bundle-set hash mismatch")
    if lock.get("jar_sha256") != JAR_SHA256:
        raise ApplicationBlocked("execution JAR hash mismatch")
    for position, entry in enumerate(entries, start=1):
        if entry.get("execution_order") != position or entry.get("row_count") != EXPECTED_ROWS_PER_BUNDLE:
            raise ApplicationBlocked("execution bundle order or row count mismatch")
        if entry.get("sourceafis_version") != SOURCEAFIS_VERSION:
            raise ApplicationBlocked("execution SourceAFIS version mismatch")
    return {
        "decision": decision,
        "execution_lock": lock,
        "execution_package_sha256": package_sha256(roots["execution"]),
        "policy_sha256": file_sha256(roots["policy"] / "decision_policy.json"),
        "registry": registry,
        "roots": roots,
    }


def _bundle_expected_files(entry: dict[str, Any]) -> dict[str, str]:
    return {
        "metadata.json": entry["metadata_sha256"],
        "provenance.json": entry["provenance_sha256"],
        "results.csv": entry["results_csv_sha256"],
    }


def verify_bundle_file_hashes(raw_root: Path, entries: list[dict[str, Any]]) -> None:
    for entry in entries:
        bundle = raw_root / entry["run_id"]
        if entry.get("bundle_relative_path") != f"raw/{entry['run_id']}":
            raise ApplicationBlocked("registry bundle path does not match run identity")
        for name, expected in _bundle_expected_files(entry).items():
            path = bundle / name
            if not path.is_file() or file_sha256(path) != expected:
                raise ApplicationBlocked(f"bundle hash mismatch: {entry['run_id']}/{name}")


def _runtime_jar(runtime_root: Path) -> Path:
    matches = [path for path in runtime_root.rglob("*.jar") if path.is_file() and file_sha256(path) == JAR_SHA256]
    if len(matches) != 1:
        raise ApplicationBlocked("canonical JAR is missing or ambiguous")
    return matches[0]


def _archive_receipt_payload(target: Path, frozen: dict[str, Any], created_at: str) -> dict[str, Any]:
    files: list[dict[str, Any]] = []
    for path in sorted((target / "raw").rglob("*")):
        if path.is_file():
            files.append({
                "relative_path": path.relative_to(target).as_posix(),
                "sha256": file_sha256(path), "size_bytes": path.stat().st_size,
            })
    jar = _runtime_jar(target / "runtime")
    files.append({
        "relative_path": jar.relative_to(target).as_posix(),
        "sha256": file_sha256(jar), "size_bytes": jar.stat().st_size,
    })
    files.sort(key=lambda item: item["relative_path"])
    return {
        "archive_id": "external_archive/sourceafis_frozen_cohort_v1",
        "bundle_set_sha256": frozen["execution_lock"]["bundle_set_sha256"],
        "copy_verification": "PASS",
        "created_at_utc": created_at,
        "execution_commit": SOURCE_EXECUTION_COMMIT,
        "execution_id": EXECUTION_ID,
        "execution_tag": SOURCE_EXECUTION_TAG,
        "file_count": len(files),
        "files": files,
        "jar_sha256": JAR_SHA256,
        "jar_size_bytes": jar.stat().st_size,
        "run_ids": [entry["run_id"] for entry in frozen["registry"]["bundles"]],
        "total_bytes": sum(item["size_bytes"] for item in files),
    }


def verify_external_archive(target: Path, frozen: dict[str, Any], *, allow_create_receipt: bool) -> dict[str, Any]:
    entries = frozen["registry"]["bundles"]
    if not target.is_dir():
        raise ApplicationBlocked("external archive is absent")
    verify_bundle_file_hashes(target / "raw", entries)
    _runtime_jar(target / "runtime")
    receipt_path = target / "archive_receipt.json"
    if receipt_path.exists():
        receipt = _load_json(receipt_path)
        created_at = str(receipt.get("created_at_utc", ""))
        expected = _archive_receipt_payload(target, frozen, created_at)
        if receipt != expected:
            raise ApplicationBlocked("existing external archive differs from frozen execution registry")
    elif allow_create_receipt:
        receipt = _archive_receipt_payload(target, frozen, utc_now())
        write_json(receipt_path, receipt)
    else:
        raise ApplicationBlocked("external archive receipt is absent")
    return {"receipt": receipt, "receipt_sha256": file_sha256(receipt_path)}


def preserve_external_archive(results_root: Path, archive_root: Path, frozen: dict[str, Any]) -> dict[str, Any]:
    target = Path(archive_root)
    if target.exists():
        return verify_external_archive(target, frozen, allow_create_receipt=True)
    source_raw = Path(results_root) / "raw"
    source_runtime = Path(results_root) / "runtime"
    verify_bundle_file_hashes(source_raw, frozen["registry"]["bundles"])
    _runtime_jar(source_runtime)
    target.parent.mkdir(parents=True, exist_ok=True)
    candidate = target.parent / f".{target.name}.candidate-{uuid.uuid4().hex}"
    candidate.mkdir(parents=False, exist_ok=False)
    try:
        shutil.copytree(source_raw, candidate / "raw", copy_function=shutil.copy2)
        shutil.copytree(source_runtime, candidate / "runtime", copy_function=shutil.copy2)
        receipt = _archive_receipt_payload(candidate, frozen, utc_now())
        write_json(candidate / "archive_receipt.json", receipt)
        verify_external_archive(candidate, frozen, allow_create_receipt=False)
        candidate.rename(target)
    except BaseException:
        if candidate.exists():
            shutil.rmtree(candidate)
        raise
    return verify_external_archive(target, frozen, allow_create_receipt=False)


# --------------------------------------------------------------------------- policy and metrics


def decision_for_row(row: dict[str, str], comparison_kind: str) -> tuple[str, str, str, str | None, str | None]:
    if comparison_kind not in EXPECTED_CLASS:
        raise InvalidInput("unknown comparison kind")
    expected = EXPECTED_CLASS[comparison_kind]
    status = row.get("status", "")
    raw_text = row.get("raw_score", "")
    error_code = row.get("error_code", "")
    error_message = row.get("error_message", "")
    if status == "ok":
        if not raw_text:
            raise InvalidInput("successful row has no score")
        if error_code or error_message:
            raise InvalidInput("successful row carries error information")
        try:
            score = Decimal(raw_text)
        except InvalidOperation as exc:
            raise InvalidInput("successful row score is not decimal") from exc
        if not score.is_finite():
            raise InvalidInput("successful row score is not finite")
        if score < Decimal(0):
            raise InvalidInput("successful row score is negative")
        decision = "same" if score >= Decimal(THRESHOLD_TEXT) else "different"
        raw_payload: str | None = raw_text
        error_payload: str | None = None
    else:
        if raw_text:
            raise InvalidInput("failed row carries a score")
        if not error_code.strip():
            raise InvalidInput("failed row has no error code")
        decision = "no_decision"
        raw_payload = None
        error_payload = error_code
    outcome = outcome_for(expected, decision)
    return expected, decision, outcome, raw_payload, error_payload


def outcome_for(expected: str, decision: str) -> str:
    if decision == "no_decision":
        return "technical_failure"
    mapping = {
        ("same", "same"): "correct_same",
        ("same", "different"): "false_non_match",
        ("different", "same"): "false_match",
        ("different", "different"): "correct_different",
    }
    try:
        return mapping[(expected, decision)]
    except KeyError as exc:
        raise InvalidInput("unsupported expected-class decision mapping") from exc


def machine_rate(numerator: int, denominator: int) -> dict[str, int | str | None]:
    if numerator < 0 or denominator < 0 or numerator > denominator:
        raise ValueError("invalid rate counts")
    value = None
    if denominator:
        value = format(
            (Decimal(numerator) / Decimal(denominator)).quantize(Decimal("0.000001"), rounding=ROUND_HALF_UP),
            ".6f",
        )
    return {"numerator": numerator, "denominator": denominator, "value": value}


def human_rate(numerator: int, denominator: int) -> str:
    if denominator == 0:
        return f"{numerator}/{denominator} (N/A)"
    value = (Decimal(numerator) * Decimal(100) / Decimal(denominator)).quantize(
        Decimal("0.01"), rounding=ROUND_HALF_UP,
    )
    return f"{numerator}/{denominator} ({value:.2f}%)"


def summarize_rows(rows: list[dict[str, str]]) -> dict[str, Any]:
    counts = {
        "planned_pairs": len(rows), "successful_scores": 0, "technical_failures": 0,
        "same_decisions": 0, "different_decisions": 0, "no_decisions": 0,
        "correct_same": 0, "correct_different": 0, "false_matches": 0,
        "false_non_matches": 0, "correct_decisions": 0, "incorrect_decisions": 0,
    }
    outcome_count = {
        "correct_same": "correct_same", "correct_different": "correct_different",
        "false_match": "false_matches", "false_non_match": "false_non_matches",
    }
    for row in rows:
        decision = row["decision"]
        if decision == "no_decision":
            counts["technical_failures"] += 1
            counts["no_decisions"] += 1
            continue
        counts["successful_scores"] += 1
        counts[f"{decision}_decisions"] += 1
        key = outcome_count[row["outcome"]]
        counts[key] += 1
        if row["outcome"].startswith("correct_"):
            counts["correct_decisions"] += 1
        else:
            counts["incorrect_decisions"] += 1
    planned = counts["planned_pairs"]
    successful = counts["successful_scores"]
    rates = {
        "decision_coverage": machine_rate(successful, planned),
        "technical_failure_rate": machine_rate(counts["technical_failures"], planned),
        "valid_only_correct_rate": machine_rate(counts["correct_decisions"], successful),
        "strict_correct_completion_rate": machine_rate(counts["correct_decisions"], planned),
    }
    expected = rows[0]["expected_class"] if rows else "same"
    if expected == "same":
        counts["correct_same_count"] = counts["correct_same"]
        counts["false_non_match_count"] = counts["false_non_matches"]
        rates["match_rate_valid"] = machine_rate(counts["correct_same"], successful)
        rates["false_non_match_rate_valid"] = machine_rate(counts["false_non_matches"], successful)
    else:
        counts["correct_different_count"] = counts["correct_different"]
        counts["false_match_count"] = counts["false_matches"]
        rates["correct_reject_rate_valid"] = machine_rate(counts["correct_different"], successful)
        rates["false_match_rate_valid"] = machine_rate(counts["false_matches"], successful)
    return {**counts, **rates}


def verification_aggregate(primary_entries: list[dict[str, Any]], release: str) -> dict[str, Any]:
    by_kind = {entry["comparison_kind"]: entry for entry in primary_entries if entry["dataset_release"] == release}
    genuine = by_kind["plain_roll_genuine"]
    impostor = by_kind["plain_roll_next_subject"]
    result = {
        "dataset_release": release,
        "plain_self_included": False,
        "roll_self_included": False,
        "included_comparison_kinds": ["plain_roll_genuine", "plain_roll_next_subject"],
        "genuine_planned": genuine["planned_pairs"],
        "impostor_planned": impostor["planned_pairs"],
        "genuine_successful": genuine["successful_scores"],
        "impostor_successful": impostor["successful_scores"],
        "genuine_technical_failures": genuine["technical_failures"],
        "impostor_technical_failures": impostor["technical_failures"],
        "false_non_matches": genuine["false_non_matches"],
        "false_matches": impostor["false_matches"],
        "correct_genuine": genuine["correct_same"],
        "correct_impostor": impostor["correct_different"],
    }
    planned = result["genuine_planned"] + result["impostor_planned"]
    successful = result["genuine_successful"] + result["impostor_successful"]
    correct = result["correct_genuine"] + result["correct_impostor"]
    result.update({
        "fnmr_valid": machine_rate(result["false_non_matches"], result["genuine_successful"]),
        "fmr_valid": machine_rate(result["false_matches"], result["impostor_successful"]),
        "verification_decision_coverage": machine_rate(successful, planned),
        "verification_strict_correct_completion_rate": machine_rate(correct, planned),
    })
    return result


def _score_payload_hash(row: dict[str, str]) -> str:
    try:
        raw_score = float(row["raw_score"]) if row["raw_score"] else None
    except ValueError as exc:
        raise InvalidInput("source score payload contains an invalid number") from exc
    payload = {
        "contract_version": "sourceafis-runtime-v1",
        "method_id": row["method"], "method_version": row["method_version"],
        "protocol_id": row["protocol_id"], "protocol_version": int(row["protocol_version"]),
        "manifest_sha256": row["manifest_sha256"], "pair_index": int(row["pair_index"]),
        "pair_id": row["pair_id"], "comparison_kind": row["comparison_kind"],
        "subject_id_a": row["subject_id_a"], "subject_id_b": row["subject_id_b"],
        "sha256_a": row["sha256_a"], "sha256_b": row["sha256_b"],
        "result_status": row["status"], "error_code": row["error_code"] or None,
        "raw_score": raw_score,
    }
    return stable_sha256(payload)


def _read_manifest(path: Path) -> tuple[tuple[str, ...], list[dict[str, str]]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        header = tuple(reader.fieldnames or ())
        rows = [dict(row) for row in reader]
    return header, rows


def process_bundle(
    *, repository_root: Path, results_root: Path, entry: dict[str, Any], application_code_commit: str,
) -> tuple[list[dict[str, str]], dict[str, Any]]:
    bundle = results_root / PurePosixPath(entry["bundle_relative_path"])
    expected_rows = entry.get("row_count", EXPECTED_ROWS_PER_BUNDLE)
    if not isinstance(expected_rows, int) or expected_rows <= 0:
        raise InvalidInput("bundle registry row count is invalid")
    metadata = _load_json(bundle / "metadata.json")
    provenance = _load_json(bundle / "provenance.json")
    if metadata.get("run_id") != entry["run_id"] or metadata.get("row_count") != expected_rows:
        raise InvalidInput("bundle metadata identity or row count mismatch")
    if metadata.get("results_sha256") != entry["results_csv_sha256"]:
        raise InvalidInput("bundle metadata results hash mismatch")
    if metadata.get("provenance_sha256") != entry["provenance_sha256"]:
        raise InvalidInput("bundle metadata provenance hash mismatch")
    if provenance.get("sourceafis_version") != SOURCEAFIS_VERSION or provenance.get("jar_sha256") != JAR_SHA256:
        raise InvalidInput("bundle provenance mismatch")
    manifest_path = repository_root / "protocols" / "supervisor_50x10_v1" / PurePosixPath(entry["manifest_relative_path"])
    manifest_header, manifest_rows = _read_manifest(manifest_path)
    if file_sha256(manifest_path) != entry["manifest_sha256"] or len(manifest_rows) != expected_rows:
        raise InvalidInput("manifest mismatch")
    derived: list[dict[str, str]] = []
    results_path = bundle / "results.csv"
    with results_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if tuple(reader.fieldnames or ()) != RESULT_COLUMNS:
            raise InvalidInput("result header mismatch")
        for expected_index, row in enumerate(reader, start=1):
            if expected_index > len(manifest_rows):
                raise InvalidInput("extra result row")
            source = manifest_rows[expected_index - 1]
            if row["pair_index"] != str(expected_index):
                raise InvalidInput("reordered or duplicate row")
            if row["pair_id"] != source.get("pair_id"):
                raise InvalidInput("pair identity mismatch")
            if row["run_id"] != entry["run_id"] or row["manifest_sha256"] != entry["manifest_sha256"]:
                raise InvalidInput("result source identity mismatch")
            for column in manifest_header:
                if row.get(column) != source.get(column):
                    raise InvalidInput("manifest mismatch")
            if row["comparison_kind"] != entry["comparison_kind"] or row["dataset_release"] != entry["dataset_release"]:
                raise InvalidInput("result reporting unit mismatch")
            if _score_payload_hash(row) != row["score_payload_sha256"]:
                raise InvalidInput("source score payload hash mismatch")
            expected, decision, outcome, raw_payload, error_payload = decision_for_row(row, row["comparison_kind"])
            payload = {
                "policy_id": POLICY_ID, "policy_version": POLICY_VERSION,
                "threshold": THRESHOLD_TEXT, "operator": OPERATOR,
                "source_run_id": entry["run_id"], "source_results_sha256": entry["results_csv_sha256"],
                "pair_index": expected_index, "pair_id": row["pair_id"],
                "comparison_kind": row["comparison_kind"], "expected_class": expected,
                "source_status": row["status"], "raw_score": raw_payload,
                "error_code": error_payload, "decision": decision, "outcome": outcome,
            }
            derived.append({
                "application_id": APPLICATION_ID, "application_code_commit": application_code_commit,
                "source_execution_id": EXECUTION_ID, "source_run_id": entry["run_id"],
                "source_results_sha256": entry["results_csv_sha256"], "pair_index": str(expected_index),
                "pair_id": row["pair_id"], "dataset_release": row["dataset_release"],
                "comparison_kind": row["comparison_kind"], "expected_class": expected,
                "source_status": row["status"], "decision": decision, "outcome": outcome,
                "decision_payload_sha256": stable_sha256(payload),
            })
    if len(derived) != len(manifest_rows):
        raise InvalidInput("missing result row")
    decision_set_sha256 = stable_sha256([row["decision_payload_sha256"] for row in derived])
    summary = summarize_rows(derived)
    primary = {
        "dataset_release": entry["dataset_release"], "comparison_kind": entry["comparison_kind"],
        "expected_class": EXPECTED_CLASS[entry["comparison_kind"]],
        "reporting_category": REPORTING_CATEGORY[entry["comparison_kind"]],
        "source_run_id": entry["run_id"], "source_results_sha256": entry["results_csv_sha256"],
        **summary, "decision_set_sha256": decision_set_sha256,
    }
    return derived, primary


def derive_all(
    *, repository_root: Path, results_root: Path, frozen: dict[str, Any], application_code_commit: str,
    progress: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    verify_bundle_file_hashes(results_root / "raw", frozen["registry"]["bundles"])
    primary: list[dict[str, Any]] = []
    derived_sets: list[dict[str, Any]] = []
    total = 0
    for position, entry in enumerate(frozen["registry"]["bundles"], start=1):
        rows, summary = process_bundle(
            repository_root=repository_root, results_root=results_root,
            entry=entry, application_code_commit=application_code_commit,
        )
        total += len(rows)
        primary.append(summary)
        derived_sets.append({"entry": entry, "rows": rows, "decision_set_sha256": summary["decision_set_sha256"]})
        if progress:
            progress(f"bundle {position}/8 validated; rows processed={total}; decisions generated={total}; "
                     f"technical failures counted={sum(item['technical_failures'] for item in primary)}")
    if total != EXPECTED_ROWS:
        raise InvalidInput("application did not derive 4000 decisions")
    combined = stable_sha256([
        {"source_run_id": item["entry"]["run_id"], "decision_set_sha256": item["decision_set_sha256"]}
        for item in derived_sets
    ])
    aggregates = [verification_aggregate(primary, release) for release in ("sd300b", "sd300c")]
    return {"primary": primary, "aggregates": aggregates, "derived_sets": derived_sets,
            "combined_decision_set_sha256": combined, "total_rows": total}


# --------------------------------------------------------------------------- publication


def _write_derived_candidate(candidate: Path, result: dict[str, Any], frozen: dict[str, Any],
                             application_code_commit: str, archive_verified: bool) -> None:
    derived_root = candidate / "derived"
    derived_root.mkdir(parents=True)
    hashes: list[dict[str, Any]] = []
    for item in result["derived_sets"]:
        name = f"{item['entry']['run_id']}-decisions.csv"
        path = derived_root / name
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=DERIVED_COLUMNS, lineterminator="\n")
            writer.writeheader()
            writer.writerows(item["rows"])
        hashes.append({"file": f"derived/{name}", "sha256": file_sha256(path), "rows": len(item["rows"])})
    metadata = {
        "application_id": APPLICATION_ID, "application_code_commit": application_code_commit,
        "policy_sha256": frozen["policy_sha256"],
        "execution_package_sha256": frozen["execution_package_sha256"],
        "bundle_set_sha256": frozen["execution_lock"]["bundle_set_sha256"],
        "combined_decision_set_sha256": result["combined_decision_set_sha256"],
        "derived_files": hashes, "total_rows": result["total_rows"],
        "external_archive_verified": archive_verified, "publication_status": "published",
    }
    write_json(candidate / "application_metadata.json", metadata)


def _publish_candidate(candidate: Path, destination: Path) -> None:
    if destination.exists():
        raise ApplicationBlocked(f"destination already exists: {destination.name}")
    candidate.rename(destination)


def _primary_csv(path: Path, primary: list[dict[str, Any]]) -> None:
    count_fields = (
        "planned_pairs", "successful_scores", "technical_failures", "same_decisions", "different_decisions",
        "no_decisions", "correct_same", "correct_different", "false_matches", "false_non_matches",
        "correct_decisions", "incorrect_decisions",
    )
    rate_fields = (
        "decision_coverage", "technical_failure_rate", "valid_only_correct_rate",
        "strict_correct_completion_rate", "match_rate_valid", "false_non_match_rate_valid",
        "correct_reject_rate_valid", "false_match_rate_valid",
    )
    fields = ("dataset_release", "comparison_kind", "expected_class", "reporting_category") + count_fields + rate_fields
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        for entry in primary:
            row = {field: entry.get(field, "N/A") for field in fields}
            for field in rate_fields:
                if isinstance(entry.get(field), dict):
                    rate = entry[field]
                    row[field] = human_rate(rate["numerator"], rate["denominator"])
            writer.writerow(row)


def build_input_bundle_registry(frozen: dict[str, Any]) -> dict[str, Any]:
    """Create the application-owned canonical snapshot of the execution registry."""
    registry = json.loads(json.dumps(frozen["registry"]))
    registry.update({
        "application_id": APPLICATION_ID,
        "source_execution_package_sha256": frozen["execution_package_sha256"],
        "source_execution_lock_sha256": file_sha256(frozen["roots"]["execution"] / "execution_lock.json"),
        "bundle_set_sha256": frozen["execution_lock"]["bundle_set_sha256"],
        "external_archive_verified": True,
        "external_archive_id": "external_archive/sourceafis_frozen_cohort_v1",
    })
    return registry


def _readme(primary: list[dict[str, Any]], aggregates: list[dict[str, Any]]) -> str:
    lines = [
        f"# {APPLICATION_ID}", "", "This frozen application deterministically applies the committed",
        f"`{POLICY_ID}` policy to the eight bundles in `{EXECUTION_ID}`.", "",
        "## Frozen inputs and preservation", "",
        f"The source execution is the existing `{SOURCE_EXECUTION_TAG}` tag at `{SOURCE_EXECUTION_COMMIT}`.",
        f"The policy is `{POLICY_TAG}` at `{POLICY_COMMIT}`. The external evidence archive is",
        "identified as `external_archive/sourceafis_frozen_cohort_v1` and was verified byte-for-byte.", "",
        "## Decision and failure policy", "",
        "The threshold is exactly `40.0` and the operator is `>=`. Each complete raw score string",
        "is parsed with `Decimal`; it is not rounded, quantized, converted to an integer, or compared",
        "with an epsilon. `plain_self`, `roll_self`, and `plain_roll_genuine` expect `same`;",
        "`plain_roll_next_subject` expects `different`. A valid technical failure receives",
        "`no_decision` and `technical_failure`, never a numeric score or biometric error outcome.", "",
        "## Primary units", "",
        "Self-consistency units remain separate from verification. Counts and denominators are:", "",
    ]
    for entry in primary:
        lines.append(
            f"- `{entry['dataset_release']}/{entry['comparison_kind']}`: planned={entry['planned_pairs']}, "
            f"successful={entry['successful_scores']}, failures={entry['technical_failures']}, "
            f"correct={entry['correct_decisions']}, incorrect={entry['incorrect_decisions']}; "
            f"coverage {human_rate(entry['decision_coverage']['numerator'], entry['decision_coverage']['denominator'])}."
        )
    lines += ["", "## Verification aggregates", ""]
    for aggregate in aggregates:
        lines.append(
            f"- `{aggregate['dataset_release']}` uses only genuine and next-subject impostor comparisons: "
            f"FNMR {human_rate(aggregate['fnmr_valid']['numerator'], aggregate['fnmr_valid']['denominator'])}; "
            f"FMR {human_rate(aggregate['fmr_valid']['numerator'], aggregate['fmr_valid']['denominator'])}."
        )
    lines += [
        "", "The official SourceAFIS threshold recommendation is not reported as an empirical FMR;",
        "every empirical rate is shown with its observed numerator and denominator.", "",
        "## Reproducibility boundary", "",
        "No matcher, Java process, threshold sweep, distribution, ROC, EER, or timing analysis was run.",
        f"Row-level decisions remain local under `results/{APPLICATION_ID}/derived`; raw bundles and",
        "derived rows are not tracked by Git. This package is the stopping point before the",
        "SourceAFIS Supervisor Report.", "",
    ]
    return "\n".join(lines)


def _build_evaluation_candidate(
    *, repository_root: Path, candidate: Path, frozen: dict[str, Any], result: dict[str, Any],
    application_code_commit: str, archive: dict[str, Any], protected_state: dict[str, str],
) -> None:
    candidate.mkdir(parents=True, exist_ok=False)
    plan = {
        "application_id": APPLICATION_ID, "application_version": APPLICATION_VERSION,
        "application_code_commit": application_code_commit,
        "source_execution_id": EXECUTION_ID, "source_execution_commit": SOURCE_EXECUTION_COMMIT,
        "source_execution_tag": SOURCE_EXECUTION_TAG, "decision_policy_id": POLICY_ID,
        "decision_policy_version": POLICY_VERSION, "decision_policy_commit": POLICY_COMMIT,
        "decision_policy_tag": POLICY_TAG, "sourceafis_version": SOURCEAFIS_VERSION,
        "threshold": THRESHOLD_TEXT, "operator": OPERATOR,
        "input_bundles": [entry["run_id"] for entry in frozen["registry"]["bundles"]],
        "expected_rows": EXPECTED_ROWS, "matcher_execution": False, "java_required": False,
        "score_analysis_allowed": False, "threshold_sweep_allowed": False,
        "row_level_derived_output_tracked": False, "external_archive_verified": True,
    }
    registry = build_input_bundle_registry(frozen)
    primary = {"application_id": APPLICATION_ID, "entries": result["primary"]}
    aggregates = {"application_id": APPLICATION_ID, "entries": result["aggregates"]}
    technical_failures = sum(entry["technical_failures"] for entry in result["primary"])
    report = {
        "application_id": APPLICATION_ID, "valid": True,
        "checks": {
            "external_archive_verified": True, "input_execution_package_valid": True,
            "input_bundles_valid": EXPECTED_BUNDLES, "input_rows_valid": EXPECTED_ROWS,
            "policy_package_valid": True, "threshold": THRESHOLD_TEXT, "operator": OPERATOR,
            "unrounded_scores_used": True, "decision_rows_generated": EXPECTED_ROWS,
            "primary_reporting_units": EXPECTED_PRIMARY_UNITS, "verification_aggregates": EXPECTED_AGGREGATES,
            "matcher_executed": False, "java_invoked": False, "threshold_sweep_performed": False,
            "score_distribution_computed": False, "raw_scores_in_committed_package": False,
            "row_level_decisions_tracked_by_git": False, "protected_areas_unchanged": True,
        },
        "errors": [],
        "warnings": (["The real cohort contained no technical failures; failure handling was exercised only by synthetic tests."]
                     if technical_failures == 0 else []),
        "process_notes": [
            PROCESS_NOTE_QUALIFICATION_DISPLAY,
            PROCESS_NOTE_EXECUTION_IDENTITY,
            PROCESS_NOTE_CODE_FIX_PREFIX + application_code_commit + ".",
            PROCESS_NOTE_LOCAL_VALIDATOR_FIX_PREFIX + application_code_commit + ".",
        ],
    }
    (candidate / "README.md").write_text(_readme(result["primary"], result["aggregates"]), encoding="utf-8", newline="\n")
    write_json(candidate / "application_plan.json", plan)
    write_json(candidate / "input_bundle_registry.json", registry)
    write_json(candidate / "primary_results.json", primary)
    _primary_csv(candidate / "primary_results.csv", result["primary"])
    write_json(candidate / "verification_aggregates.json", aggregates)
    write_json(candidate / "application_validation_report.json", report)
    locked_names = [name for name in EVALUATION_FILES if name not in {"application_lock.json", "SHA256SUMS.txt"}]
    evaluation_files = {
        f"evaluations/{APPLICATION_ID}/{name}": {
            "sha256": file_sha256(candidate / name), "size_bytes": (candidate / name).stat().st_size,
        }
        for name in locked_names
    }
    source_bundles = [
        {
            "run_id": item["entry"]["run_id"],
            "results_csv_sha256": item["entry"]["results_csv_sha256"],
            "decision_set_sha256": item["decision_set_sha256"],
        }
        for item in result["derived_sets"]
    ]
    lock = {
        "application_id": APPLICATION_ID, "application_version": APPLICATION_VERSION,
        "application_code_commit": application_code_commit,
        "protocol": {"commit": REQUIRED_TAGS["protocol-supervisor-50x10-v1"],
                     "tag": "protocol-supervisor-50x10-v1", "tree_sha256": FROZEN_TREE_SHA256["protocol"]},
        "runtime": {"commit": REQUIRED_TAGS["sourceafis-runtime-v1"], "tag": "sourceafis-runtime-v1",
                    "tree_sha256": FROZEN_TREE_SHA256["runtime"]},
        "qualification": {"commit": REQUIRED_TAGS["sourceafis-runtime-qualified-v1"],
                          "tag": "sourceafis-runtime-qualified-v1", "tree_sha256": FROZEN_TREE_SHA256["qualification"]},
        "policy": {"commit": POLICY_COMMIT, "tag": POLICY_TAG, "tree_sha256": FROZEN_TREE_SHA256["policy"],
                   "sha256": frozen["policy_sha256"]},
        "execution": {"commit": SOURCE_EXECUTION_COMMIT, "tag": SOURCE_EXECUTION_TAG,
                      "package_sha256": frozen["execution_package_sha256"],
                      "bundle_set_sha256": frozen["execution_lock"]["bundle_set_sha256"]},
        "threshold": THRESHOLD_TEXT, "operator": OPERATOR,
        "external_archive_receipt_sha256": archive["receipt_sha256"],
        "source_bundles": source_bundles,
        "combined_decision_set_sha256": result["combined_decision_set_sha256"],
        "files": evaluation_files,
        "code_files": {
            relative: {"sha256": file_sha256(repository_root / PurePosixPath(relative)),
                       "size_bytes": (repository_root / PurePosixPath(relative)).stat().st_size}
            for relative in (
                "tools/apply_sourceafis_decision_policy_v1.py",
                "tools/validate_sourceafis_policy_application_v1.py",
                "tests/test_sourceafis_policy_application_v1.py",
            )
        },
        "protected_git_trees": {path: protected_state[path] for path in PROTECTED_GIT_TREES},
        "total_input_rows": EXPECTED_ROWS, "total_derived_decisions": EXPECTED_ROWS,
        "primary_unit_count": EXPECTED_PRIMARY_UNITS, "aggregate_count": EXPECTED_AGGREGATES,
    }
    write_json(candidate / "application_lock.json", lock)
    sums = []
    for path in sorted(candidate.iterdir(), key=lambda item: item.name):
        if path.is_file() and path.name != "SHA256SUMS.txt":
            sums.append(f"{file_sha256(path)}  {path.name}")
    (candidate / "SHA256SUMS.txt").write_text("\n".join(sums) + "\n", encoding="utf-8", newline="\n")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="apply-sourceafis-decision-policy-v1")
    parser.add_argument("--repository-root", required=True, type=Path)
    parser.add_argument("--results-root", required=True, type=Path)
    parser.add_argument("--archive-root", required=True, type=Path)
    parser.add_argument("--derived-output-root", required=True, type=Path)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--validate-only", action="store_true")
    mode.add_argument("--preserve-only", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    repository_root = args.repository_root.resolve()
    results_root = args.results_root.resolve()
    archive_root = args.archive_root.resolve()
    derived_root = args.derived_output_root.resolve()
    try:
        repository = verify_repository(repository_root)
        frozen = validate_frozen_packages(repository_root)
        verify_bundle_file_hashes(results_root / "raw", frozen["registry"]["bundles"])
        _runtime_jar(results_root / "runtime")
        if args.validate_only:
            if not archive_root.is_dir():
                print("SourceAFIS policy application validation: READY; external archive not yet preserved")
            else:
                verify_external_archive(archive_root, frozen, allow_create_receipt=False)
                print("SourceAFIS policy application validation: PASS")
            return 0
        archive = preserve_external_archive(results_root, archive_root, frozen)
        if args.preserve_only:
            print("SourceAFIS frozen-cohort external preservation: PASS")
            return 0
        # This is the final gate before opening any results.csv.
        repository = verify_repository(repository_root)
        frozen = validate_frozen_packages(repository_root)
        verify_external_archive(archive_root, frozen, allow_create_receipt=False)
        verify_bundle_file_hashes(results_root / "raw", frozen["registry"]["bundles"])
        application_code_commit = repository["head"]
        result = derive_all(
            repository_root=repository_root, results_root=results_root, frozen=frozen,
            application_code_commit=application_code_commit, progress=print,
        )
        derived_candidate = derived_root.parent / f".{derived_root.name}.candidate-{uuid.uuid4().hex}"
        _write_derived_candidate(derived_candidate, result, frozen, application_code_commit, True)
        _publish_candidate(derived_candidate, derived_root)
        evaluation_root = repository_root / "evaluations" / APPLICATION_ID
        evaluation_root.parent.mkdir(parents=True, exist_ok=True)
        candidate = evaluation_root.parent / f".{APPLICATION_ID}.candidate-{uuid.uuid4().hex}"
        _build_evaluation_candidate(
            repository_root=repository_root, candidate=candidate, frozen=frozen, result=result,
            application_code_commit=application_code_commit, archive=archive, protected_state=repository,
        )
        tools_root = repository_root / "tools"
        if str(tools_root) not in sys.path:
            sys.path.insert(0, str(tools_root))
        import validate_sourceafis_policy_application_v1 as validator
        errors = validator.validate_package_root(repository_root, candidate, results_root=results_root)
        if errors:
            raise ApplicationFailed(f"evaluation candidate validation failed: {errors[0]}")
        _publish_candidate(candidate, evaluation_root)
        print("package validation status=PASS")
        return 0
    except ApplicationBlocked as exc:
        print(f"status=BLOCKED\nreason={exc}", file=sys.stderr)
        return 2
    except InvalidInput as exc:
        print(f"status=INVALID_INPUT\nreason={exc}", file=sys.stderr)
        return 3
    except (ApplicationFailed, OSError, ValueError) as exc:
        print(f"status=FAIL\nreason={exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
