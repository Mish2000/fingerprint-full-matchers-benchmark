"""One-manifest raw-score runner with atomic result publication."""

from __future__ import annotations

import csv
import json
import math
import shutil
import uuid
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .bundle import publish_bundle
from .contract import BENCHMARK_CONTRACT_VERSION, MatcherAdapter
from .hashing import file_sha256, stable_sha256
from .io import write_csv_atomic, write_json_atomic
from .manifest import ProtocolManifest

RESULT_COLUMNS = (
    "run_id", "method", "method_version", "protocol_id", "protocol_version",
    "manifest_relative_path", "manifest_sha256", "pair_index", "pair_id", "comparison_kind",
    "dataset_release", "subject_index_a", "subject_id_a", "subject_index_b", "subject_id_b",
    "canonical_finger", "hand", "finger_name", "capture_type_a", "capture_type_b",
    "nominal_ppi_a", "nominal_ppi_b", "relative_path_a", "relative_path_b", "sha256_a", "sha256_b",
    "source_frgp_a", "source_frgp_b", "image_status_a", "image_status_b", "pair_status", "source_pair_id",
    "prepare_a_status", "prepare_b_status", "comparison_status", "status", "error_code", "error_message",
    "raw_score", "score_direction", "score_semantics", "prepare_a_wall_ms", "prepare_b_wall_ms",
    "compare_wall_ms", "method_internal_prepare_a_ms", "method_internal_prepare_b_ms", "method_internal_compare_ms",
    "score_payload_sha256",
)


class ResultBundleError(ValueError):
    pass


def _display(value: Any) -> Any:
    return "" if value is None else value


def _result_for_pair(run_id: str, manifest: ProtocolManifest, pair_index: int, pair, adapter: MatcherAdapter) -> dict[str, Any]:
    prepared_a = adapter.prepare(pair.path_a, {"nominal_ppi": pair.nominal_ppi_a, "sha256": pair.sha256_a})
    prepared_b = adapter.prepare(pair.path_b, {"nominal_ppi": pair.nominal_ppi_b, "sha256": pair.sha256_b})
    comparison = None
    if prepared_a.status == "ok" and prepared_b.status == "ok":
        assert prepared_a.representation is not None and prepared_b.representation is not None
        comparison = adapter.compare(prepared_a.representation, prepared_b.representation)
    if prepared_a.status != "ok":
        result_status, error_code, error_message = "prepare_a_failure", prepared_a.error_code, prepared_a.error_message
    elif prepared_b.status != "ok":
        result_status, error_code, error_message = "prepare_b_failure", prepared_b.error_code, prepared_b.error_message
    elif comparison is None or comparison.status != "ok":
        result_status = "comparison_failure"
        error_code = comparison.error_code if comparison else "comparison_not_run"
        error_message = comparison.error_message if comparison else "comparison was not run"
    else:
        result_status, error_code, error_message = "ok", None, None
    raw_score = comparison.raw_score if comparison and comparison.status == "ok" else None
    deterministic = {
        "contract_version": BENCHMARK_CONTRACT_VERSION, "method_id": adapter.metadata.method_id,
        "method_version": adapter.metadata.method_version, "protocol_id": manifest.protocol_id,
        "protocol_version": manifest.protocol_version, "manifest_sha256": manifest.sha256,
        "pair_index": pair_index, "pair_id": pair.pair_id, "comparison_kind": pair.comparison_kind,
        "subject_id_a": pair.subject_id_a, "subject_id_b": pair.subject_id_b,
        "sha256_a": pair.sha256_a, "sha256_b": pair.sha256_b, "result_status": result_status,
        "error_code": error_code, "raw_score": raw_score,
    }
    row = {
        "run_id": run_id, "method": adapter.metadata.method_id, "method_version": adapter.metadata.method_version,
        "protocol_id": manifest.protocol_id, "protocol_version": manifest.protocol_version,
        "manifest_relative_path": manifest.relative_path, "manifest_sha256": manifest.sha256, "pair_index": pair_index,
        **{key: value for key, value in asdict(pair).items() if key not in {"path_a", "path_b"}},
        "prepare_a_status": prepared_a.status, "prepare_b_status": prepared_b.status,
        "comparison_status": comparison.status if comparison else "not_run", "status": result_status,
        "error_code": error_code, "error_message": error_message, "raw_score": raw_score,
        "score_direction": adapter.metadata.score_direction, "score_semantics": adapter.metadata.score_semantics,
        "prepare_a_wall_ms": prepared_a.wall_ms, "prepare_b_wall_ms": prepared_b.wall_ms,
        "compare_wall_ms": comparison.wall_ms if comparison else None,
        "method_internal_prepare_a_ms": prepared_a.internal_ms, "method_internal_prepare_b_ms": prepared_b.internal_ms,
        "method_internal_compare_ms": comparison.internal_ms if comparison else None,
        "score_payload_sha256": stable_sha256(deterministic),
    }
    return {column: _display(row[column]) for column in RESULT_COLUMNS}


def validate_result_bundle(bundle: Path) -> dict[str, Any]:
    bundle = Path(bundle)
    metadata_path, results_path, provenance_path = bundle / "metadata.json", bundle / "results.csv", bundle / "provenance.json"
    if not all(path.is_file() for path in (metadata_path, results_path, provenance_path)):
        raise ResultBundleError("result bundle is incomplete")
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        json.loads(provenance_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ResultBundleError("result bundle contains invalid JSON") from exc
    if metadata.get("contract_version") != BENCHMARK_CONTRACT_VERSION:
        raise ResultBundleError("unexpected result contract version")
    identity = metadata.get("identity")
    if not isinstance(identity, dict) or stable_sha256(identity)[:24] != metadata.get("run_id"):
        raise ResultBundleError("result bundle identity mismatch")
    if metadata.get("results_sha256") != file_sha256(results_path) or metadata.get("provenance_sha256") != file_sha256(provenance_path):
        raise ResultBundleError("result bundle checksum mismatch")
    row_count = 0
    with results_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if tuple(reader.fieldnames or ()) != RESULT_COLUMNS:
            raise ResultBundleError("unexpected results schema")
        for row in reader:
            row_count += 1
            if row["run_id"] != metadata.get("run_id"):
                raise ResultBundleError("result row run identity mismatch")
            if row["status"] == "ok":
                try:
                    score = float(row["raw_score"])
                except ValueError as exc:
                    raise ResultBundleError("successful row has invalid raw score") from exc
                if not math.isfinite(score) or row["error_code"]:
                    raise ResultBundleError("successful row violates score semantics")
            elif row["raw_score"] or not row["error_code"]:
                raise ResultBundleError("failed row violates failure semantics")
            payload = {
                "contract_version": BENCHMARK_CONTRACT_VERSION, "method_id": row["method"],
                "method_version": row["method_version"], "protocol_id": row["protocol_id"],
                "protocol_version": int(row["protocol_version"]), "manifest_sha256": row["manifest_sha256"],
                "pair_index": int(row["pair_index"]), "pair_id": row["pair_id"],
                "comparison_kind": row["comparison_kind"], "subject_id_a": row["subject_id_a"],
                "subject_id_b": row["subject_id_b"], "sha256_a": row["sha256_a"], "sha256_b": row["sha256_b"],
                "result_status": row["status"], "error_code": row["error_code"] or None,
                "raw_score": float(row["raw_score"]) if row["raw_score"] else None,
            }
            if stable_sha256(payload) != row["score_payload_sha256"]:
                raise ResultBundleError("score payload checksum mismatch")
    if row_count != metadata.get("row_count"):
        raise ResultBundleError("result row count mismatch")
    return {"valid": True, "row_count": row_count, "run_id": metadata["run_id"]}


def run_manifest(
    *, manifest: ProtocolManifest, adapter: MatcherAdapter, output_root: Path,
    provenance: dict[str, Any], replace: bool = False,
) -> Path:
    identity = {
        "contract_version": BENCHMARK_CONTRACT_VERSION, "method_id": adapter.metadata.method_id,
        "method_version": adapter.metadata.method_version, "manifest_sha256": manifest.sha256,
        "protocol_lock_sha256": manifest.protocol_lock_sha256,
    }
    run_id = stable_sha256(identity)[:24]
    output_root = Path(output_root)
    destination = output_root / run_id
    if destination.exists() and not replace:
        try:
            validate_result_bundle(destination)
            return destination
        finally:
            adapter.close()
    candidate = output_root / f"{run_id}.candidate-{uuid.uuid4().hex}"
    candidate.mkdir(parents=True, exist_ok=False)
    try:
        rows = [_result_for_pair(run_id, manifest, index, pair, adapter) for index, pair in enumerate(manifest.records, start=1)]
        write_csv_atomic(candidate / "results.csv", rows, RESULT_COLUMNS)
        write_json_atomic(candidate / "provenance.json", provenance)
        metadata = {
            "contract_version": BENCHMARK_CONTRACT_VERSION, "run_id": run_id,
            "row_count": len(rows), "identity": identity,
            "results_sha256": file_sha256(candidate / "results.csv"),
            "provenance_sha256": file_sha256(candidate / "provenance.json"),
        }
        write_json_atomic(candidate / "metadata.json", metadata)
        return publish_bundle(candidate, destination, validate_result_bundle, replace=replace)
    except BaseException:
        if candidate.exists():
            shutil.rmtree(candidate)
        raise
    finally:
        adapter.close()
