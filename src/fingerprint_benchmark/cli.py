"""Command line surface for protocol validation and SourceAFIS raw scores."""

from __future__ import annotations

import argparse
import http.client
import json
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse

from .manifest import read_protocol_manifest
from .provenance import collect_provenance
from .runner import run_manifest, validate_result_bundle
from .sourceafis_adapter import SourceAfisAdapter
from .sourceafis_sidecar import SourceAfisSidecar

FIXTURE_BLOCK_REASON = "no permitted tracked non-SD300 fingerprint fixture exists in the audited source repository"


def _print(value: object) -> None:
    print(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False))


def _post_raw(base_url: str, path: str, payload: dict[str, object]) -> int:
    parsed = urlparse(base_url)
    connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=10)
    try:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        connection.request("POST", path, body=body, headers={"Content-Type": "application/json"})
        response = connection.getresponse()
        response.read()
        return response.status
    finally:
        connection.close()


def sourceafis_smoke(jar: Path, java: str) -> dict[str, object]:
    sidecar = SourceAfisSidecar(jar, java_executable=java)
    with sidecar as client:
        health = client.health()
        sidecar_url = f"http://{health['bind_host']}:{health['bind_port']}"
        checks = {
            "health": True,
            "invalid_dpi_rejected": _post_raw(sidecar_url, "/extract-template", {"image_base64": "AA==", "dpi": 500}) not in (200, 404),
            "invalid_image_rejected": _post_raw(sidecar_url, "/extract-template", {"image_base64": "bm90LWFuLWltYWdl", "dpi": 1000}) not in (200, 404),
            "invalid_template_rejected": _post_raw(sidecar_url, "/verify", {"template_a_base64": "AA==", "template_b_base64": "AA=="}) not in (200, 404),
            "removed_raw_route_absent": _post_raw(sidecar_url, "/extract-template-raw", {}) == 404,
            "removed_detector_route_absent": _post_raw(sidecar_url, "/extract-final-minutiae", {}) == 404,
        }
        if not all(checks.values()):
            raise RuntimeError(f"sidecar smoke check failed: {checks}")
        return {
            "status": "BLOCKED", "reason": FIXTURE_BLOCK_REASON,
            "jar_sha256": sidecar.jar_sha256, "dataset_independent_checks": checks,
        }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="fingerprint-benchmark")
    sub = parser.add_subparsers(dest="command", required=True)
    validate = sub.add_parser("validate-protocol")
    validate.add_argument("--protocol-root", required=True, type=Path)
    validate.add_argument("--curation-root", required=True, type=Path)
    validate.add_argument("--dataset-root", required=True, type=Path)
    smoke = sub.add_parser("sourceafis-smoke")
    smoke.add_argument("--jar", required=True, type=Path)
    smoke.add_argument("--java", default="java")
    run = sub.add_parser("run-sourceafis-manifest")
    run.add_argument("--manifest", required=True, type=Path)
    run.add_argument("--dataset-root", required=True, type=Path)
    run.add_argument("--output-root", required=True, type=Path)
    run.add_argument("--jar", required=True, type=Path)
    run.add_argument("--java", default="java")
    run.add_argument("--replace", action="store_true")
    check = sub.add_parser("validate-result-bundle")
    check.add_argument("--bundle", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "validate-protocol":
            validator = Path(__file__).resolve().parents[2] / "tools" / "validate_supervisor_50x10_v1.py"
            completed = subprocess.run([
                sys.executable, str(validator), "--protocol-root", str(args.protocol_root),
                "--curation-root", str(args.curation_root), "--dataset-root", str(args.dataset_root),
            ], check=False)
            return completed.returncode
        elif args.command == "sourceafis-smoke":
            _print(sourceafis_smoke(args.jar, args.java))
        elif args.command == "validate-result-bundle":
            _print(validate_result_bundle(args.bundle))
        elif args.command == "run-sourceafis-manifest":
            manifest = read_protocol_manifest(args.manifest, args.dataset_root)
            sidecar = SourceAfisSidecar(args.jar, java_executable=args.java)
            client = sidecar.start()
            try:
                health = client.health()
                repo_root = Path(__file__).resolve().parents[2]
                implementation = list((repo_root / "src" / "fingerprint_benchmark").glob("*.py"))
                provenance = collect_provenance(
                    repo_root=repo_root, implementation_files=implementation,
                    manifest_sha256=manifest.sha256, protocol_lock_sha256=manifest.protocol_lock_sha256,
                    method_config={"method_id": "sourceafis", "nominal_ppi_source": "manifest"},
                    sidecar_health=health, jar_path=args.jar,
                )
                destination = run_manifest(
                    manifest=manifest, adapter=SourceAfisAdapter(client), output_root=args.output_root,
                    provenance=provenance, replace=args.replace,
                )
                _print({"bundle": str(destination), **validate_result_bundle(destination)})
            finally:
                sidecar.close()
        return 0
    except Exception as exc:
        print(json.dumps({"status": "error", "error_type": type(exc).__name__, "message": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
