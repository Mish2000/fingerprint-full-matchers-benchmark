"""Persistent loopback client for the narrow SourceAFIS sidecar contract."""

from __future__ import annotations

import base64
import http.client
import json
import math
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

CONTRACT_VERSION = "sourceafis-sidecar-contract-v1"
IMPLEMENTATION_VERSION = "1.0.0"
SOURCEAFIS_VERSION = "3.18.1"
SOURCEAFIS_COORDINATES = "com.machinezoo.sourceafis:sourceafis:3.18.1"
TEMPLATE_FORMAT = "sourceafis"
TEMPLATE_VERSION = "3.18.1"


class SourceAfisClientError(RuntimeError):
    def __init__(self, code: str, message: str, status: int | None = None):
        super().__init__(message)
        self.code = code
        self.status = status


@dataclass(frozen=True)
class ExtractedTemplate:
    payload: bytes
    format_id: str
    format_version: str
    elapsed_ms: float


@dataclass(frozen=True)
class Verification:
    score: float
    elapsed_ms: float


def _validate_loopback_url(base_url: str) -> tuple[str, int]:
    parsed = urlparse(base_url)
    if parsed.scheme != "http" or parsed.path not in ("", "/") or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("sidecar URL must be a plain loopback HTTP origin")
    if parsed.hostname not in {"127.0.0.1", "localhost", "::1"} or parsed.port is None:
        raise ValueError("sidecar must use a loopback host and explicit port")
    return parsed.hostname, parsed.port


class SourceAfisClient:
    def __init__(self, base_url: str, timeout_seconds: float = 30.0):
        host, port = _validate_loopback_url(base_url)
        self._connection = http.client.HTTPConnection(host, port, timeout=timeout_seconds)
        self._closed = False

    def close(self) -> None:
        if not self._closed:
            self._connection.close()
            self._closed = True

    def __enter__(self) -> "SourceAfisClient":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _request_json(self, method: str, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        if self._closed:
            raise SourceAfisClientError("client_closed", "SourceAFIS client is closed")
        body = None if payload is None else json.dumps(payload, separators=(",", ":"), allow_nan=False).encode("utf-8")
        headers = {"Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        try:
            self._connection.request(method, path, body=body, headers=headers)
            response = self._connection.getresponse()
            data = response.read()
        except (OSError, http.client.HTTPException) as exc:
            self._connection.close()
            raise SourceAfisClientError("transport_error", str(exc)) from exc
        try:
            decoded = json.loads(data.decode("utf-8")) if data else {}
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SourceAfisClientError("invalid_response", "sidecar returned invalid JSON", response.status) from exc
        if not isinstance(decoded, dict):
            raise SourceAfisClientError("invalid_response", "sidecar response must be a JSON object", response.status)
        if response.status >= 400:
            raise SourceAfisClientError(str(decoded.get("error_code", "http_error")), str(decoded.get("message", "sidecar request failed")), response.status)
        return decoded

    def health(self) -> dict[str, Any]:
        health = self._request_json("GET", "/health")
        expected = {
            "status": "ok", "service": "sourceafis-sidecar", "method_id": "sourceafis",
            "sourceafis_version": SOURCEAFIS_VERSION, "sourceafis_maven_coordinates": SOURCEAFIS_COORDINATES,
            "contract_version": CONTRACT_VERSION, "implementation_version": IMPLEMENTATION_VERSION,
            "template_format": TEMPLATE_FORMAT, "template_version": TEMPLATE_VERSION,
            "transport": "loopback-http-json", "external_preprocessing": "none",
            "decision_logic": "none", "thresholding": "none", "template_cache": False,
            "identification_supported": False,
            "supported_operations": ["template_extraction", "pairwise_verification"],
        }
        for key, value in expected.items():
            if health.get(key) != value:
                raise SourceAfisClientError("health_contract_mismatch", f"unexpected health field {key}")
        required = ("java_runtime_version", "bind_host", "bind_port", "dpi_policy", "timing_scopes")
        if any(key not in health for key in required):
            raise SourceAfisClientError("health_contract_mismatch", "health response is incomplete")
        return health

    def extract_template(self, image_bytes: bytes, dpi: int) -> ExtractedTemplate:
        if dpi not in (1000, 2000):
            raise SourceAfisClientError("invalid_dpi", "DPI must be 1000 or 2000")
        response = self._request_json("POST", "/extract-template", {
            "image_base64": base64.b64encode(image_bytes).decode("ascii"), "dpi": dpi,
        })
        try:
            payload = base64.b64decode(response["template_base64"], validate=True)
            format_id = str(response["template_format"])
            format_version = str(response["template_version"])
            elapsed = float(response["elapsed_ms"])
        except (KeyError, TypeError, ValueError) as exc:
            raise SourceAfisClientError("invalid_response", "invalid extraction response") from exc
        if not payload or format_id != TEMPLATE_FORMAT or format_version != TEMPLATE_VERSION or not math.isfinite(elapsed) or elapsed < 0:
            raise SourceAfisClientError("invalid_response", "invalid extraction response values")
        return ExtractedTemplate(payload, format_id, format_version, elapsed)

    def verify(self, template_a: bytes, template_b: bytes) -> Verification:
        response = self._request_json("POST", "/verify", {
            "template_a_base64": base64.b64encode(template_a).decode("ascii"),
            "template_b_base64": base64.b64encode(template_b).decode("ascii"),
        })
        try:
            score, elapsed = float(response["raw_score"]), float(response["elapsed_ms"])
        except (KeyError, TypeError, ValueError) as exc:
            raise SourceAfisClientError("invalid_response", "invalid verification response") from exc
        if not math.isfinite(score) or not math.isfinite(elapsed) or elapsed < 0:
            raise SourceAfisClientError("invalid_response", "verification values must be finite")
        return Verification(score, elapsed)
