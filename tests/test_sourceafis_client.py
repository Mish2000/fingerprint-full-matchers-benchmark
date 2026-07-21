from __future__ import annotations

import json
import math
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from fingerprint_benchmark.sourceafis_client import SourceAfisClient, SourceAfisClientError


HEALTH = {
    "status": "ok", "service": "sourceafis-sidecar", "method_id": "sourceafis",
    "sourceafis_version": "3.18.1", "sourceafis_maven_coordinates": "com.machinezoo.sourceafis:sourceafis:3.18.1",
    "contract_version": "sourceafis-sidecar-contract-v1", "implementation_version": "1.0.0",
    "template_format": "sourceafis", "template_version": "3.18.1",
    "transport": "loopback-http-json", "external_preprocessing": "none", "decision_logic": "none",
    "thresholding": "none", "template_cache": False, "identification_supported": False,
    "supported_operations": ["template_extraction", "pairwise_verification"],
    "java_runtime_version": "17-test", "bind_host": "127.0.0.1", "bind_port": 0,
    "dpi_policy": "explicit", "timing_scopes": {},
}


@pytest.fixture
def sidecar_server():
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_): pass

        def _send(self, status, value):
            body = json.dumps(value, allow_nan=True).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            self._send(200, HEALTH if self.path == "/health" else {})

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            json.loads(self.rfile.read(length))
            if self.path == "/extract-template":
                self._send(200, {"template_base64": "dGVtcGxhdGU=", "template_format": "sourceafis", "template_version": "3.18.1", "elapsed_ms": 1.0})
            elif self.path == "/verify":
                self._send(200, {"raw_score": 12.5, "elapsed_ms": 2.0})
            else:
                self._send(422, {"error_code": "bad_input", "message": "rejected"})

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()


def test_client_restricts_transport_to_loopback():
    with pytest.raises(ValueError):
        SourceAfisClient("http://example.com:80")


def test_health_contract_and_persistent_connection(sidecar_server):
    client = SourceAfisClient(sidecar_server)
    connection = client._connection
    assert client.health()["sourceafis_version"] == "3.18.1"
    assert client.health()["status"] == "ok"
    assert client._connection is connection
    client.close()


def test_extract_and_verify_return_official_values(sidecar_server):
    with SourceAfisClient(sidecar_server) as client:
        template = client.extract_template(b"encoded", 1000)
        verification = client.verify(template.payload, template.payload)
    assert template.payload == b"template"
    assert verification.score == 12.5


def test_client_rejects_invalid_dpi_before_transport(sidecar_server):
    with SourceAfisClient(sidecar_server) as client:
        with pytest.raises(SourceAfisClientError, match="DPI"):
            client.extract_template(b"x", 500)


def test_structured_sidecar_error_is_preserved(sidecar_server):
    with SourceAfisClient(sidecar_server) as client:
        with pytest.raises(SourceAfisClientError) as captured:
            client._request_json("POST", "/error", {})
    assert captured.value.code == "bad_input" and captured.value.status == 422
