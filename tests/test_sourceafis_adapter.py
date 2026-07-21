from __future__ import annotations

from fingerprint_benchmark.contract import PreparedRepresentation
from fingerprint_benchmark.sourceafis_adapter import SourceAfisAdapter
from fingerprint_benchmark.sourceafis_client import ExtractedTemplate, SourceAfisClientError, Verification


class FakeClient:
    def __init__(self):
        self.extract_calls = []
        self.verify_calls = []
        self.closed = False

    def extract_template(self, data, dpi):
        self.extract_calls.append((data, dpi))
        return ExtractedTemplate(b"template", "sourceafis", "3.18.1", 1.25)

    def verify(self, a, b):
        self.verify_calls.append((a, b))
        return Verification(0.0, 2.5)

    def close(self):
        self.closed = True


def test_adapter_passes_original_encoded_bytes_and_explicit_ppi(tmp_path):
    image = tmp_path / "encoded.bin"
    image.write_bytes(b"encoded-exactly")
    client = FakeClient()
    outcome = SourceAfisAdapter(client).prepare(image, {"nominal_ppi": 2000})
    assert outcome.status == "ok"
    assert client.extract_calls == [(b"encoded-exactly", 2000)]


def test_adapter_does_not_infer_ppi_from_image(tmp_path):
    image = tmp_path / "image.png"
    image.write_bytes(b"metadata-is-never-read")
    client = FakeClient()
    outcome = SourceAfisAdapter(client).prepare(image, {})
    assert outcome.status == "error"
    assert client.extract_calls == []


def test_adapter_rejects_unapproved_ppi(tmp_path):
    image = tmp_path / "image.bin"
    image.write_bytes(b"x")
    assert SourceAfisAdapter(FakeClient()).prepare(image, {"nominal_ppi": 500}).error_code == "invalid_image_input"


def test_adapter_verifies_templates_and_preserves_zero_score():
    client = FakeClient()
    adapter = SourceAfisAdapter(client)
    representation = PreparedRepresentation(b"template", "sourceafis", "3.18.1")
    outcome = adapter.compare(representation, representation)
    assert outcome.status == "ok" and outcome.raw_score == 0.0
    assert client.verify_calls == [(b"template", b"template")]


def test_adapter_rejects_template_version_mismatch():
    adapter = SourceAfisAdapter(FakeClient())
    bad = PreparedRepresentation(b"template", "sourceafis", "other")
    outcome = adapter.compare(bad, bad)
    assert outcome.status == "error" and outcome.raw_score is None
