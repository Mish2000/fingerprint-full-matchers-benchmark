"""Matcher adapter for official SourceAFIS encoded-image processing."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Mapping

from .contract import CompareOutcome, MethodMetadata, PrepareOutcome, PreparedRepresentation
from .sourceafis_client import SOURCEAFIS_VERSION, SourceAfisClient, SourceAfisClientError


class SourceAfisAdapter:
    metadata = MethodMetadata(method_id="sourceafis", method_version=SOURCEAFIS_VERSION)

    def __init__(self, client: SourceAfisClient):
        self._client = client

    def prepare(self, image_path: Path, image_metadata: Mapping[str, Any]) -> PrepareOutcome:
        started = time.perf_counter()
        try:
            dpi = int(image_metadata["nominal_ppi"])
            if dpi not in (1000, 2000):
                raise ValueError("nominal_ppi must be 1000 or 2000")
            encoded = Path(image_path).read_bytes()
            extracted = self._client.extract_template(encoded, dpi)
            return PrepareOutcome(
                status="ok",
                representation=PreparedRepresentation(extracted.payload, extracted.format_id, extracted.format_version),
                wall_ms=(time.perf_counter() - started) * 1000,
                internal_ms=extracted.elapsed_ms,
            )
        except SourceAfisClientError as exc:
            return PrepareOutcome(status="error", error_code=exc.code, error_message=str(exc), wall_ms=(time.perf_counter() - started) * 1000)
        except (OSError, KeyError, TypeError, ValueError) as exc:
            return PrepareOutcome(status="error", error_code="invalid_image_input", error_message=str(exc), wall_ms=(time.perf_counter() - started) * 1000)

    def compare(self, representation_a: PreparedRepresentation, representation_b: PreparedRepresentation) -> CompareOutcome:
        started = time.perf_counter()
        try:
            expected = ("sourceafis", SOURCEAFIS_VERSION)
            if (representation_a.format_id, representation_a.format_version) != expected or (representation_b.format_id, representation_b.format_version) != expected:
                raise ValueError("SourceAFIS template identity/version mismatch")
            verification = self._client.verify(representation_a.payload, representation_b.payload)
            return CompareOutcome(status="ok", raw_score=verification.score, wall_ms=(time.perf_counter() - started) * 1000, internal_ms=verification.elapsed_ms)
        except SourceAfisClientError as exc:
            return CompareOutcome(status="error", error_code=exc.code, error_message=str(exc), wall_ms=(time.perf_counter() - started) * 1000)
        except (TypeError, ValueError) as exc:
            return CompareOutcome(status="error", error_code="invalid_template", error_message=str(exc), wall_ms=(time.perf_counter() - started) * 1000)

    def close(self) -> None:
        self._client.close()
