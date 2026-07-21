"""Matcher-neutral types with strict score and failure semantics."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Protocol, runtime_checkable

BENCHMARK_CONTRACT_VERSION = "sourceafis-runtime-v1"


class MethodExecutionError(RuntimeError):
    def __init__(self, code: str, message: str):
        if not code:
            raise ValueError("error code is required")
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class MethodMetadata:
    method_id: str
    method_version: str
    score_direction: str = "higher_is_more_similar"
    score_semantics: str = "raw_similarity"

    def __post_init__(self) -> None:
        if not self.method_id or not self.method_version:
            raise ValueError("method identity and version are required")
        if self.score_direction != "higher_is_more_similar":
            raise ValueError("unsupported score direction")
        if self.score_semantics != "raw_similarity":
            raise ValueError("unsupported score semantics")


@dataclass(frozen=True)
class PreparedRepresentation:
    payload: bytes
    format_id: str
    format_version: str

    def __post_init__(self) -> None:
        if not self.payload or not self.format_id or not self.format_version:
            raise ValueError("complete prepared representation is required")


@dataclass(frozen=True)
class PrepareOutcome:
    status: str
    representation: PreparedRepresentation | None = None
    error_code: str | None = None
    error_message: str | None = None
    wall_ms: float | None = None
    internal_ms: float | None = None
    diagnostics: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _validate_outcome(self.status, self.representation is not None, self.error_code)


@dataclass(frozen=True)
class CompareOutcome:
    status: str
    raw_score: float | None = None
    error_code: str | None = None
    error_message: str | None = None
    wall_ms: float | None = None
    internal_ms: float | None = None
    diagnostics: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.status == "ok":
            if self.raw_score is None or not math.isfinite(self.raw_score):
                raise ValueError("successful comparison requires a finite raw score")
            if self.error_code is not None:
                raise ValueError("successful comparison cannot have an error code")
        elif self.raw_score is not None or not self.error_code:
            raise ValueError("failed comparison requires no score and an error code")


def _validate_outcome(status: str, has_value: bool, error_code: str | None) -> None:
    if status == "ok":
        if not has_value or error_code is not None:
            raise ValueError("successful preparation requires a value and no error")
    elif has_value or not error_code:
        raise ValueError("failed preparation requires no value and an error code")


@runtime_checkable
class MatcherAdapter(Protocol):
    metadata: MethodMetadata

    def prepare(self, image_path: Path, image_metadata: Mapping[str, Any]) -> PrepareOutcome: ...

    def compare(
        self, representation_a: PreparedRepresentation, representation_b: PreparedRepresentation
    ) -> CompareOutcome: ...

    def close(self) -> None: ...
