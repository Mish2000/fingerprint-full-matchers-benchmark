"""Prepare the dataset-independent NBIS 1000-to-500 PPI audit workspace.

This tool deliberately does not download documents, open images, execute NBIS,
or choose pixel semantics.  It creates a deterministic audit plan and synthetic
matrices that can be used to distinguish candidate interpretations once the
official evidence has been reviewed.
"""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path
from typing import Any


AUDIT_ID = "nbis_1000_ppi_downsampler_v1"
PREREQUISITE_ID = "NBIS_1000_PPI_DOWNSAMPLER_CONFORMANCE_V1"
AUDIT_VERSION = 1
SEEDS = (0, 1, 7839, 500289, 500306)
WORKSPACE_DIRECTORIES = (
    "official-documents",
    "official-software",
    "reference-material",
    "synthetic-vectors",
    "independent-implementation-a",
    "independent-implementation-b",
    "results",
    "logs",
    "receipts",
)
PIXEL_SEMANTIC_FIELDS = (
    "gaussian_sigma",
    "filter_radius",
    "kernel_dimensions",
    "coefficient_generation_formula",
    "kernel_separability",
    "normalization_rule",
    "coefficient_precision",
    "numeric_representation",
    "accumulation_precision",
    "intermediate_rounding",
    "output_rounding",
    "clipping_or_saturation",
    "border_extension_rule",
    "corner_handling",
    "repeated_edge_vs_reflection",
    "mirrored_pixel_semantics",
    "decimation_order",
    "row_parity",
    "column_parity",
    "coordinate_origin",
    "filter_before_decimation",
    "output_width",
    "output_height",
    "even_input_dimensions",
    "odd_input_dimensions",
    "input_smaller_than_kernel",
    "accepted_bit_depth",
    "accepted_color_model",
    "output_bit_depth",
    "output_ppi_metadata",
    "png_metadata_treatment",
    "alpha_channel_treatment",
    "compression_scope",
    "jpeg2000_relationship",
    "conformance_metric",
    "conformance_tolerance",
    "certification_submission_procedure",
    "certification_pathway_availability",
)
CRITICAL_PIXEL_SEMANTICS = (
    "coefficient_precision",
    "normalization_rule",
    "border_extension_rule",
    "output_rounding",
    "clipping_or_saturation",
    "row_parity",
    "column_parity",
    "odd_input_dimensions",
)
VECTOR_PURPOSES = (
    "all_zeros",
    "all_255",
    "constant_mid_gray",
    "impulse_center",
    "impulse_top_left",
    "impulse_top_right",
    "impulse_bottom_left",
    "impulse_bottom_right",
    "impulse_adjacent_top",
    "impulse_adjacent_bottom",
    "impulse_adjacent_left",
    "impulse_adjacent_right",
    "horizontal_gradient",
    "vertical_gradient",
    "two_dimensional_gradient",
    "horizontal_alternating_stripes",
    "vertical_alternating_stripes",
    "checkerboard",
    "isolated_zero_in_255",
    "isolated_255_in_zero",
    "clipping_sensitive",
    "rounding_half_sensitive",
    "kernel_sized_9x9",
    "smaller_than_kernel",
    "even_width_even_height",
    "odd_width_odd_height",
    "even_width_odd_height",
    "odd_width_even_height",
    "dimensions_1_through_12",
    "deterministic_pseudorandom",
    "parity_sensitive",
    "border_sensitive",
)


def canonical_json_bytes(value: Any) -> bytes:
    """Return stable, reviewable JSON bytes."""

    return (json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _matrix(width: int, height: int, value: int = 0) -> list[list[int]]:
    if width < 1 or height < 1:
        raise ValueError("synthetic matrix dimensions must be positive")
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 255:
        raise ValueError("synthetic matrix value must be an unsigned 8-bit integer")
    return [[value for _ in range(width)] for _ in range(height)]


def synthetic_matrix(purpose: str, width: int, height: int, *, seed: int = 0) -> list[list[int]]:
    """Build a deterministic non-biometric matrix for a named diagnostic purpose."""

    rows = _matrix(width, height)
    if purpose == "all_zeros":
        return rows
    if purpose == "all_255":
        return _matrix(width, height, 255)
    if purpose == "constant_mid_gray":
        return _matrix(width, height, 127)
    if purpose.startswith("impulse_"):
        locations = {
            "impulse_center": (height // 2, width // 2),
            "impulse_top_left": (0, 0),
            "impulse_top_right": (0, width - 1),
            "impulse_bottom_left": (height - 1, 0),
            "impulse_bottom_right": (height - 1, width - 1),
            "impulse_adjacent_top": (min(1, height - 1), width // 2),
            "impulse_adjacent_bottom": (max(0, height - 2), width // 2),
            "impulse_adjacent_left": (height // 2, min(1, width - 1)),
            "impulse_adjacent_right": (height // 2, max(0, width - 2)),
        }
        if purpose not in locations:
            raise ValueError(f"unsupported impulse purpose: {purpose}")
        row, column = locations[purpose]
        rows[row][column] = 255
        return rows
    if purpose == "horizontal_gradient":
        denominator = max(1, width - 1)
        return [[(255 * column) // denominator for column in range(width)] for _ in range(height)]
    if purpose == "vertical_gradient":
        denominator = max(1, height - 1)
        return [[(255 * row) // denominator for _ in range(width)] for row in range(height)]
    if purpose == "two_dimensional_gradient":
        denominator = max(1, width + height - 2)
        return [
            [(255 * (row + column)) // denominator for column in range(width)]
            for row in range(height)
        ]
    if purpose == "horizontal_alternating_stripes":
        return [[255 if row % 2 else 0 for _ in range(width)] for row in range(height)]
    if purpose == "vertical_alternating_stripes":
        return [[255 if column % 2 else 0 for column in range(width)] for _ in range(height)]
    if purpose == "checkerboard":
        return [[255 if (row + column) % 2 else 0 for column in range(width)] for row in range(height)]
    if purpose == "isolated_zero_in_255":
        rows = _matrix(width, height, 255)
        rows[height // 2][width // 2] = 0
        return rows
    if purpose in {"isolated_255_in_zero", "clipping_sensitive", "rounding_half_sensitive"}:
        rows[height // 2][width // 2] = 255
        if purpose == "clipping_sensitive" and width * height > 1:
            rows[0][0] = 254
        if purpose == "rounding_half_sensitive" and width * height > 1:
            rows[0][0] = 1
        return rows
    if purpose in {"parity_sensitive", "border_sensitive"}:
        return [
            [((row + 1) * 47 + (column + 1) * 83 + row * column * 19) % 256 for column in range(width)]
            for row in range(height)
        ]
    if purpose == "deterministic_pseudorandom":
        generator = random.Random(seed)
        return [[generator.randrange(256) for _ in range(width)] for _ in range(height)]
    raise ValueError(f"unsupported synthetic purpose: {purpose}")


def parity_decimation(rows: list[list[int]], row_start: int, column_start: int) -> list[list[int]]:
    """Diagnostic sampler for comparing four zero-based parity hypotheses."""

    if row_start not in (0, 1) or column_start not in (0, 1):
        raise ValueError("parity starts must be zero or one")
    return [row[column_start::2] for row in rows[row_start::2]]


def border_index(index: int, length: int, mode: str) -> int | None:
    """Map one coordinate under explicit candidate border semantics.

    These definitions are diagnostic hypotheses only.  Their presence does not
    select any mode as NIST-conformant.
    """

    if length < 1:
        raise ValueError("length must be positive")
    if 0 <= index < length:
        return index
    if mode == "zero_padding":
        return None
    if mode == "edge_replication":
        return 0 if index < 0 else length - 1
    if length == 1:
        return 0
    if mode == "reflect_repeated_edge":
        period = 2 * length
        position = index % period
        return position if position < length else period - 1 - position
    if mode == "reflect_101":
        period = 2 * (length - 1)
        position = index % period
        return position if position < length else period - position
    if mode == "symmetric_mirroring":
        # A separately testable repeated reversed-tile hypothesis.  It is kept
        # explicit because historical prose can use "mirror" ambiguously.
        if index < 0:
            return (-index - 1) % length
        return (2 * length - 1 - index) % length
    if mode == "periodic_wrapping":
        return index % length
    raise ValueError(f"unsupported diagnostic border mode: {mode}")


def audit_plan() -> dict[str, Any]:
    """Return the immutable, dataset-independent plan for this audit version."""

    dimension_cases = [
        {"width": width, "height": height}
        for width, height in (
            (1, 1), (2, 2), (3, 3), (8, 8), (9, 9), (10, 10), (11, 11),
            (8, 9), (9, 8), (10, 11), (11, 10),
        )
    ]
    return {
        "audit_id": AUDIT_ID,
        "audit_version": AUDIT_VERSION,
        "prerequisite_id": PREREQUISITE_ID,
        "biometric_input_allowed": False,
        "dataset_access_allowed": False,
        "matcher_execution_allowed": False,
        "official_source_policy": "NIST_OFFICIAL_ONLY",
        "pixel_semantic_fields": list(PIXEL_SEMANTIC_FIELDS),
        "critical_pixel_semantics": list(CRITICAL_PIXEL_SEMANTICS),
        "fixed_random_seeds": list(SEEDS),
        "required_vector_purposes": list(VECTOR_PURPOSES),
        "dimension_cases": dimension_cases,
        "fresh_process_repetitions": 3,
        "required_platforms": ["WINDOWS_PROJECT_PYTHON", "GITHUB_ACTIONS_PYTHON_3_11"],
        "decision_rule": {
            "resolved": "all critical pixel semantics are authoritative or decided by an official NIST oracle",
            "unresolved": "at least one output-affecting critical semantic lacks authoritative evidence and no official NIST oracle decides it",
        },
    }


def prepare_workspace(workspace_root: Path) -> Path:
    """Create the external evidence layout and deterministic audit plan."""

    root = Path(workspace_root).resolve()
    root.mkdir(parents=True, exist_ok=True)
    for directory in WORKSPACE_DIRECTORIES:
        (root / directory).mkdir(exist_ok=True)
    plan_path = root / "audit_plan.json"
    plan_path.write_bytes(canonical_json_bytes(audit_plan()))
    return plan_path


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace-root", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    plan_path = prepare_workspace(arguments.workspace_root)
    print(f"Prepared dataset-independent audit workspace: {plan_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
