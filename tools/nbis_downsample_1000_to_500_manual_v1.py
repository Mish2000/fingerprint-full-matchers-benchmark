"""Deterministic project-local 1000-to-500 PPI matrix downsampler.

This is a manually selected project policy.  It is not an official NIST
reference implementation and does not change the UNRESOLVED result of the
NBIS 1000 PPI downsampler conformance audit.
"""

from __future__ import annotations

from collections.abc import Sequence


POLICY_ID = "NBIS_1000_TO_500_MANUAL_POLICY_V1"
POLICY_VERSION = 1
SIGMA_DECIMAL = "0.8475"
RADIUS = 4
Q31_SCALE = 1 << 31
KERNEL_Q31 = (
    14706,
    1922071,
    62430569,
    503934447,
    1010880062,
    503934447,
    62430569,
    1922071,
    14706,
)
BORDER_RULE = "EDGE_REPLICATION"
ROW_START_ZERO_BASED = 1
COLUMN_START_ZERO_BASED = 1
OUTPUT_ROUNDING = "TRUNCATE_NONNEGATIVE_FIXED_POINT"
CLIPPING_RULE = "CLAMP_TO_U8_AFTER_TRUNCATION"
_DENOMINATOR = Q31_SCALE * Q31_SCALE


def _validate_input(input_rows: Sequence[Sequence[int]]) -> tuple[tuple[int, ...], ...]:
    if isinstance(input_rows, (str, bytes)) or not isinstance(input_rows, Sequence):
        raise TypeError("input_rows must be a sequence of rows")
    if len(input_rows) == 0:
        raise ValueError("input_rows must not be empty")

    validated: list[tuple[int, ...]] = []
    width: int | None = None
    for row in input_rows:
        if isinstance(row, (str, bytes)) or not isinstance(row, Sequence):
            raise TypeError("each row must be a sequence")
        if width is None:
            width = len(row)
            if width == 0:
                raise ValueError("input rows must not be empty")
        elif len(row) != width:
            raise ValueError("input matrix must be rectangular")

        checked_row: list[int] = []
        for value in row:
            if not isinstance(value, int) or isinstance(value, bool):
                raise TypeError("input pixels must be integers")
            if not 0 <= value <= 255:
                raise ValueError("input pixels must be in the range 0..255")
            checked_row.append(value)
        validated.append(tuple(checked_row))
    return tuple(validated)


def _clamp_index(index: int, length: int) -> int:
    if index < 0:
        return 0
    if index >= length:
        return length - 1
    return index


def output_shape(input_width: int, input_height: int) -> tuple[int, int]:
    """Return ``(width, height)`` for the fixed zero-based odd origin."""

    for name, value in (("input_width", input_width), ("input_height", input_height)):
        if not isinstance(value, int) or isinstance(value, bool):
            raise TypeError(f"{name} must be an integer")
        if value < 1:
            raise ValueError(f"{name} must be positive")
    return input_width // 2, input_height // 2


def downsample_u8_matrix(input_rows: Sequence[Sequence[int]]) -> list[list[int]]:
    """Downsample a rectangular unsigned-byte matrix under the manual policy.

    The implementation performs exact integer convolution with a frozen Q31
    separable kernel.  Horizontal sums are deliberately left unscaled before
    the vertical pass, so only one final truncating division is performed.
    """

    rows = _validate_input(input_rows)
    height = len(rows)
    width = len(rows[0])
    selected_columns = tuple(range(COLUMN_START_ZERO_BASED, width, 2))

    horizontal: list[list[int]] = []
    for row in rows:
        filtered_row: list[int] = []
        for source_column in selected_columns:
            total = 0
            for kernel_index, coefficient in enumerate(KERNEL_Q31):
                offset = kernel_index - RADIUS
                column = _clamp_index(source_column + offset, width)
                total += row[column] * coefficient
            filtered_row.append(total)
        horizontal.append(filtered_row)

    output: list[list[int]] = []
    for source_row in range(ROW_START_ZERO_BASED, height, 2):
        output_row: list[int] = []
        for output_column in range(len(selected_columns)):
            total = 0
            for kernel_index, coefficient in enumerate(KERNEL_Q31):
                offset = kernel_index - RADIUS
                row = _clamp_index(source_row + offset, height)
                total += horizontal[row][output_column] * coefficient
            value = total // _DENOMINATOR
            output_row.append(min(255, max(0, value)))
        output.append(output_row)
    return output


__all__ = [
    "BORDER_RULE",
    "CLIPPING_RULE",
    "COLUMN_START_ZERO_BASED",
    "KERNEL_Q31",
    "OUTPUT_ROUNDING",
    "POLICY_ID",
    "POLICY_VERSION",
    "Q31_SCALE",
    "RADIUS",
    "ROW_START_ZERO_BASED",
    "SIGMA_DECIMAL",
    "downsample_u8_matrix",
    "output_shape",
]
