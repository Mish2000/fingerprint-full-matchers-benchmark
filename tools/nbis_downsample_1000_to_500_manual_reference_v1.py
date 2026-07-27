"""Structurally independent reference for the local manual downsampler policy."""

from __future__ import annotations

from collections.abc import Sequence


POLICY_ID = "NBIS_1000_TO_500_MANUAL_POLICY_V1"
Q31_SCALE = 2147483648
RADIUS = 4
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


def _copy_and_check(source: Sequence[Sequence[int]]) -> list[list[int]]:
    if isinstance(source, (str, bytes)) or not isinstance(source, Sequence):
        raise TypeError("input_rows must be a sequence of rows")
    if not source:
        raise ValueError("input_rows must not be empty")
    result: list[list[int]] = []
    expected_width = -1
    for source_row in source:
        if isinstance(source_row, (str, bytes)) or not isinstance(source_row, Sequence):
            raise TypeError("each row must be a sequence")
        if expected_width < 0:
            expected_width = len(source_row)
            if expected_width == 0:
                raise ValueError("input rows must not be empty")
        if len(source_row) != expected_width:
            raise ValueError("input matrix must be rectangular")
        copied: list[int] = []
        for sample in source_row:
            if isinstance(sample, bool) or not isinstance(sample, int):
                raise TypeError("input pixels must be integers")
            if sample < 0 or sample > 255:
                raise ValueError("input pixels must be in the range 0..255")
            copied.append(sample)
        result.append(copied)
    return result


def _edge(coordinate: int, extent: int) -> int:
    return min(extent - 1, max(0, coordinate))


def downsample_u8_matrix(input_rows: Sequence[Sequence[int]]) -> list[list[int]]:
    """Evaluate the frozen policy as a direct two-dimensional convolution."""

    pixels = _copy_and_check(input_rows)
    height = len(pixels)
    width = len(pixels[0])
    divisor = Q31_SCALE ** 2
    result: list[list[int]] = []

    for center_y in range(1, height, 2):
        result_row: list[int] = []
        for center_x in range(1, width, 2):
            accumulator = 0
            for y_offset in range(-RADIUS, RADIUS + 1):
                source_y = _edge(center_y + y_offset, height)
                y_weight = KERNEL_Q31[y_offset + RADIUS]
                for x_offset in range(-RADIUS, RADIUS + 1):
                    source_x = _edge(center_x + x_offset, width)
                    x_weight = KERNEL_Q31[x_offset + RADIUS]
                    accumulator += pixels[source_y][source_x] * y_weight * x_weight
            quantized = accumulator // divisor
            if quantized < 0:
                quantized = 0
            elif quantized > 255:
                quantized = 255
            result_row.append(quantized)
        result.append(result_row)
    return result


__all__ = ["KERNEL_Q31", "POLICY_ID", "Q31_SCALE", "RADIUS", "downsample_u8_matrix"]
