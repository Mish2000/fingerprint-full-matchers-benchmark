"""Synthetic and isolation tests for the project-local manual policy v1."""

from __future__ import annotations

import ast
import importlib.util
import json
import os
import random
import subprocess
import sys
from decimal import Decimal, ROUND_HALF_EVEN, localcontext
from pathlib import Path

import pytest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
TOOLS_ROOT = REPOSITORY_ROOT / "tools"


def _load(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, REPOSITORY_ROOT / relative)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


canonical = _load("manual_downsampler", "tools/nbis_downsample_1000_to_500_manual_v1.py")
reference = _load(
    "manual_downsampler_reference",
    "tools/nbis_downsample_1000_to_500_manual_reference_v1.py",
)
validator = _load(
    "manual_downsampler_validator",
    "tools/validate_nbis_1000_to_500_manual_policy_v1.py",
)
runner = _load(
    "manual_downsampler_runner",
    "tools/run_nbis_1000_to_500_manual_policy_tests_v1.py",
)
audit_validator = _load(
    "prior_downsampler_audit_validator",
    "tools/validate_nbis_1000_ppi_downsampler_v1.py",
)


def _random_matrix(width: int, height: int, seed: int) -> list[list[int]]:
    generator = random.Random(seed)
    return [[generator.randrange(256) for _ in range(width)] for _ in range(height)]


def test_policy_identity_and_integer_kernel_are_locked() -> None:
    assert canonical.POLICY_ID == "NBIS_1000_TO_500_MANUAL_POLICY_V1"
    assert canonical.POLICY_VERSION == 1
    assert canonical.SIGMA_DECIMAL == "0.8475"
    assert canonical.RADIUS == 4
    assert canonical.Q31_SCALE == 1 << 31
    assert sum(canonical.KERNEL_Q31) == canonical.Q31_SCALE
    assert canonical.KERNEL_Q31 == tuple(reversed(canonical.KERNEL_Q31))
    assert reference.KERNEL_Q31 == canonical.KERNEL_Q31


def test_frozen_kernel_reconstructs_from_documented_decimal_rule() -> None:
    with localcontext() as context:
        context.prec = 80
        sigma = Decimal(canonical.SIGMA_DECIMAL)
        unnormalized = [
            (-(Decimal(offset * offset) / (2 * sigma * sigma))).exp()
            for offset in range(-canonical.RADIUS, canonical.RADIUS + 1)
        ]
        total = sum(unnormalized)
        quantized = [
            int((value / total * canonical.Q31_SCALE).to_integral_value(rounding=ROUND_HALF_EVEN))
            for value in unnormalized
        ]
        quantized[canonical.RADIUS] += canonical.Q31_SCALE - sum(quantized)
    assert tuple(quantized) == canonical.KERNEL_Q31


def test_policy_choices_are_explicit() -> None:
    assert canonical.BORDER_RULE == "EDGE_REPLICATION"
    assert canonical.ROW_START_ZERO_BASED == 1
    assert canonical.COLUMN_START_ZERO_BASED == 1
    assert canonical.OUTPUT_ROUNDING == "TRUNCATE_NONNEGATIVE_FIXED_POINT"
    assert canonical.CLIPPING_RULE == "CLAMP_TO_U8_AFTER_TRUNCATION"


@pytest.mark.parametrize(
    ("width", "height", "expected"),
    [
        (1, 1, (0, 0)),
        (2, 2, (1, 1)),
        (3, 3, (1, 1)),
        (8, 9, (4, 4)),
        (9, 8, (4, 4)),
        (11, 11, (5, 5)),
    ],
)
def test_output_shape_is_floor_half(width: int, height: int, expected: tuple[int, int]) -> None:
    assert canonical.output_shape(width, height) == expected


def test_one_pixel_dimensions_have_explicit_zero_sized_outputs() -> None:
    assert canonical.downsample_u8_matrix([[17]]) == []
    assert canonical.downsample_u8_matrix([[17], [23], [42]]) == [[],]
    assert canonical.downsample_u8_matrix([[17, 23, 42]]) == []


@pytest.mark.parametrize("value", [0, 1, 63, 127, 128, 254, 255])
def test_constant_matrices_remain_constant(value: int) -> None:
    matrix = [[value] * 11 for _ in range(9)]
    expected = [[value] * 5 for _ in range(4)]
    assert canonical.downsample_u8_matrix(matrix) == expected
    assert reference.downsample_u8_matrix(matrix) == expected


def test_small_hand_locked_examples() -> None:
    assert canonical.downsample_u8_matrix([[0, 1], [2, 3]]) == [[2]]
    assert canonical.downsample_u8_matrix([[0, 1, 2], [3, 4, 5], [6, 7, 8]]) == [[4]]
    impulse = [[0] * 5 for _ in range(5)]
    impulse[2][2] = 255
    assert canonical.downsample_u8_matrix(impulse) == [[14, 14], [14, 14]]


def test_zero_based_odd_parity_and_edge_replication_are_observable() -> None:
    vertical = [[255 if column % 2 else 0 for column in range(8)] for _ in range(8)]
    assert canonical.downsample_u8_matrix(vertical) == [
        [127, 134, 135, 194],
        [127, 134, 135, 194],
        [127, 134, 135, 194],
        [127, 134, 135, 194],
    ]


@pytest.mark.parametrize("width", range(1, 13))
@pytest.mark.parametrize("height", range(1, 13))
def test_independent_implementations_agree_for_dimension_grid(width: int, height: int) -> None:
    matrix = _random_matrix(width, height, seed=width * 1000 + height)
    actual = canonical.downsample_u8_matrix(matrix)
    assert actual == reference.downsample_u8_matrix(matrix)
    assert len(actual) == height // 2
    assert all(len(row) == width // 2 for row in actual)
    assert all(0 <= value <= 255 for row in actual for value in row)


@pytest.mark.parametrize("seed", [0, 1, 7839, 500289, 500306])
def test_fixed_seed_random_matrices_agree(seed: int) -> None:
    matrix = _random_matrix(17, 15, seed)
    assert canonical.downsample_u8_matrix(matrix) == reference.downsample_u8_matrix(matrix)


def test_input_is_not_mutated() -> None:
    matrix = _random_matrix(10, 9, 17)
    before = [row[:] for row in matrix]
    canonical.downsample_u8_matrix(matrix)
    assert matrix == before


@pytest.mark.parametrize(
    ("value", "error"),
    [
        ([], ValueError),
        ([[]], ValueError),
        ([[0, 1], [2]], ValueError),
        ([[-1]], ValueError),
        ([[256]], ValueError),
        ([[1.0]], TypeError),
        ([[True]], TypeError),
        ("not-a-matrix", TypeError),
    ],
)
def test_invalid_inputs_are_rejected(value: object, error: type[Exception]) -> None:
    with pytest.raises(error):
        canonical.downsample_u8_matrix(value)  # type: ignore[arg-type]
    with pytest.raises(error):
        reference.downsample_u8_matrix(value)  # type: ignore[arg-type]


def test_tuple_input_is_supported_and_returns_lists() -> None:
    result = canonical.downsample_u8_matrix(((0, 1), (2, 3)))
    assert result == [[2]]
    assert isinstance(result, list) and isinstance(result[0], list)


def test_implementations_are_structurally_independent_and_standard_library_only() -> None:
    canonical_source = (TOOLS_ROOT / "nbis_downsample_1000_to_500_manual_v1.py").read_text(encoding="utf-8")
    reference_source = (
        TOOLS_ROOT / "nbis_downsample_1000_to_500_manual_reference_v1.py"
    ).read_text(encoding="utf-8")
    assert "nbis_downsample_1000_to_500_manual_v1" not in reference_source
    assert "horizontal" in canonical_source
    assert "horizontal" not in reference_source
    forbidden = {"cv2", "numpy", "PIL", "scipy", "skimage"}
    for source in (canonical_source, reference_source):
        tree = ast.parse(source)
        imported = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imported.update(
            node.module.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module
        )
        assert not imported.intersection(forbidden)


def test_three_fresh_processes_are_byte_identical_across_environment_changes(tmp_path: Path) -> None:
    matrix = _random_matrix(12, 11, 500306)
    script = (
        "import json,sys;"
        f"sys.path.insert(0,{str(TOOLS_ROOT)!r});"
        "import nbis_downsample_1000_to_500_manual_v1 as m;"
        f"print(json.dumps(m.downsample_u8_matrix({matrix!r}),separators=(',',':')))"
    )
    outputs: list[bytes] = []
    for index, cwd in enumerate((REPOSITORY_ROOT, tmp_path, TOOLS_ROOT)):
        environment = os.environ.copy()
        environment.update({
            "PYTHONHASHSEED": str(index + 1),
            "TZ": ("UTC", "Asia/Jerusalem", "Pacific/Honolulu")[index],
            "LC_ALL": "C",
        })
        outputs.append(subprocess.check_output(
            [sys.executable, "-c", script], cwd=cwd, env=environment
        ))
    assert outputs[0] == outputs[1] == outputs[2]
    assert json.loads(outputs[0]) == canonical.downsample_u8_matrix(matrix)


def test_manual_policy_package_passes_read_only_validator() -> None:
    assert validator.validate_package(REPOSITORY_ROOT) == []


def test_prior_unresolved_audit_remains_valid_and_unchanged() -> None:
    assert audit_validator.validate_package(REPOSITORY_ROOT) == []
    resolution = json.loads((
        REPOSITORY_ROOT
        / "preprocessing/nbis_1000_ppi_downsampler_v1/prerequisite_resolution.json"
    ).read_text(encoding="utf-8"))
    assert resolution["status"] == "UNRESOLVED"


def test_runner_has_one_fixed_file_and_rejects_user_paths() -> None:
    assert runner.FIXED_TEST_FILES == ("tests/test_nbis_1000_to_500_manual_policy_v1.py",)
    assert runner.pytest_arguments() == [
        "-q", "--noconftest", "tests/test_nbis_1000_to_500_manual_policy_v1.py",
    ]
    with pytest.raises(runner.IsolationViolation):
        runner.main(["tests/test_supervisor_50x10_v1.py"])


def test_runner_blocks_dataset_and_protocol_paths_before_open() -> None:
    dataset_path = Path(Path.cwd().anchor) / "fingerprint-datasets" / "NIST" / "sample.bin"
    protocol_path = REPOSITORY_ROOT / "protocols" / "manifest.csv"
    assert runner.path_is_forbidden(dataset_path)
    assert runner.path_is_forbidden(protocol_path)


def test_dedicated_workflow_is_explicit_and_offline() -> None:
    workflow = (
        REPOSITORY_ROOT / ".github/workflows/nbis-1000-to-500-manual-policy-v1.yml"
    ).read_text(encoding="utf-8").casefold()
    assert "run_nbis_1000_to_500_manual_policy_tests_v1.py" in workflow
    assert "validate_nbis_1000_to_500_manual_policy_v1.py" in workflow
    assert "python -m pytest" not in workflow
    assert "curl " not in workflow and "wget " not in workflow and "wsl.exe" not in workflow
