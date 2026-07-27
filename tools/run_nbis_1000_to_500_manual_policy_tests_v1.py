"""Run the fixed dataset-independent test file for the manual policy v1."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
FIXED_TEST_FILES = ("tests/test_nbis_1000_to_500_manual_policy_v1.py",)
FORBIDDEN_TEST_FILES = {"tests/test_supervisor_50x10_v1.py"}
FORBIDDEN_DATASET_PARTS = ("fingerprint-datasets", "nist")


class IsolationViolation(RuntimeError):
    """Raised before a prohibited collection or filesystem operation."""


def _parts(value: os.PathLike[str] | str) -> tuple[str, ...]:
    try:
        path = Path(os.path.abspath(os.fspath(value)))
    except (OSError, TypeError, ValueError):
        return ()
    return tuple(part.casefold() for part in path.parts)


def path_is_forbidden(value: os.PathLike[str] | str) -> bool:
    parts = _parts(value)
    for index in range(len(parts) - 1):
        if parts[index:index + 2] == FORBIDDEN_DATASET_PARTS:
            return True
    protocol_parts = tuple(part.casefold() for part in (REPOSITORY_ROOT / "protocols").parts)
    return parts[:len(protocol_parts)] == protocol_parts


def _install_filesystem_guard() -> None:
    guarded_events = {
        "open", "os.chdir", "os.listdir", "os.scandir", "os.stat", "os.remove",
        "os.rename", "os.rmdir", "os.mkdir",
    }

    def guard(event: str, arguments: tuple[Any, ...]) -> None:
        if event not in guarded_events or not arguments:
            return
        candidate = arguments[0]
        if isinstance(candidate, (str, bytes, os.PathLike)) and path_is_forbidden(
            os.fsdecode(candidate)
        ):
            raise IsolationViolation(f"prohibited filesystem access blocked: {event}")

    sys.addaudithook(guard)


def pytest_arguments() -> list[str]:
    if not FIXED_TEST_FILES or len(FIXED_TEST_FILES) != len(set(FIXED_TEST_FILES)):
        raise IsolationViolation("fixed test allowlist is empty or contains duplicates")
    if FORBIDDEN_TEST_FILES.intersection(FIXED_TEST_FILES):
        raise IsolationViolation("dataset-backed supervisor test is forbidden")
    for relative in FIXED_TEST_FILES:
        if not relative.startswith("tests/") or not relative.endswith(".py"):
            raise IsolationViolation(f"invalid fixed test path: {relative}")
        path = (REPOSITORY_ROOT / relative).resolve(strict=False)
        path.relative_to(REPOSITORY_ROOT)
        if not path.is_file():
            raise IsolationViolation(f"fixed test file is missing: {relative}")
    return ["-q", "--noconftest", *FIXED_TEST_FILES]


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if argv:
        raise IsolationViolation("this runner accepts no command-line test paths or options")
    arguments = pytest_arguments()
    _install_filesystem_guard()
    os.environ["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    repository_text = str(REPOSITORY_ROOT)
    if repository_text not in sys.path:
        sys.path.insert(0, repository_text)
    import pytest

    return int(pytest.main(arguments))


if __name__ == "__main__":
    raise SystemExit(main())
