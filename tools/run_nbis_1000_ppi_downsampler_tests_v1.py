"""Run only fixed, dataset-independent pytest allowlists.

No positional test paths are accepted.  The audit suite installs an audit hook
before pytest is imported, disables repository conftest loading, and blocks any
attempt to touch the external dataset tree or committed protocol manifests.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
AUDIT_TEST_FILES = (
    "tests/test_nbis_1000_ppi_downsampler_v1.py",
)
PROJECT_TEST_FILES = (
    "tests/test_benchmark_contract.py",
    "tests/test_benchmark_runner.py",
    "tests/test_protocol_manifest_reader.py",
    "tests/test_sourceafis_adapter.py",
    "tests/test_sourceafis_client.py",
    "tests/test_sourceafis_sidecar_lifecycle.py",
    "tests/test_forbidden_runtime_coupling.py",
    "tests/test_sourceafis_runtime_qualification.py",
    "tests/test_sourceafis_decision_policy_v1.py",
    "tests/test_sourceafis_frozen_cohort_v1.py",
    "tests/test_sourceafis_policy_application_v1.py",
)
SUITES = {
    "audit": AUDIT_TEST_FILES,
    "project": PROJECT_TEST_FILES,
}
FORBIDDEN_TEST_FILES = {
    "tests/test_supervisor_50x10_v1.py",
}
FORBIDDEN_DATASET_PARTS = ("fingerprint-datasets", "nist")


class IsolationViolation(RuntimeError):
    """Raised before a prohibited filesystem operation can proceed."""


def _normalized_parts(value: os.PathLike[str] | str) -> tuple[str, ...]:
    try:
        path = Path(os.path.abspath(os.fspath(value)))
    except (OSError, TypeError, ValueError):
        return ()
    return tuple(part.casefold() for part in path.parts)


def path_is_forbidden(value: os.PathLike[str] | str, *, audit_suite: bool) -> bool:
    """Return whether a path crosses an attempt-2 isolation boundary."""

    parts = _normalized_parts(value)
    if not parts:
        return False
    for index in range(len(parts) - 1):
        if parts[index:index + 2] == FORBIDDEN_DATASET_PARTS:
            return True
    if audit_suite:
        protocol_root = tuple(part.casefold() for part in (REPOSITORY_ROOT / "protocols").parts)
        if parts[:len(protocol_root)] == protocol_root:
            return True
    return False


def _install_filesystem_guard(*, audit_suite: bool) -> None:
    guarded_events = {
        "open", "os.chdir", "os.listdir", "os.scandir", "os.stat", "os.remove",
        "os.rename", "os.rmdir", "os.mkdir",
    }

    def guard(event: str, arguments: tuple[Any, ...]) -> None:
        if event not in guarded_events or not arguments:
            return
        candidate = arguments[0]
        if isinstance(candidate, (str, bytes, os.PathLike)) and path_is_forbidden(
            os.fsdecode(candidate), audit_suite=audit_suite
        ):
            raise IsolationViolation(f"prohibited filesystem access blocked before operation: {event}")

    sys.addaudithook(guard)


def validate_allowlist(suite: str) -> tuple[str, ...]:
    """Validate the fixed allowlist before importing pytest."""

    if suite not in SUITES:
        raise IsolationViolation(f"unknown fixed suite: {suite}")
    files = SUITES[suite]
    if not files or len(files) != len(set(files)):
        raise IsolationViolation("test allowlist is empty or contains duplicates")
    if FORBIDDEN_TEST_FILES.intersection(files):
        raise IsolationViolation("dataset-backed supervisor test is forbidden")
    for relative in files:
        if not relative.startswith("tests/") or not relative.endswith(".py"):
            raise IsolationViolation(f"invalid allowlisted test path: {relative}")
        path = (REPOSITORY_ROOT / Path(relative)).resolve(strict=False)
        path.relative_to(REPOSITORY_ROOT)
        if not path.is_file():
            raise IsolationViolation(f"allowlisted test file is missing: {relative}")
    return files


def pytest_arguments(suite: str) -> list[str]:
    files = validate_allowlist(suite)
    arguments = ["-q"]
    if suite == "audit":
        arguments.append("--noconftest")
    arguments.extend(files)
    return arguments


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", choices=tuple(SUITES), default="audit")
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    pytest_args = pytest_arguments(arguments.suite)
    _install_filesystem_guard(audit_suite=arguments.suite == "audit")
    os.environ["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    repository_text = str(REPOSITORY_ROOT)
    if repository_text not in sys.path:
        sys.path.insert(0, repository_text)
    import pytest

    return int(pytest.main(pytest_args))


if __name__ == "__main__":
    raise SystemExit(main())
