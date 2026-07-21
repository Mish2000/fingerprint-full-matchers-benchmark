from __future__ import annotations

import pytest

from fingerprint_benchmark.sourceafis_sidecar import SidecarStartupError, SourceAfisSidecar, _resolve_java_executable


def test_missing_jar_fails_before_process_start(tmp_path):
    sidecar = SourceAfisSidecar(tmp_path / "missing.jar")
    with pytest.raises(SidecarStartupError, match="does not exist"):
        sidecar.start()
    assert sidecar.process is None


def test_close_is_idempotent(tmp_path):
    sidecar = SourceAfisSidecar(tmp_path / "missing.jar")
    sidecar.close()
    sidecar.close()
    assert sidecar.process is None


def test_non_jar_artifact_is_rejected(tmp_path):
    artifact = tmp_path / "not-a-jar.jar"
    artifact.write_bytes(b"not a ZIP archive")
    sidecar = SourceAfisSidecar(artifact)
    with pytest.raises(SidecarStartupError, match="valid JAR"):
        sidecar.start()
    assert sidecar.jar_sha256 is None


def test_conda_java_launcher_resolves_to_managed_jvm(tmp_path):
    launcher = tmp_path / "Library" / "bin" / "java.exe"
    runtime = tmp_path / "Library" / "lib" / "jvm" / "bin" / "java.exe"
    launcher.parent.mkdir(parents=True)
    runtime.parent.mkdir(parents=True)
    launcher.write_bytes(b"launcher")
    runtime.write_bytes(b"runtime")
    assert _resolve_java_executable(str(launcher)) == str(runtime)
