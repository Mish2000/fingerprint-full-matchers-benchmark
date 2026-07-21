"""Managed lifecycle for the SourceAFIS JVM sidecar."""

from __future__ import annotations

import json
import queue
import shutil
import subprocess
import threading
import time
from pathlib import Path

from .hashing import file_sha256
from .sourceafis_client import SourceAfisClient


class SidecarStartupError(RuntimeError):
    pass


class SourceAfisSidecar:
    def __init__(self, jar_path: Path, java_executable: str = "java", startup_timeout_seconds: float = 30.0):
        self.jar_path = Path(jar_path).resolve()
        self.java_executable = _resolve_java_executable(java_executable)
        self.startup_timeout_seconds = startup_timeout_seconds
        self.process: subprocess.Popen[str] | None = None
        self.client: SourceAfisClient | None = None
        self._output: list[str] = []
        self._threads: list[threading.Thread] = []
        self.jar_sha256: str | None = None

    @property
    def base_url(self) -> str:
        if self.client is None:
            raise RuntimeError("sidecar is not running")
        return self._base_url

    def start(self) -> SourceAfisClient:
        if self.process is not None:
            raise RuntimeError("sidecar has already been started")
        if not self.jar_path.is_file():
            raise SidecarStartupError(f"sidecar JAR does not exist: {self.jar_path}")
        with self.jar_path.open("rb") as handle:
            signature = handle.read(4)
        if signature != b"PK\x03\x04":
            raise SidecarStartupError(f"sidecar artifact is not a valid JAR/ZIP file: {self.jar_path}")
        self.jar_sha256 = file_sha256(self.jar_path)
        self.process = subprocess.Popen(
            [self.java_executable, "-jar", str(self.jar_path), "--host", "127.0.0.1", "--port", "0"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", errors="replace",
        )
        ready: queue.Queue[str] = queue.Queue()

        def read_stdout() -> None:
            assert self.process is not None and self.process.stdout is not None
            for line in self.process.stdout:
                cleaned = line.rstrip()
                self._output.append(cleaned)
                if cleaned.startswith("{"):
                    ready.put(cleaned)

        def read_stderr() -> None:
            assert self.process is not None and self.process.stderr is not None
            for line in self.process.stderr:
                self._output.append(line.rstrip())

        self._threads = [threading.Thread(target=read_stdout, daemon=True), threading.Thread(target=read_stderr, daemon=True)]
        for thread in self._threads:
            thread.start()
        deadline = time.monotonic() + self.startup_timeout_seconds
        try:
            while time.monotonic() < deadline:
                if self.process.poll() is not None:
                    raise SidecarStartupError(f"sidecar exited during startup: {' | '.join(self._output[-5:])}")
                try:
                    message = json.loads(ready.get(timeout=min(0.1, max(0.01, deadline - time.monotonic()))))
                except queue.Empty:
                    continue
                except json.JSONDecodeError:
                    continue
                if message.get("status") == "ready" and isinstance(message.get("port"), int):
                    self._base_url = f"http://127.0.0.1:{message['port']}"
                    self.client = SourceAfisClient(self._base_url)
                    self.client.health()
                    return self.client
            raise SidecarStartupError("timed out waiting for sidecar readiness")
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        if self.client is not None:
            self.client.close()
            self.client = None
        process, self.process = self.process, None
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

    def __enter__(self) -> SourceAfisClient:
        return self.start()

    def __exit__(self, *_: object) -> None:
        self.close()


def _resolve_java_executable(value: str) -> str:
    discovered = shutil.which(value) or value
    path = Path(discovered)
    if path.is_file() and path.parent.name.lower() == "bin":
        conda_jvm = path.parent.parent / "lib" / "jvm" / "bin" / "java.exe"
        if conda_jvm.is_file():
            return str(conda_jvm)
    return str(path) if path.is_file() else value
