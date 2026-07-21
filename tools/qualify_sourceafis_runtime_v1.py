"""Qualify the successful SourceAFIS path on one deterministic non-cohort fixture."""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import http.client
import json
import math
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import uuid
import zipfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Iterator, Mapping, Sequence
from urllib.parse import urlparse
import xml.etree.ElementTree as ET


QUALIFICATION_ID = "sourceafis_runtime_v1"
OLD_SOURCE_COMMIT = "0893d50d08972fc68337749332ecdaa0faef2a70"
NEW_RUNTIME_BASELINE = "db1e499f0ee3a5457ec71fbc7feba22214d34116"
FROZEN_PROTOCOL_COMMIT = "29d8de0180403e9aa8a5e81cc468664b96dc8932"
SOURCEAFIS_VERSION = "3.18.1"
OLD_CONTRACT_VERSION = "sourceafis-sidecar-v2.3"
NEW_CONTRACT_VERSION = "sourceafis-sidecar-contract-v1"
EXPECTED_JAVA_VERSION = "17.0.18"
EXPECTED_JAVA_VENDOR = "Azul Systems, Inc."
EXPECTED_MAVEN_VERSION = "3.9.16"
EXPECTED_COMPILER_RELEASE = "11"
FIXED_EXCLUSIONS = frozenset({"00001585", "00001586"})
CANONICAL_FINGER = 1
IMAGE_KEYS = ("sd300b_plain", "sd300b_roll", "sd300c_plain", "sd300c_roll")
COMPARISONS = (
    "sd300b_plain_self", "sd300b_roll_self", "sd300b_plain_roll",
    "sd300c_plain_self", "sd300c_roll_self", "sd300c_plain_roll",
)
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
DRIVE_PATH_PATTERN = re.compile(r"(?i)(?:^|[\s\"'])(?:[a-z]:[\\/])")


class QualificationError(RuntimeError):
    def __init__(self, status: str, reason: str):
        if status not in {"FAIL", "BLOCKED"}:
            raise ValueError("qualification error status must be FAIL or BLOCKED")
        super().__init__(reason)
        self.status = status
        self.reason = reason


@dataclass(frozen=True)
class EnvironmentInfo:
    java_distribution: str
    java_version: str
    java_vendor: str
    java_runtime_build: str
    java_architecture: str
    maven_version: str
    compiler_release: int

    def artifact(self) -> dict[str, Any]:
        return {
            "operating_system": f"{platform.system()} {platform.release()}",
            "python_version": platform.python_version(),
            "java_distribution": self.java_distribution,
            "java_version": self.java_version,
            "java_vendor": self.java_vendor,
            "java_runtime_build": self.java_runtime_build,
            "java_architecture": self.java_architecture,
            "java_source": "existing_conda_environment",
            "conda_environment_name": "fingerprint-recognition-research",
            "maven_version": self.maven_version,
            "compiler_release": self.compiler_release,
            "sourceafis_version": SOURCEAFIS_VERSION,
            "old_and_new_used_same_java": True,
            "old_and_new_used_same_maven_runtime": True,
            "persistent_system_environment_modified": False,
            "conda_environment_modified": False,
        }


@dataclass(frozen=True)
class QualifiedImage:
    key: str
    path: Path
    relative_path: str
    sha256: str
    nominal_ppi: int

    def artifact(self) -> dict[str, Any]:
        return {"relative_path": self.relative_path, "sha256": self.sha256, "nominal_ppi": self.nominal_ppi}


@dataclass(frozen=True)
class Fixture:
    subject_id: str
    canonical_finger: int
    images: Mapping[str, QualifiedImage]


@dataclass(frozen=True)
class SidecarSpec:
    implementation: str
    jar_path: Path
    contract_version: str
    implementation_version: str
    launch_style: str


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def tree_sha256(root: Path) -> str:
    entries = [
        {"path": path.relative_to(root).as_posix(), "sha256": file_sha256(path)}
        for path in sorted(Path(root).rglob("*")) if path.is_file()
    ]
    return hashlib.sha256(canonical_json_bytes(entries)).hexdigest()


def read_csv_rows(path: Path) -> list[dict[str, str]]:
    with Path(path).open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _truth(value: str | bool | None) -> bool:
    return value is True or str(value or "").strip().lower() == "true"


def manual_review_subjects(rows: Iterable[Mapping[str, str]]) -> set[str]:
    subjects: set[str] = set()
    for row in rows:
        key = str(row.get("logical_record_key") or "")
        subject = key.split("|", 1)[0].strip()
        if subject:
            subjects.add(subject)
    return subjects


def blocked_subjects(rows: Iterable[Mapping[str, str]]) -> set[str]:
    blocked: set[str] = set()
    for row in rows:
        if _truth(row.get("selection_blocked")):
            for field in ("subject_id", "subject_id_a", "subject_id_b"):
                subject = str(row.get(field) or "").strip()
                if subject:
                    blocked.add(subject)
    return blocked


def select_subject(
    eligible_rows: Iterable[Mapping[str, str]], cohort_subjects: set[str],
    manual_subjects: set[str], blocked: set[str],
) -> str:
    candidates: list[str] = []
    excluded = cohort_subjects | manual_subjects | blocked | set(FIXED_EXCLUSIONS)
    for row in eligible_rows:
        subject = str(row.get("subject_id") or "").strip()
        complete = all(
            _truth(row.get(field))
            for field in ("has_all_10_fingers_b", "has_all_10_fingers_c", "has_all_10_in_both")
        )
        counts = all(str(row.get(field) or "") == "10" for field in (
            "plain_count_b", "roll_count_b", "pair_count_b", "plain_count_c", "roll_count_c", "pair_count_c",
        ))
        if subject and complete and counts and _truth(row.get("eligible_for_core_selection")) and subject not in excluded:
            candidates.append(subject)
    if not candidates:
        raise QualificationError("BLOCKED", "no authoritative eligible non-cohort subject remains after exclusions")
    return sorted(set(candidates))[0]


def find_canonical_pair(rows: Iterable[Mapping[str, str]], subject_id: str, release: str) -> Mapping[str, str]:
    matches = [
        row for row in rows
        if str(row.get("subject_id")) == subject_id and str(row.get("canonical_finger")) == str(CANONICAL_FINGER)
    ]
    if len(matches) != 1:
        raise QualificationError("FAIL", f"canonical finger 1 pair is missing or duplicated in {release}")
    row = matches[0]
    if str(row.get("dataset_release") or "").upper() != release.upper():
        raise QualificationError("FAIL", f"canonical pair release mismatch in {release}")
    if str(row.get("pair_status") or "").lower() != "valid":
        raise QualificationError("FAIL", f"canonical pair is not valid in {release}")
    return row


def _locked_metadata_hashes(curation_root: Path, protocol_root: Path) -> None:
    lock_path = curation_root / "outputs" / "manifest_lock.json"
    sums_path = curation_root / "outputs" / "MANIFEST_SHA256SUMS.txt"
    if not lock_path.is_file() or not sums_path.is_file():
        raise QualificationError("BLOCKED", "authoritative Stage 0 lock files are missing")
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    required = (
        "eligible_subjects.csv", "selected_50_subjects.csv", "all_genuine_pairs_sd300b.csv",
        "all_genuine_pairs_sd300c.csv", "duplicate_identity_review.csv",
    )
    for name in required:
        path = curation_root / "outputs" / name
        expected = (lock.get("artifact_sha256", {}).get(name) or {}).get("sha256")
        if not path.is_file() or not SHA256_PATTERN.fullmatch(str(expected or "")) or file_sha256(path) != expected:
            raise QualificationError("BLOCKED", f"authoritative Stage 0 artifact lock mismatch: {name}")
    protocol_lock = json.loads((protocol_root / "manifest_lock.json").read_text(encoding="utf-8"))
    manual = curation_root / "config" / "manual_review_decisions.csv"
    if not manual.is_file() or file_sha256(manual) != protocol_lock.get("manual_review_decisions_sha256"):
        raise QualificationError("BLOCKED", "manual review decisions do not match the frozen protocol provenance")


def _safe_dataset_path(dataset_root: Path, source_path: str, release: str) -> tuple[Path, str]:
    raw = Path(source_path)
    resolved = raw.resolve() if raw.is_absolute() else (dataset_root / raw).resolve()
    root = dataset_root.resolve()
    try:
        relative = resolved.relative_to(root).as_posix()
    except ValueError as exc:
        raise QualificationError("FAIL", "fixture image path escapes dataset root") from exc
    if not relative.lower().startswith(release.lower() + "/"):
        raise QualificationError("FAIL", f"fixture image path does not match {release}")
    if not resolved.is_file():
        raise QualificationError("FAIL", f"fixture image is missing: {relative}")
    return resolved, relative


def verify_image_hash(path: Path, expected: str, relative_path: str) -> str:
    actual = file_sha256(path)
    if not SHA256_PATTERN.fullmatch(str(expected or "")) or actual != expected:
        raise QualificationError("FAIL", f"fixture image hash mismatch: {relative_path}")
    return actual


def select_and_verify_fixture(curation_root: Path, dataset_root: Path, protocol_root: Path) -> Fixture:
    required = {
        "eligible": curation_root / "outputs" / "eligible_subjects.csv",
        "pairs_b": curation_root / "outputs" / "all_genuine_pairs_sd300b.csv",
        "pairs_c": curation_root / "outputs" / "all_genuine_pairs_sd300c.csv",
        "duplicates": curation_root / "outputs" / "duplicate_identity_review.csv",
        "manual": curation_root / "config" / "manual_review_decisions.csv",
        "cohort": protocol_root / "provenance" / "selected_50_subjects.csv",
    }
    missing = [name for name, path in required.items() if not path.is_file()]
    if missing:
        raise QualificationError("BLOCKED", f"authoritative selection files are missing: {', '.join(sorted(missing))}")
    _locked_metadata_hashes(curation_root, protocol_root)
    cohort = {row["subject_id"] for row in read_csv_rows(required["cohort"])}
    manual = manual_review_subjects(read_csv_rows(required["manual"]))
    blocked = blocked_subjects(read_csv_rows(required["duplicates"]))
    subject = select_subject(read_csv_rows(required["eligible"]), cohort, manual, blocked)
    if subject in cohort or subject in manual or subject in blocked or subject in FIXED_EXCLUSIONS:
        raise QualificationError("FAIL", "selected subject violates exclusion policy")
    pair_b = find_canonical_pair(read_csv_rows(required["pairs_b"]), subject, "SD300B")
    pair_c = find_canonical_pair(read_csv_rows(required["pairs_c"]), subject, "SD300C")
    images: dict[str, QualifiedImage] = {}
    for release_key, release, ppi, row in (
        ("sd300b", "sd300b", 1000, pair_b), ("sd300c", "sd300c", 2000, pair_c),
    ):
        if int(row["nominal_ppi"]) != ppi:
            raise QualificationError("FAIL", f"frozen nominal PPI mismatch in {release_key}")
        for capture in ("plain", "roll"):
            path, relative = _safe_dataset_path(dataset_root, row[f"{capture}_path"], release)
            expected = row[f"{capture}_sha256"]
            actual = verify_image_hash(path, expected, relative)
            key = f"{release_key}_{capture}"
            images[key] = QualifiedImage(key, path, relative, actual, ppi)
    if tuple(images) != IMAGE_KEYS or len({image.path for image in images.values()}) != 4:
        raise QualificationError("FAIL", "fixture must contain exactly four unique images")
    return Fixture(subject, CANONICAL_FINGER, images)


def parse_java_properties(output: str) -> dict[str, str]:
    values: dict[str, str] = {}
    version = re.search(r'(?m)^(?:openjdk|java) version "([^"]+)"', output.strip())
    if version:
        values["java_version"] = version.group(1)
    for key in ("java.home", "java.runtime.version", "java.vendor", "os.arch"):
        match = re.search(rf"(?m)^\s*{re.escape(key)}\s*=\s*(.+?)\s*$", output)
        if match:
            values[key] = match.group(1)
    runtime = re.search(r"Zulu[^\s(]*.*?\(build\s+([^\)]+)\)", output)
    if runtime:
        values["zulu_build"] = runtime.group(1)
    return values


def parse_maven_version(output: str) -> dict[str, str]:
    values: dict[str, str] = {}
    version = re.search(r"(?m)^Apache Maven\s+([^\s]+)", output)
    runtime = re.search(
        r"(?m)^Java version:\s*(.+?),\s*vendor:\s*(.+),\s*runtime:\s*(.+?)\s*$",
        output,
    )
    if version:
        values["maven_version"] = version.group(1)
    if runtime:
        values["java_version"] = runtime.group(1).strip()
        values["java_vendor"] = runtime.group(2).strip()
        values["java_runtime"] = runtime.group(3).strip()
    return values


def validate_environment_outputs(
    java_output: str, javac_output: str, maven_output: str, expected_java_home: Path,
) -> EnvironmentInfo:
    java = parse_java_properties(java_output)
    maven = parse_maven_version(maven_output)
    javac = re.search(r"(?m)^javac\s+([^\s]+)", javac_output.strip())
    if java.get("java_version") != EXPECTED_JAVA_VERSION or java.get("java.runtime.version") != "17.0.18+8-LTS":
        raise QualificationError("BLOCKED", "canonical Java runtime must be exactly 17.0.18+8-LTS")
    if java.get("java.vendor") != EXPECTED_JAVA_VENDOR or "Zulu" not in java_output:
        raise QualificationError("BLOCKED", "canonical Java vendor/distribution must be Azul Zulu")
    if java.get("os.arch") not in {"amd64", "x86_64"}:
        raise QualificationError("BLOCKED", "canonical Java architecture must be amd64/x64")
    if not javac or javac.group(1) != EXPECTED_JAVA_VERSION:
        raise QualificationError("BLOCKED", "canonical javac must be exactly 17.0.18")
    if maven.get("maven_version") != EXPECTED_MAVEN_VERSION:
        raise QualificationError("BLOCKED", "canonical Maven must be exactly 3.9.16")
    if maven.get("java_version") != EXPECTED_JAVA_VERSION or maven.get("java_vendor") != EXPECTED_JAVA_VENDOR:
        raise QualificationError("BLOCKED", "Maven is not using the canonical Java runtime")
    try:
        same_home = Path(maven.get("java_runtime", "")).resolve() == expected_java_home.resolve()
    except OSError:
        same_home = False
    if not same_home:
        raise QualificationError("BLOCKED", "Maven Java home differs from the canonical Java home")
    try:
        java_home_matches = Path(java.get("java.home", "")).resolve() == expected_java_home.resolve()
    except OSError:
        java_home_matches = False
    if not java_home_matches:
        raise QualificationError("BLOCKED", "Java launcher home differs from the canonical Java home")
    return EnvironmentInfo(
        "Zulu OpenJDK", EXPECTED_JAVA_VERSION, EXPECTED_JAVA_VENDOR, "17.0.18+8-LTS",
        str(java["os.arch"]), EXPECTED_MAVEN_VERSION, 11,
    )


def _run_checked(command: Sequence[str], *, cwd: Path | None = None, env: Mapping[str, str] | None = None) -> str:
    completed = subprocess.run(command, cwd=cwd, env=env, text=True, encoding="utf-8", errors="replace", stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if completed.returncode:
        tail = completed.stdout[-4000:].replace("\x00", "")
        raise QualificationError("BLOCKED", f"command failed ({Path(command[0]).name}): {tail}")
    return completed.stdout


def qualification_subprocess_env(java_home: Path, java_executable: Path) -> dict[str, str]:
    env = dict(os.environ)
    env["JAVA_HOME"] = str(java_home)
    env["PATH"] = str(java_executable.parent) + os.pathsep + env.get("PATH", "")
    return env


def canonical_runtime_paths(java: Path, javac: Path, maven: Path, java_home: Path) -> None:
    library = java_home.parent.parent
    expected = {
        "java": library / "bin" / "java.exe",
        "javac": library / "bin" / "javac.exe",
        "maven": library / "bin" / "mvn.cmd",
        "java_home_launcher": java_home / "bin" / "java.exe",
    }
    for label, path in {"java": java, "javac": javac, "maven": maven}.items():
        if path.resolve() != expected[label].resolve():
            raise QualificationError("BLOCKED", f"canonical {label} path does not match the Conda runtime layout")
    if not expected["java_home_launcher"].is_file():
        raise QualificationError("BLOCKED", "canonical Java home launcher is missing")
    if library.parent.name != "fingerprint-recognition-research":
        raise QualificationError("BLOCKED", "canonical Conda environment name mismatch")


def validate_environment(java: Path, javac: Path, maven: Path, java_home: Path) -> EnvironmentInfo:
    for label, path in (("java", java), ("javac", javac), ("maven", maven), ("java_home", java_home)):
        if not path.exists():
            raise QualificationError("BLOCKED", f"canonical {label} path does not exist")
    canonical_runtime_paths(java, javac, maven, java_home)
    env = qualification_subprocess_env(java_home, java)
    java_output = _run_checked([str(java), "-XshowSettings:properties", "-version"], env=env)
    javac_output = _run_checked([str(javac), "-version"], env=env)
    maven_output = _run_checked([str(maven), "-version"], env=env)
    return validate_environment_outputs(java_output, javac_output, maven_output, java_home)


def pom_versions(pom: Path) -> dict[str, str]:
    root = ET.parse(pom).getroot()
    namespace = {"m": "http://maven.apache.org/POM/4.0.0"}
    properties = root.find("m:properties", namespace)
    if properties is None:
        raise QualificationError("FAIL", "Maven properties are missing")
    return {child.tag.split("}")[-1]: str(child.text or "").strip() for child in properties}


def validate_pom(pom: Path) -> None:
    versions = pom_versions(pom)
    if versions.get("maven.compiler.release") != EXPECTED_COMPILER_RELEASE:
        raise QualificationError("FAIL", "compiler release is not Java 11")
    if versions.get("sourceafis.version") != SOURCEAFIS_VERSION:
        raise QualificationError("FAIL", "SourceAFIS version is not 3.18.1")


@contextmanager
def temporary_workspace(new_repository_root: Path) -> Iterator[Path]:
    parent = new_repository_root / ".qualification-tmp"
    workspace = parent / f"run-{uuid.uuid4().hex}"
    workspace.mkdir(parents=True, exist_ok=False)
    try:
        yield workspace
    finally:
        if workspace.exists():
            shutil.rmtree(workspace)
        try:
            parent.rmdir()
        except OSError:
            pass


def export_old_sidecar(old_repository_root: Path, workspace: Path) -> Path:
    archive = workspace / "old-sidecar.zip"
    _run_checked([
        "git", "-C", str(old_repository_root), "archive", "--format=zip", "--output", str(archive),
        OLD_SOURCE_COMMIT, "apps/sourceafis-sidecar",
    ])
    extracted = workspace / "old-source"
    extracted.mkdir()
    with zipfile.ZipFile(archive) as bundle:
        for info in bundle.infolist():
            path = PurePosixPath(info.filename)
            if path.is_absolute() or ".." in path.parts:
                raise QualificationError("BLOCKED", "old source archive contains an unsafe path")
        bundle.extractall(extracted)
    archive.unlink()
    pom = extracted / "apps" / "sourceafis-sidecar" / "pom.xml"
    if not pom.is_file():
        raise QualificationError("BLOCKED", "old sidecar source cannot be extracted from the audited commit")
    return pom.parent


def maven_build_command(maven: Path, pom: Path) -> list[str]:
    return [str(maven), "-V", "-f", str(pom), "clean", "test", "package"]


def build_sidecars(
    old_repository_root: Path, new_repository_root: Path, workspace: Path,
    maven: Path, java: Path, java_home: Path,
) -> tuple[Path, Path]:
    old_root = export_old_sidecar(old_repository_root, workspace)
    new_root = new_repository_root / "apps" / "sourceafis-sidecar"
    validate_pom(old_root / "pom.xml")
    validate_pom(new_root / "pom.xml")
    env = qualification_subprocess_env(java_home, java)
    for pom in (old_root / "pom.xml", new_root / "pom.xml"):
        output = _run_checked(maven_build_command(maven, pom), env=env)
        parsed = parse_maven_version(output)
        try:
            same_home = Path(parsed.get("java_runtime", "")).resolve() == java_home.resolve()
        except OSError:
            same_home = False
        if (
            parsed.get("maven_version") != EXPECTED_MAVEN_VERSION
            or parsed.get("java_version") != EXPECTED_JAVA_VERSION
            or parsed.get("java_vendor") != EXPECTED_JAVA_VENDOR
            or not same_home
        ):
            raise QualificationError("BLOCKED", "Maven build did not use the canonical runtime")
    old_jar = old_root / "target" / "sourceafis-sidecar-0.4.0.jar"
    new_jar = new_root / "target" / "sourceafis-sidecar-1.0.0-all.jar"
    for label, jar in (("old", old_jar), ("new", new_jar)):
        if not jar.is_file() or not zipfile.is_zipfile(jar):
            raise QualificationError("BLOCKED", f"{label} sidecar JAR was not built")
    return old_jar, new_jar


def _free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _http_json(port: int, method: str, path: str, payload: Mapping[str, Any] | None = None) -> tuple[int, dict[str, Any]]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=120)
    body = None if payload is None else json.dumps(payload, separators=(",", ":"), allow_nan=False).encode("utf-8")
    headers = {"Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        data = response.read()
    finally:
        connection.close()
    try:
        decoded = json.loads(data.decode("utf-8")) if data else {}
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise QualificationError("FAIL", "sidecar returned invalid JSON") from exc
    if not isinstance(decoded, dict):
        raise QualificationError("FAIL", "sidecar response is not a JSON object")
    return response.status, decoded


def _http_status(port: int, method: str, path: str, payload: Mapping[str, Any] | None = None) -> int:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=120)
    body = None if payload is None else json.dumps(payload, separators=(",", ":"), allow_nan=False).encode("utf-8")
    headers = {"Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        response.read()
        return response.status
    finally:
        connection.close()


def sidecar_launch_command(spec: SidecarSpec, java: Path, port: int) -> list[str]:
    command = [str(java), "-jar", str(spec.jar_path)]
    if spec.launch_style == "arguments":
        command.extend(["--host", "127.0.0.1", "--port", str(port)])
    return command


class RunningSidecar:
    def __init__(self, spec: SidecarSpec, java: Path, java_home: Path):
        self.spec = spec
        self.java = java
        self.java_home = java_home
        self.port = _free_loopback_port()
        self.process: subprocess.Popen[str] | None = None
        self._output: list[str] = []
        self._threads: list[threading.Thread] = []

    def __enter__(self) -> "RunningSidecar":
        env = qualification_subprocess_env(self.java_home, self.java)
        if self.spec.launch_style == "environment":
            env["SOURCEAFIS_HOST"] = "127.0.0.1"
            env["SOURCEAFIS_PORT"] = str(self.port)
        command = sidecar_launch_command(self.spec, self.java, self.port)
        flags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
        self.process = subprocess.Popen(
            command, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", errors="replace", creationflags=flags,
        )
        for stream in (self.process.stdout, self.process.stderr):
            assert stream is not None
            thread = threading.Thread(target=self._drain, args=(stream,), daemon=True)
            thread.start()
            self._threads.append(thread)
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            try:
                status, _ = _http_json(self.port, "GET", "/health")
                if status == 200:
                    return self
            except (OSError, QualificationError):
                time.sleep(0.1)
        self.close()
        raise QualificationError("FAIL", "sidecar did not become healthy")

    def _drain(self, stream) -> None:
        for line in stream:
            self._output.append(line.rstrip())
            if len(self._output) > 100:
                del self._output[:-100]

    def close(self) -> None:
        process, self.process = self.process, None
        if process is None:
            return
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        elif process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)
        for thread in self._threads:
            thread.join(timeout=2)
        self._threads.clear()

    def __exit__(self, *_: object) -> None:
        self.close()


def validate_health(health: Mapping[str, Any], spec: SidecarSpec) -> None:
    if health.get("status") != "ok" or health.get("sourceafis_version") != SOURCEAFIS_VERSION:
        raise QualificationError("FAIL", f"{spec.implementation} sidecar health/version mismatch")
    if health.get("contract_version") != spec.contract_version:
        raise QualificationError("FAIL", f"{spec.implementation} sidecar contract mismatch")
    implementation = health.get("implementation_version", health.get("sidecar_implementation_version"))
    if implementation != spec.implementation_version:
        raise QualificationError("FAIL", f"{spec.implementation} sidecar implementation mismatch")
    runtime = str(health.get("java_runtime_version") or "")
    if not runtime.startswith(EXPECTED_JAVA_VERSION):
        raise QualificationError("FAIL", f"{spec.implementation} sidecar used the wrong Java runtime")
    if spec.implementation == "new":
        expected = {
            "external_preprocessing": "none", "thresholding": "none", "decision_logic": "none",
            "template_cache": False, "supported_operations": ["template_extraction", "pairwise_verification"],
        }
        for key, value in expected.items():
            if health.get(key) != value:
                raise QualificationError("FAIL", f"new sidecar health mismatch: {key}")


def _extract(port: int, image_bytes: bytes, dpi: int) -> tuple[bytes, str, str]:
    status, response = _http_json(port, "POST", "/extract-template", {
        "image_base64": base64.b64encode(image_bytes).decode("ascii"), "dpi": dpi,
    })
    if status != 200:
        raise QualificationError("FAIL", f"template extraction failed: {response.get('error_code', status)}")
    try:
        template = base64.b64decode(str(response["template_base64"]).encode("ascii"), validate=True)
        template_format = str(response["template_format"])
        template_version = str(response["template_version"])
    except (KeyError, ValueError) as exc:
        raise QualificationError("FAIL", "template extraction response is invalid") from exc
    if not template or template_format != "sourceafis" or template_version != SOURCEAFIS_VERSION:
        raise QualificationError("FAIL", "template identity/version mismatch")
    return template, template_format, template_version


def _verify(port: int, template_a: bytes, template_b: bytes) -> float:
    status, response = _http_json(port, "POST", "/verify", {
        "template_a_base64": base64.b64encode(template_a).decode("ascii"),
        "template_b_base64": base64.b64encode(template_b).decode("ascii"),
    })
    if status != 200:
        raise QualificationError("FAIL", f"template verification failed: {response.get('error_code', status)}")
    try:
        score = float(response["raw_score"])
    except (KeyError, TypeError, ValueError) as exc:
        raise QualificationError("FAIL", "verification response is invalid") from exc
    if not math.isfinite(score):
        raise QualificationError("FAIL", "SourceAFIS returned a non-finite raw score")
    return score


def run_repetition(spec: SidecarSpec, fixture: Fixture, java: Path, java_home: Path, index: int) -> dict[str, Any]:
    templates: dict[str, bytes] = {}
    try:
        with RunningSidecar(spec, java, java_home) as sidecar:
            status, health = _http_json(sidecar.port, "GET", "/health")
            if status != 200:
                raise QualificationError("FAIL", f"{spec.implementation} health endpoint failed")
            validate_health(health, spec)
            formats: dict[str, str] = {}
            versions: dict[str, str] = {}
            for key in IMAGE_KEYS:
                image = fixture.images[key]
                encoded = image.path.read_bytes()
                template, template_format, template_version = _extract(sidecar.port, encoded, image.nominal_ppi)
                templates[key] = template
                formats[key] = template_format
                versions[key] = template_version
            pairs = {
                "sd300b_plain_self": ("sd300b_plain", "sd300b_plain"),
                "sd300b_roll_self": ("sd300b_roll", "sd300b_roll"),
                "sd300b_plain_roll": ("sd300b_plain", "sd300b_roll"),
                "sd300c_plain_self": ("sd300c_plain", "sd300c_plain"),
                "sd300c_roll_self": ("sd300c_roll", "sd300c_roll"),
                "sd300c_plain_roll": ("sd300c_plain", "sd300c_roll"),
            }
            scores = {name: _verify(sidecar.port, templates[a], templates[b]) for name, (a, b) in pairs.items()}
            removed: dict[str, int] = {}
            if spec.implementation == "new":
                for path in ("/extract-template-raw", "/extract-final-minutiae"):
                    route_status = _http_status(sidecar.port, "POST", path, {})
                    removed[path] = route_status
                    if route_status != 404:
                        raise QualificationError("FAIL", f"removed endpoint is still active: {path}")
            return {
                "repetition": index,
                "template_sha256": {key: hashlib.sha256(templates[key]).hexdigest() for key in IMAGE_KEYS},
                "template_format": formats,
                "template_version": versions,
                "raw_scores": scores,
                "finite_scores": all(math.isfinite(value) for value in scores.values()),
                "removed_route_status": removed,
            }
    finally:
        templates.clear()


def validate_repetitions(old_runs: Sequence[Mapping[str, Any]], new_runs: Sequence[Mapping[str, Any]]) -> dict[str, bool]:
    if len(old_runs) != 3 or len(new_runs) != 3:
        raise QualificationError("FAIL", "exactly three repetitions are required per implementation")
    for label, runs in (("old", old_runs), ("new", new_runs)):
        reference_templates = runs[0]["template_sha256"]
        reference_scores = runs[0]["raw_scores"]
        reference_formats = runs[0]["template_format"]
        reference_versions = runs[0]["template_version"]
        for run in runs:
            if not run.get("finite_scores"):
                raise QualificationError("FAIL", f"{label} sidecar returned a non-finite raw score")
            if run["template_sha256"] != reference_templates:
                raise QualificationError("FAIL", f"{label} template nondeterminism")
            if run["raw_scores"] != reference_scores:
                raise QualificationError("FAIL", f"{label} score nondeterminism")
            if run["template_format"] != reference_formats or run["template_version"] != reference_versions:
                raise QualificationError("FAIL", f"{label} template identity nondeterminism")
    for old, new in zip(old_runs, new_runs):
        if old["template_format"] != new["template_format"] or old["template_version"] != new["template_version"]:
            raise QualificationError("FAIL", "old/new template identity mismatch")
        if old["template_sha256"] != new["template_sha256"]:
            raise QualificationError("FAIL", "old/new template hash mismatch")
        if old["raw_scores"] != new["raw_scores"]:
            raise QualificationError("FAIL", "old/new raw score mismatch")
        removed = new.get("removed_route_status", {})
        if set(removed) != {"/extract-template-raw", "/extract-final-minutiae"} or any(
            status != 404 for status in removed.values()
        ):
            raise QualificationError("FAIL", "removed endpoint did not return 404")
    return {
        "old_internal_determinism": True, "new_internal_determinism": True,
        "template_parity": True, "score_parity": True, "removed_routes_absent": True,
    }


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n", encoding="utf-8", newline="\n")


def _assert_safe_json(value: Any, key: str = "") -> None:
    lowered = key.lower()
    if any(term in lowered for term in ("base64", "template_bytes", "image_bytes", "payload")):
        raise QualificationError("FAIL", f"forbidden byte-bearing result field: {key}")
    if isinstance(value, Mapping):
        for child_key, child in value.items():
            _assert_safe_json(child, str(child_key))
    elif isinstance(value, list):
        for child in value:
            _assert_safe_json(child, key)
    elif isinstance(value, str) and (DRIVE_PATH_PATTERN.search(value) or "\\Users\\" in value):
        raise QualificationError("FAIL", "qualification artifact contains an absolute local path")
    if ("threshold" in lowered or "decision" in lowered) and value not in (False, None, "none"):
        raise QualificationError("FAIL", f"qualification artifact contains active decision policy: {key}")


def qualification_manifest(fixture: Fixture) -> dict[str, Any]:
    return {
        "qualification_id": QUALIFICATION_ID,
        "purpose": "successful_path_runtime_qualification_only",
        "research_result": False,
        "threshold_input": False,
        "accuracy_input": False,
        "cohort_member": False,
        "selection_policy": {
            "source": "stage0 metadata only",
            "order": "lexicographically smallest eligible non-cohort subject",
            "canonical_finger": CANONICAL_FINGER,
            "fallback_allowed": False,
        },
        "subject_id": fixture.subject_id,
        "canonical_finger": fixture.canonical_finger,
        "images": {key: fixture.images[key].artifact() for key in IMAGE_KEYS},
        "comparisons": list(COMPARISONS),
    }


def _qualification_report(
    fixture: Fixture, environment: EnvironmentInfo, old_jar_hash: str, new_jar_hash: str,
    checks: Mapping[str, bool], supporting_provenance: str,
) -> str:
    image_lines = "\n".join(
        f"- `{key}`: `{fixture.images[key].relative_path}` — `{fixture.images[key].sha256}` ({fixture.images[key].nominal_ppi} PPI)"
        for key in IMAGE_KEYS
    )
    report = f"""# SourceAFIS Successful-Path Runtime Qualification

## Purpose and final status

**PASS** — technical successful-path qualification for `sourceafis_runtime_v1`.

This qualification proves encoded-image extraction, official SourceAFIS 3.18.1 template serialization, official pairwise verification, deterministic finite raw scores, and old/new parity. It is not a research result and provides no biometric interpretation.

## Canonical JVM selection

The first attempt stopped before matcher execution because Java 11 was treated as a runtime requirement.
It published no PASS package and left the partial BLOCKED report untouched until this successful replacement.

The historical research environment was verified to contain Zulu OpenJDK 17.0.18 and Maven 3.9.16 using the same Java home. Both sidecars were built and run with this same existing environment, while the compiler target remained Java release 11. No Java installation, Conda change, or persistent system-environment change was made.

Supporting read-only old-run provenance: `{supporting_provenance}` recorded Java runtime 17.0.18 and SourceAFIS 3.18.1.

## Deterministic fixture selection

The selected subject is `{fixture.subject_id}`, canonical finger `{fixture.canonical_finger}`. It is the lexicographically smallest Stage 0 subject with complete matching PLAIN/ROLL coverage in both releases after removing the frozen 50-subject cohort, fixed duplicate exclusions, all manual-review subjects, and all selection-blocked subjects. No quality, dimensions, matcher success, or score informed selection, and no fallback was allowed.

The subject is not part of the frozen cohort. Exactly four images were used:

{image_lines}

## Environment and implementations

- Runtime: {environment.java_distribution} {environment.java_version} (`{environment.java_runtime_build}`), vendor `{environment.java_vendor}`, architecture `{environment.java_architecture}`
- Maven: {environment.maven_version}
- Compiler release: 11
- SourceAFIS: 3.18.1
- Old source commit: `{OLD_SOURCE_COMMIT}`
- New runtime baseline: `{NEW_RUNTIME_BASELINE}`
- Old JAR SHA-256: `{old_jar_hash}`
- New JAR SHA-256: `{new_jar_hash}`

## Qualification results

- Old successful extraction: PASS
- New successful extraction: PASS
- Old successful verification: PASS
- New successful verification: PASS
- Old internal determinism: {'PASS' if checks['old_internal_determinism'] else 'FAIL'}
- New internal determinism: {'PASS' if checks['new_internal_determinism'] else 'FAIL'}
- Template parity: {'PASS' if checks['template_parity'] else 'FAIL'}
- Score parity: {'PASS' if checks['score_parity'] else 'FAIL'}
- Removed routes return 404: {'PASS' if checks['removed_routes_absent'] else 'FAIL'}

All four templates and all six raw scores were identical across three independent repetitions per implementation. Old and new template hashes and parsed double scores were exactly equal. Serialized templates remained in memory and were never written to disk.

## Research boundary

No threshold, calibration, decision, acceptance classification, accuracy metric, or score-height interpretation was used. No impostor or cross-release comparison was performed. No research benchmark ran, and none of the frozen 50 subjects was accessible to the matcher. The frozen protocol, source repository, curation, and raw datasets remained unchanged.
"""
    return report.replace(chr(0xfffd), "—")


def build_candidate_package(
    candidate: Path, fixture: Fixture, environment: EnvironmentInfo,
    old_runs: Sequence[Mapping[str, Any]], new_runs: Sequence[Mapping[str, Any]], checks: Mapping[str, bool],
    old_jar_hash: str, new_jar_hash: str, protocol_before: str, protocol_after: str,
    new_repository_root: Path, supporting_provenance: str, git_dirty_before: bool,
) -> None:
    candidate.mkdir(parents=True, exist_ok=False)
    manifest = qualification_manifest(fixture)
    environment_artifact = environment.artifact()
    environment_artifact.update({
        "old_sidecar_implementation_version": "0.4.0",
        "new_sidecar_implementation_version": "1.0.0",
        "old_jar_sha256": old_jar_hash,
        "new_jar_sha256": new_jar_hash,
        "old_source_commit": OLD_SOURCE_COMMIT,
        "new_source_commit": NEW_RUNTIME_BASELINE,
        "git_dirty_state_before_qualification": git_dirty_before,
    })
    results = {
        "qualification_id": QUALIFICATION_ID,
        "selected_subject": fixture.subject_id,
        "canonical_finger": fixture.canonical_finger,
        "images": {key: fixture.images[key].artifact() for key in IMAGE_KEYS},
        "java_version": environment.java_version,
        "maven_version": environment.maven_version,
        "operating_system": environment_artifact["operating_system"],
        "old_source_commit": OLD_SOURCE_COMMIT,
        "new_source_commit": NEW_RUNTIME_BASELINE,
        "old_jar_sha256": old_jar_hash,
        "new_jar_sha256": new_jar_hash,
        "sourceafis_version": SOURCEAFIS_VERSION,
        "implementations": {
            "old": {"contract_version": OLD_CONTRACT_VERSION, "implementation_version": "0.4.0", "repetitions": list(old_runs)},
            "new": {"contract_version": NEW_CONTRACT_VERSION, "implementation_version": "1.0.0", "repetitions": list(new_runs)},
        },
        "checks": dict(checks),
        "status": {
            "status": "PASS", "successful_extraction": True, "successful_verification": True,
            **dict(checks), "research_benchmark_executed": False, "threshold_used": False,
            "decision_logic_used": False, "frozen_cohort_accessed_by_matcher": False,
        },
    }
    for artifact in (manifest, environment_artifact, results):
        _assert_safe_json(artifact)
    _write_json(candidate / "qualification_manifest.json", manifest)
    _write_json(candidate / "qualification_environment.json", environment_artifact)
    _write_json(candidate / "qualification_results.json", results)
    (candidate / "README.md").write_text(
        "# SourceAFIS runtime qualification v1\n\n"
        "This locked package records technical successful-path qualification on one deterministic non-cohort fixture. "
        "It contains no image bytes, templates, decisions, or research conclusions.\n",
        encoding="utf-8", newline="\n",
    )
    (candidate / "QUALIFICATION_REPORT.md").write_text(
        _qualification_report(fixture, environment, old_jar_hash, new_jar_hash, checks, supporting_provenance),
        encoding="utf-8", newline="\n",
    )
    package_files = {
        path.name: {"sha256": file_sha256(path), "size_bytes": path.stat().st_size}
        for path in sorted(candidate.iterdir()) if path.is_file()
    }
    tool = new_repository_root / "tools" / "qualify_sourceafis_runtime_v1.py"
    tests = new_repository_root / "tests" / "test_sourceafis_runtime_qualification.py"
    lock = {
        "qualification_id": QUALIFICATION_ID,
        "status": "PASS",
        "package_files": package_files,
        "qualification_tool": {"path": "tools/qualify_sourceafis_runtime_v1.py", "sha256": file_sha256(tool)},
        "qualification_tests": {"path": "tests/test_sourceafis_runtime_qualification.py", "sha256": file_sha256(tests)},
        "images": {key: fixture.images[key].artifact() for key in IMAGE_KEYS},
        "jars": {"old_sha256": old_jar_hash, "new_sha256": new_jar_hash},
        "commits": {"old_source": OLD_SOURCE_COMMIT, "new_runtime": NEW_RUNTIME_BASELINE, "frozen_protocol": FROZEN_PROTOCOL_COMMIT},
        "protocol_tree_sha256_before": protocol_before,
        "protocol_tree_sha256_after": protocol_after,
    }
    _assert_safe_json(lock)
    _write_json(candidate / "qualification_lock.json", lock)
    sums = [
        f"{file_sha256(path)}  {path.name}"
        for path in sorted(candidate.iterdir(), key=lambda item: item.name) if path.is_file() and path.name != "SHA256SUMS.txt"
    ]
    (candidate / "SHA256SUMS.txt").write_text("\n".join(sums) + "\n", encoding="utf-8", newline="\n")
    validate_package(candidate)


def validate_package(root: Path) -> None:
    required = {
        "README.md", "qualification_manifest.json", "qualification_results.json", "qualification_environment.json",
        "qualification_lock.json", "SHA256SUMS.txt", "QUALIFICATION_REPORT.md",
    }
    if {path.name for path in root.iterdir() if path.is_file()} != required:
        raise QualificationError("FAIL", "qualification package file set mismatch")
    results = json.loads((root / "qualification_results.json").read_text(encoding="utf-8"))
    environment = json.loads((root / "qualification_environment.json").read_text(encoding="utf-8"))
    manifest = json.loads((root / "qualification_manifest.json").read_text(encoding="utf-8"))
    lock = json.loads((root / "qualification_lock.json").read_text(encoding="utf-8"))
    for artifact in (results, environment, manifest, lock):
        _assert_safe_json(artifact)
    if (
        results.get("status", {}).get("status") != "PASS"
        or manifest.get("cohort_member") is not False
        or lock.get("status") != "PASS"
    ):
        raise QualificationError("FAIL", "qualification package status/cohort invariant failed")
    locked_files = lock.get("package_files", {})
    expected_locked_names = {
        "README.md", "qualification_manifest.json", "qualification_results.json",
        "qualification_environment.json", "QUALIFICATION_REPORT.md",
    }
    if set(locked_files) != expected_locked_names:
        raise QualificationError("FAIL", "qualification lock file coverage mismatch")
    for name, metadata in locked_files.items():
        path = root / name
        if metadata.get("sha256") != file_sha256(path) or metadata.get("size_bytes") != path.stat().st_size:
            raise QualificationError("FAIL", f"qualification lock mismatch: {name}")
    expected: dict[str, str] = {}
    for line in (root / "SHA256SUMS.txt").read_text(encoding="utf-8").splitlines():
        digest, separator, name = line.partition("  ")
        if not separator or not SHA256_PATTERN.fullmatch(digest) or name in expected:
            raise QualificationError("FAIL", "invalid qualification checksum index")
        expected[name] = digest
    actual_names = {path.name for path in root.iterdir() if path.is_file() and path.name != "SHA256SUMS.txt"}
    if set(expected) != actual_names or any(file_sha256(root / name) != digest for name, digest in expected.items()):
        raise QualificationError("FAIL", "qualification checksum mismatch")


def validate_repository_bindings(root: Path, repository_root: Path) -> None:
    lock = json.loads((root / "qualification_lock.json").read_text(encoding="utf-8"))
    for key in ("qualification_tool", "qualification_tests"):
        metadata = lock.get(key, {})
        relative = str(metadata.get("path") or "")
        path = repository_root / Path(*PurePosixPath(relative).parts)
        if not relative or not path.is_file() or metadata.get("sha256") != file_sha256(path):
            raise QualificationError("FAIL", f"qualification repository binding mismatch: {key}")
    if lock.get("protocol_tree_sha256_before") != lock.get("protocol_tree_sha256_after"):
        raise QualificationError("FAIL", "qualification lock records a modified frozen protocol")


def publish_candidate(candidate: Path, destination: Path, replace: bool) -> None:
    validate_package(candidate)
    if destination.exists() and not replace:
        raise QualificationError("FAIL", "qualification output exists; use --replace")
    backup = destination.with_name(f".{destination.name}.backup-{uuid.uuid4().hex}")
    moved = False
    published = False
    try:
        if destination.exists():
            os.replace(destination, backup)
            moved = True
        os.replace(candidate, destination)
        published = True
        validate_package(destination)
        if moved:
            shutil.rmtree(backup)
    except BaseException:
        if destination.exists() and published:
            shutil.rmtree(destination)
        if moved and backup.exists():
            os.replace(backup, destination)
        raise


def _git_output(repo: Path, *args: str) -> str:
    return _run_checked(["git", "-C", str(repo), *args]).strip()


def run_qualification(args: argparse.Namespace) -> dict[str, Any]:
    new_root, old_root = args.new_repository_root.resolve(), args.old_repository_root.resolve()
    curation_root, dataset_root = args.curation_root.resolve(), args.dataset_root.resolve()
    protocol_root = new_root / "protocols" / "supervisor_50x10_v1"
    if _git_output(old_root, "rev-parse", "HEAD") != OLD_SOURCE_COMMIT or _git_output(old_root, "status", "--short"):
        raise QualificationError("BLOCKED", "old repository commit or cleanliness mismatch")
    _run_checked(["git", "-C", str(new_root), "merge-base", "--is-ancestor", NEW_RUNTIME_BASELINE, "HEAD"])
    if _git_output(new_root, "rev-parse", "--abbrev-ref", "HEAD") != "main":
        raise QualificationError("BLOCKED", "qualification must run directly on main")
    if _git_output(new_root, "rev-parse", "sourceafis-runtime-v1^{}") != NEW_RUNTIME_BASELINE:
        raise QualificationError("BLOCKED", "runtime baseline tag does not resolve to the required commit")
    dirty_before = bool(_git_output(new_root, "status", "--short"))
    environment = validate_environment(args.java.resolve(), args.javac.resolve(), args.maven.resolve(), args.java_home.resolve())
    protocol_before = tree_sha256(protocol_root)
    fixture = select_and_verify_fixture(curation_root, dataset_root, protocol_root)
    if args.validation_only:
        return {
            "status": "VALID", "qualification_id": QUALIFICATION_ID,
            "subject_id": fixture.subject_id, "canonical_finger": fixture.canonical_finger,
            "images": {key: fixture.images[key].artifact() for key in IMAGE_KEYS},
            "environment": environment.artifact(), "matcher_executed": False,
        }
    temp_parent = new_root / ".qualification-tmp"
    new_target = new_root / "apps" / "sourceafis-sidecar" / "target"
    candidate = args.output_root.parent / f".{args.output_root.name}.candidate-{uuid.uuid4().hex}"
    try:
        with temporary_workspace(new_root) as workspace:
            old_jar, new_jar = build_sidecars(old_root, new_root, workspace, args.maven.resolve(), args.java.resolve(), args.java_home.resolve())
            old_hash, new_hash = file_sha256(old_jar), file_sha256(new_jar)
            old_spec = SidecarSpec("old", old_jar, OLD_CONTRACT_VERSION, "0.4.0", "environment")
            new_spec = SidecarSpec("new", new_jar, NEW_CONTRACT_VERSION, "1.0.0", "arguments")
            old_runs = [run_repetition(old_spec, fixture, args.java.resolve(), args.java_home.resolve(), index) for index in range(1, 4)]
            new_runs = [run_repetition(new_spec, fixture, args.java.resolve(), args.java_home.resolve(), index) for index in range(1, 4)]
            checks = validate_repetitions(old_runs, new_runs)
            protocol_after = tree_sha256(protocol_root)
            if protocol_after != protocol_before:
                raise QualificationError("FAIL", "frozen protocol tree changed during qualification")
            supporting = (
                "results/detector_only_joint_500_v1/sd300b/roll_self/"
                "sourceafis_final_minutiae_rootsift_geometric/run_metadata.json"
            )
            build_candidate_package(
                candidate, fixture, environment, old_runs, new_runs, checks, old_hash, new_hash,
                protocol_before, protocol_after, new_root, supporting, dirty_before,
            )
        publish_candidate(candidate, args.output_root.resolve(), args.replace)
        validate_repository_bindings(args.output_root.resolve(), new_root)
        return {"status": "PASS", "qualification_id": QUALIFICATION_ID, "subject_id": fixture.subject_id}
    finally:
        if candidate.exists():
            shutil.rmtree(candidate)
        if new_target.exists():
            shutil.rmtree(new_target)
        if temp_parent.exists():
            try:
                temp_parent.rmdir()
            except OSError:
                pass


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--new-repository-root", type=Path, required=True)
    value.add_argument("--old-repository-root", type=Path, required=True)
    value.add_argument("--curation-root", type=Path, required=True)
    value.add_argument("--dataset-root", type=Path, required=True)
    value.add_argument("--output-root", type=Path, required=True)
    value.add_argument("--java", type=Path, required=True)
    value.add_argument("--javac", type=Path, required=True)
    value.add_argument("--java-home", type=Path, required=True)
    value.add_argument("--maven", type=Path, required=True)
    value.add_argument("--validation-only", action="store_true")
    value.add_argument("--replace", action="store_true")
    return value


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        result = run_qualification(args)
        print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False))
        return 0
    except QualificationError as exc:
        print(json.dumps({"status": exc.status, "reason": exc.reason}, ensure_ascii=False, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
