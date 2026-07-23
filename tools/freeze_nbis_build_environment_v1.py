"""Orchestrate the isolated, reproducible NBIS 5.0.0 build freeze.

The tool never accepts biometric inputs.  Its fixed source is the official
NBIS 5.0.0 archive, verified with ``nbis_source_tree_identity_v2``.  Full
logs, archives, source trees, executables, and WSL exports remain outside Git.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


FREEZE_ID = "nbis_build_environment_v1"
FREEZE_VERSION = 1
PREREQUISITE_ID = "NBIS_BUILD_ENVIRONMENT_FREEZE_V1"
ENVIRONMENT_ID = "wsl2_ubuntu_24_04_lts_x86_64"
DISTRO_NAME = "NBIS-BUILD-V1"
VERIFY_DISTRO_NAME = "NBIS-BUILD-V1-VERIFY"
UBUNTU_WSL_FILENAME = "ubuntu-24.04.4-wsl-amd64.wsl"
UBUNTU_WSL_URL = f"https://releases.ubuntu.com/noble/{UBUNTU_WSL_FILENAME}"
UBUNTU_WSL_SHA256SUMS_URL = "https://releases.ubuntu.com/noble/SHA256SUMS"
UBUNTU_WSL_SHA256 = "9b2f7730dc68227dd04a9f3e5eab86ad85caf556b8606ad94f1f29ff5c4fd3f5"
AUDIT_TAG = "nbis-candidate-audit-v1"
AUDIT_COMMIT = "6a14e4c1a960494bc2e1a8a9c351790f6cc2d571"
ERRATUM_TAG = "nbis-candidate-audit-v1-erratum1"
ERRATUM_COMMIT = "d5f8122a1b76ff79556d909155f8e3b586adcabc"
SOURCEAFIS_TAG = "sourceafis-policy-application-v1"
SOURCEAFIS_COMMIT = "241dfe41eb8d07a3c6b953b6114040637c4f3012"
ARCHIVE_FILENAME = "nbis_v5_0_0.zip"
ARCHIVE_SHA256 = "0adf8ab0f6b0e4208de50ca00ba21d3d77112ecd66288757ddfed21f6bee92c3"
ARCHIVE_SIZE = 52_595_795
SOURCE_FILE_COUNT = 3_879
SOURCE_ALGORITHM = "nbis_source_tree_identity_v2"
SOURCE_TREE_SHA256 = "00ae5eff70693fa5647e3ff57232eff7abd623e4786c110a3286ac8614ac7f3e"
ARCHIVE_LAYOUT_SHA256 = "1338ea21b50a084ec4d724449af226b129aedaf70a184109590f7cb64251d2d8"
MINDTCT_SUBTREE_SHA256 = "6271302a7a049102d7cc0fa078d2d393cbd3647d6cc59c037bf71d915e51ed2f"
BOZORTH3_SUBTREE_SHA256 = "ae2ac6cefee221a62716d941498d64e06e39eb60716936243459756cb5cb1ef8"
PROHIBITED_V1_HASH = "058aeb4638644f998109371c821acb75649d39ee411429fef268f6e4c1ae5bc9"
BUILD_USER = "nbisbuild"
BUILD_UID = 2000
BUILD_GID = 2000
CANONICAL_INSTALL = "/opt/nbis/5.0.0"
FIXED_PACKAGES = ("binutils", "build-essential", "file", "unzip")
PHASES = (
    "preflight", "install-wsl", "configure", "build", "export",
    "restore-check", "package", "all",
)
PROTECTED_AREAS = (
    "protocols", "qualification", "policies", "executions", "evaluations",
    "audits/nbis_candidate_v1", "audits/nbis_candidate_v1_erratum_1",
    "migration", "migration-audit", "src/fingerprint_benchmark",
    "apps/sourceafis-sidecar",
)


class FreezeError(RuntimeError):
    """A controlled freeze failure that must not be hidden."""


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def canonical_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def decode_process_output(value: bytes) -> str:
    if not value:
        return ""
    if value.count(b"\x00") > len(value) // 8:
        return value.decode("utf-16-le", errors="replace")
    return value.decode("utf-8", errors="replace")


def normalized_lines(value: str) -> list[str]:
    return [line.rstrip() for line in value.replace("\r\n", "\n").replace("\r", "\n").split("\n")]


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json_bytes(value))


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def windows_to_wsl(path: Path) -> str:
    resolved = path.resolve()
    drive = resolved.drive.rstrip(":").casefold()
    suffix = resolved.as_posix().split(":", 1)[1]
    return f"/mnt/{drive}{suffix}"


def command_record(command: Iterable[str], stdout: bytes, stderr: bytes, returncode: int) -> dict[str, Any]:
    return {
        "command": list(command),
        "exit_code": returncode,
        "stderr_bytes": len(stderr),
        "stderr_sha256": sha256_bytes(stderr),
        "stdout_bytes": len(stdout),
        "stdout_sha256": sha256_bytes(stdout),
    }


@dataclass(frozen=True)
class Context:
    repository_root: Path
    workspace_root: Path
    archive: Path

    @property
    def receipts(self) -> Path:
        return self.workspace_root / "receipts"

    @property
    def logs(self) -> Path:
        return self.workspace_root / "logs"

    @property
    def exports(self) -> Path:
        return self.workspace_root / "exports"

    @property
    def bootstrap(self) -> Path:
        return self.workspace_root / "bootstrap"

    @property
    def wsl_root(self) -> Path:
        return self.workspace_root / "wsl"


def run_command(
    ctx: Context,
    label: str,
    command: list[str],
    *,
    check: bool = True,
    input_bytes: bytes | None = None,
) -> tuple[subprocess.CompletedProcess[bytes], dict[str, Any]]:
    started = utc_now()
    completed = subprocess.run(
        command,
        cwd=ctx.repository_root,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    ended = utc_now()
    ctx.logs.mkdir(parents=True, exist_ok=True)
    (ctx.logs / f"{label}.stdout.log").write_bytes(completed.stdout)
    (ctx.logs / f"{label}.stderr.log").write_bytes(completed.stderr)
    record = command_record(command, completed.stdout, completed.stderr, completed.returncode)
    record.update({"ended_utc": ended, "label": label, "started_utc": started})
    if check and completed.returncode != 0:
        stderr = decode_process_output(completed.stderr).strip()
        raise FreezeError(f"command failed ({label}, exit {completed.returncode}): {stderr[-1000:]}")
    return completed, record


def run_wsl(
    ctx: Context,
    label: str,
    script: str,
    *,
    distro: str = DISTRO_NAME,
    user: str = "root",
    check: bool = True,
) -> tuple[str, dict[str, Any]]:
    command = [
        "wsl.exe", "--distribution", distro, "--user", user,
        "--exec", "bash", "-lc", script,
    ]
    completed, record = run_command(ctx, label, command, check=check)
    return decode_process_output(completed.stdout), record


def list_distros(ctx: Context) -> set[str]:
    completed, _ = run_command(ctx, "wsl-list-quiet", ["wsl.exe", "--list", "--quiet"], check=False)
    return {line.strip() for line in normalized_lines(decode_process_output(completed.stdout)) if line.strip()}


def git_output(ctx: Context, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", *arguments], cwd=ctx.repository_root, check=False,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        raise FreezeError(decode_process_output(completed.stderr).strip())
    return decode_process_output(completed.stdout).strip()


def load_identity_module(repository_root: Path):
    path = repository_root / "tools" / "recompute_nbis_source_tree_identity_v2.py"
    spec = importlib.util.spec_from_file_location("nbis_source_tree_identity_v2_freeze", path)
    if spec is None or spec.loader is None:
        raise FreezeError("cannot load source-tree identity v2 tool")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def verified_archive_identity(ctx: Context) -> tuple[dict[str, Any], bytes]:
    identity = load_identity_module(ctx.repository_root)
    summary, manifest = identity.compute_identity(ctx.archive, ARCHIVE_SHA256)
    errors = identity.validate_official_identity(summary)
    if errors:
        raise FreezeError("; ".join(errors))
    if summary["canonical_release_root_tree_sha256"] != SOURCE_TREE_SHA256:
        raise FreezeError("corrected canonical source identity mismatch")
    if PROHIBITED_V1_HASH in json.dumps(summary):
        raise FreezeError("prohibited non-reproducible source identity was accepted")
    return summary, manifest


def verify_git_baseline(ctx: Context, *, require_clean: bool = True) -> dict[str, Any]:
    branch = git_output(ctx, "branch", "--show-current")
    status = git_output(ctx, "status", "--porcelain=v1", "--untracked-files=all")
    tags = {
        AUDIT_TAG: git_output(ctx, "rev-parse", f"{AUDIT_TAG}^{{commit}}"),
        ERRATUM_TAG: git_output(ctx, "rev-parse", f"{ERRATUM_TAG}^{{commit}}"),
        SOURCEAFIS_TAG: git_output(ctx, "rev-parse", f"{SOURCEAFIS_TAG}^{{commit}}"),
    }
    expected = {AUDIT_TAG: AUDIT_COMMIT, ERRATUM_TAG: ERRATUM_COMMIT, SOURCEAFIS_TAG: SOURCEAFIS_COMMIT}
    if branch != "main" or tags != expected:
        raise FreezeError("branch or provenance tag baseline mismatch")
    if require_clean and status:
        raise FreezeError("worktree is not clean")
    for commit in (AUDIT_COMMIT, ERRATUM_COMMIT):
        result = subprocess.run(
            ["git", "merge-base", "--is-ancestor", commit, "HEAD"],
            cwd=ctx.repository_root, check=False,
        )
        if result.returncode != 0:
            raise FreezeError(f"required provenance commit is not an ancestor: {commit}")
    return {"branch": branch, "head": git_output(ctx, "rev-parse", "HEAD"), "status_clean": not status, "tags": tags}


def preflight_data(ctx: Context, *, require_clean: bool = True) -> dict[str, Any]:
    git = verify_git_baseline(ctx, require_clean=require_clean)
    archive, _ = verified_archive_identity(ctx)
    commands: dict[str, Any] = {}
    outputs: dict[str, str] = {}
    for label, args in (
        ("status", ["wsl.exe", "--status"]),
        ("version", ["wsl.exe", "--version"]),
        ("help", ["wsl.exe", "--help"]),
        ("list_verbose", ["wsl.exe", "--list", "--verbose"]),
        ("list_online", ["wsl.exe", "--list", "--online"]),
    ):
        completed, record = run_command(
            ctx, f"preflight-wsl-{label}", args, check=label not in {"help", "list_verbose"}
        )
        commands[label] = record
        outputs[label] = decode_process_output(completed.stdout) + decode_process_output(completed.stderr)
    if "--from-file" not in outputs["help"] or "--name" not in outputs["help"]:
        raise FreezeError("installed WSL does not support direct named installation from a file")
    distros = sorted(list_distros(ctx), key=str.casefold)
    return {
        "archive_identity": archive,
        "commands": commands,
        "existing_distributions": distros,
        "freeze_id": FREEZE_ID,
        "git": git,
        "official_image": {
            "filename": UBUNTU_WSL_FILENAME,
            "sha256": UBUNTU_WSL_SHA256,
            "sha256sums_url": UBUNTU_WSL_SHA256SUMS_URL,
            "url": UBUNTU_WSL_URL,
        },
        "preflight_utc": utc_now(),
        "wsl_status": outputs["status"],
        "wsl_version": outputs["version"],
    }


def phase_preflight(ctx: Context, *, write_receipt_file: bool = True) -> dict[str, Any]:
    data = preflight_data(ctx)
    if write_receipt_file:
        write_json(ctx.receipts / "wsl_install_receipt.json", data)
    return data


def _require_canonical_release_url(url: str) -> None:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != "releases.ubuntu.com":
        raise FreezeError(f"Ubuntu release request resolved outside Canonical: {url}")


def acquire_official_wsl_image(ctx: Context) -> tuple[Path, dict[str, Any]]:
    """Acquire and authenticate Canonical's pinned Ubuntu 24.04 WSL image."""

    ctx.bootstrap.mkdir(parents=True, exist_ok=True)
    image = ctx.bootstrap / UBUNTU_WSL_FILENAME
    partial = image.with_suffix(image.suffix + ".partial")
    if partial.exists():
        raise FreezeError(f"incomplete WSL image download requires review: {partial}")

    user_agent = f"{FREEZE_ID}/1 provenance-freeze"
    sums_request = urllib.request.Request(
        UBUNTU_WSL_SHA256SUMS_URL, headers={"User-Agent": user_agent}
    )
    with urllib.request.urlopen(sums_request, timeout=60) as response:
        _require_canonical_release_url(response.geturl())
        sums_bytes = response.read()
        sums_resolved_url = response.geturl()
        sums_headers = dict(response.headers.items())
    expected_line = f"{UBUNTU_WSL_SHA256} *{UBUNTU_WSL_FILENAME}"
    sums_text = sums_bytes.decode("utf-8", errors="strict")
    if expected_line not in sums_text.splitlines():
        raise FreezeError("pinned Ubuntu WSL image is absent from Canonical SHA256SUMS")

    reused = image.exists()
    resolved_url = UBUNTU_WSL_URL
    image_headers: dict[str, str] = {}
    if not reused:
        image_request = urllib.request.Request(UBUNTU_WSL_URL, headers={"User-Agent": user_agent})
        digest = hashlib.sha256()
        total = 0
        try:
            with urllib.request.urlopen(image_request, timeout=60) as response, partial.open("xb") as output:
                _require_canonical_release_url(response.geturl())
                resolved_url = response.geturl()
                image_headers = dict(response.headers.items())
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    output.write(chunk)
                    digest.update(chunk)
                    total += len(chunk)
            if digest.hexdigest() != UBUNTU_WSL_SHA256:
                raise FreezeError("downloaded Ubuntu WSL image SHA-256 mismatch")
            partial.replace(image)
        except BaseException:
            partial.unlink(missing_ok=True)
            raise
    actual_sha256 = file_sha256(image)
    if actual_sha256 != UBUNTU_WSL_SHA256:
        raise FreezeError("cached Ubuntu WSL image SHA-256 mismatch")
    metadata = {
        "bytes": image.stat().st_size,
        "download_reused": reused,
        "filename": UBUNTU_WSL_FILENAME,
        "http_headers": {
            key: value for key, value in image_headers.items()
            if key.casefold() in {"content-length", "etag", "last-modified"}
        },
        "publisher": "Canonical",
        "resolved_url": resolved_url,
        "retrieval_utc": utc_now(),
        "sha256": actual_sha256,
        "sha256sums_bytes": len(sums_bytes),
        "sha256sums_resolved_url": sums_resolved_url,
        "sha256sums_sha256": sha256_bytes(sums_bytes),
        "sha256sums_headers": {
            key: value for key, value in sums_headers.items()
            if key.casefold() in {"content-length", "etag", "last-modified"}
        },
        "source_url": UBUNTU_WSL_URL,
    }
    return image, metadata


def phase_install_wsl(ctx: Context) -> dict[str, Any]:
    preflight = preflight_data(ctx)
    existing = set(preflight["existing_distributions"])
    if DISTRO_NAME in existing:
        os_release, _ = run_wsl(ctx, "existing-distro-os-release", "cat /etc/os-release; uname -m")
        if 'VERSION_ID="24.04"' not in os_release or "x86_64" not in os_release:
            raise FreezeError("existing canonical WSL distribution has unknown or conflicting identity")
        receipt_path = ctx.receipts / "distribution_acquisition_receipt.json"
        if not receipt_path.is_file():
            raise FreezeError("existing canonical distro lacks its acquisition receipt")
        receipt = read_json(receipt_path)
        expected = {
            "acquisition_method": "official_canonical_wsl_image_from_file",
            "canonical_distribution": DISTRO_NAME,
            "publisher": "Canonical",
            "release": "24.04 LTS",
            "rootfs_image_sha256": UBUNTU_WSL_SHA256,
            "wsl_generation": 2,
        }
        if any(receipt.get(key) != value for key, value in expected.items()):
            raise FreezeError("existing canonical distro acquisition receipt mismatch")
        return receipt
    ctx.wsl_root.mkdir(parents=True, exist_ok=True)
    canonical_location = ctx.wsl_root / DISTRO_NAME
    if canonical_location.exists():
        raise FreezeError("canonical WSL location exists without a registered canonical distro")
    image, acquisition = acquire_official_wsl_image(ctx)
    _, install_record = run_command(
        ctx, "install-official-ubuntu-24-04",
        [
            "wsl.exe", "--install", "--from-file", str(image),
            "--name", DISTRO_NAME, "--location", str(canonical_location),
            "--version", "2", "--no-launch",
        ],
    )
    if DISTRO_NAME not in list_distros(ctx):
        raise FreezeError("Windows restart required to complete WSL2 activation")
    os_release, identity_record = run_wsl(ctx, "canonical-distro-identity", "cat /etc/os-release; uname -m")
    if 'VERSION_ID="24.04"' not in os_release or "x86_64" not in os_release:
        raise FreezeError("installed canonical distribution identity mismatch")
    receipt = {
        "acquisition_method": "official_canonical_wsl_image_from_file",
        "architecture": "x86_64",
        "canonical_distribution": DISTRO_NAME,
        "distribution": "Ubuntu",
        "distribution_created_by_task": True,
        "freeze_id": FREEZE_ID,
        "official": True,
        "official_image": acquisition,
        "os_release_and_architecture": os_release,
        "publisher": "Canonical",
        "release": "24.04 LTS",
        "rootfs_image_bytes": acquisition["bytes"],
        "rootfs_image_sha256": acquisition["sha256"],
        "retrieval_utc": utc_now(),
        "wsl_generation": 2,
        "commands": {
            "install": install_record, "identity": identity_record,
        },
    }
    write_json(ctx.receipts / "distribution_acquisition_receipt.json", receipt)
    return receipt


def package_version_script() -> str:
    packages = " ".join(FIXED_PACKAGES)
    return f"""
set -euo pipefail
export LC_ALL=C LANG=C TZ=UTC DEBIAN_FRONTEND=noninteractive
umask 022
packages=({packages})
specs=()
for package in "${{packages[@]}}"; do
  version=$(apt-cache policy "$package" | awk '/Candidate:/ {{print $2}}')
  test -n "$version" && test "$version" != "(none)"
  specs+=("$package=$version")
done
printf '%s\n' "${{specs[@]}}"
apt-get install -y --no-install-recommends "${{specs[@]}}"
""".strip()


def phase_configure(ctx: Context) -> dict[str, Any]:
    verified_archive_identity(ctx)
    if DISTRO_NAME not in list_distros(ctx):
        raise FreezeError("canonical WSL distribution is missing")
    receipt_path = ctx.receipts / "package_install_receipt.json"
    if receipt_path.is_file():
        return read_json(receipt_path)

    archive_copy = "/opt/nbis-input/nbis_v5_0_0.zip"
    mounted_archive = windows_to_wsl(ctx.archive)
    setup_script = f"""
set -euo pipefail
export LC_ALL=C LANG=C TZ=UTC DEBIAN_FRONTEND=noninteractive
umask 022
getent group {BUILD_GID} >/dev/null || groupadd --gid {BUILD_GID} {BUILD_USER}
id -u {BUILD_USER} >/dev/null 2>&1 || useradd --uid {BUILD_UID} --gid {BUILD_GID} --create-home --shell /bin/bash {BUILD_USER}
test "$(id -u {BUILD_USER})" = "{BUILD_UID}"
test "$(id -g {BUILD_USER})" = "{BUILD_GID}"
install -d -o root -g root -m 0755 /opt/nbis-input /opt/nbis
install -d -o {BUILD_USER} -g {BUILD_USER} -m 0755 {CANONICAL_INSTALL}
install -m 0644 '{mounted_archive}' '{archive_copy}'
echo '{ARCHIVE_SHA256}  {archive_copy}' | sha256sum --check --strict
apt-get update
""".strip()
    _, setup_record = run_wsl(ctx, "configure-user-source-and-apt", setup_script)
    install_output, install_record = run_wsl(ctx, "install-pinned-build-packages", package_version_script())

    inventory_script = """
set -euo pipefail
export LC_ALL=C LANG=C TZ=UTC
printf '%s\n' '===OS_RELEASE==='; cat /etc/os-release
printf '%s\n' '===UNAME==='; uname -a
printf '%s\n' '===LONG_BIT==='; getconf LONG_BIT
printf '%s\n' '===GCC==='; command -v gcc; gcc --version
printf '%s\n' '===CC==='; command -v cc; cc --version
printf '%s\n' '===MAKE==='; command -v make; make --version
printf '%s\n' '===GMAKE==='; command -v gmake || true; gmake --version 2>/dev/null || true
printf '%s\n' '===BASH==='; command -v bash; bash --version
printf '%s\n' '===LIBC==='; ldd --version
printf '%s\n' '===BINUTILS==='; command -v readelf; readelf --version
printf '%s\n' '===PACKAGES==='; dpkg-query -W -f='${Package}\t${Version}\n' | sort
printf '%s\n' '===MANUAL==='; apt-mark showmanual | sort
printf '%s\n' '===APT_SOURCES==='; find /etc/apt -maxdepth 2 -type f \\( -name '*.list' -o -name '*.sources' \\) -print0 | sort -z | xargs -0 -r sha256sum
printf '%s\n' '===DPKG_STATUS==='; sha256sum /var/lib/dpkg/status
printf '%s\n' '===PACKAGE_POLICY==='; apt-cache policy binutils build-essential file unzip
""".strip()
    inventory, inventory_record = run_wsl(ctx, "capture-toolchain-package-inventory", inventory_script)
    installed_specs = [line for line in normalized_lines(install_output) if re.fullmatch(r"[a-z0-9+.-]+=[^\s]+", line)]
    receipt = {
        "apt_upgrade_performed": False,
        "archive_copied_to_linux_filesystem": True,
        "archive_sha256": ARCHIVE_SHA256,
        "commands": {"configure": setup_record, "install": install_record, "inventory": inventory_record},
        "fixed_environment": {"LANG": "C", "LC_ALL": "C", "TZ": "UTC", "umask": "022"},
        "freeze_id": FREEZE_ID,
        "installed_package_specs": installed_specs,
        "inventory_bytes": len(inventory.encode("utf-8")),
        "inventory_sha256": sha256_bytes(inventory.encode("utf-8")),
        "package_sources_official_ubuntu_only": "ubuntu.com" in inventory and "ppa.launchpad" not in inventory,
        "third_party_repository_used": False,
        "toolchain_inventory": inventory,
        "user": {"gid": BUILD_GID, "home": "/home/nbisbuild", "shell": "/bin/bash", "uid": BUILD_UID},
    }
    if not receipt["package_sources_official_ubuntu_only"]:
        raise FreezeError("package sources are not demonstrably official Ubuntu repositories")
    write_json(receipt_path, receipt)
    return receipt


def extracted_identity_script(root: str) -> str:
    return f"""
set -euo pipefail
export LC_ALL=C LANG=C TZ=UTC
cd '{root}'
count=0
while IFS= read -r path; do
  test -f "$path"
  digest=$(sha256sum -- "$path" | awk '{{print $1}}')
  size=$(stat -c %s -- "$path")
  printf '%s  %s  %s\n' "$digest" "$size" "$path"
  count=$((count+1))
done < /opt/nbis-input/source-paths.txt > /tmp/nbis-source-identity.manifest
test "$count" = "{SOURCE_FILE_COUNT}"
printf 'file_count=%s\n' "$count"
printf 'tree_sha256=%s\n' "$(sha256sum /tmp/nbis-source-identity.manifest | awk '{{print $1}}')"
rm -f /tmp/nbis-source-identity.manifest
""".strip()


def parse_key_values(value: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in normalized_lines(value):
        if "=" in line:
            key, item = line.split("=", 1)
            result[key.strip()] = item.strip()
    return result


def executable_metadata(ctx: Context, install_root: str, label: str) -> tuple[dict[str, Any], dict[str, Any]]:
    script = f"""
set -euo pipefail
export LC_ALL=C LANG=C TZ=UTC
for name in mindtct bozorth3; do
  path='{install_root}/bin/'$name
  test -x "$path"
  printf '%s.path=%s\n' "$name" "$path"
  printf '%s.bytes=%s\n' "$name" "$(stat -c %s "$path")"
  printf '%s.sha256=%s\n' "$name" "$(sha256sum "$path" | awk '{{print $1}}')"
  printf '%s.file=%s\n' "$name" "$(file -b "$path")"
  printf '%s.interpreter=%s\n' "$name" "$(readelf -l "$path" | sed -n 's/.*interpreter: \\(.*\\)]/\\1/p')"
  printf '%s.dependencies_sha256=%s\n' "$name" "$(ldd "$path" | LC_ALL=C sort | sha256sum | awk '{{print $1}}')"
  printf '%s.dynamic_sha256=%s\n' "$name" "$(readelf -d "$path" | sha256sum | awk '{{print $1}}')"
  printf '%s.symbols_sha256=%s\n' "$name" "$(readelf -Ws "$path" | sed 's/[[:space:]]\\+/ /g' | sha256sum | awk '{{print $1}}')"
  text_file=$(mktemp); rodata_file=$(mktemp)
  objcopy --dump-section .text="$text_file" "$path"
  objcopy --dump-section .rodata="$rodata_file" "$path"
  printf '%s.text_sha256=%s\n' "$name" "$(sha256sum "$text_file" | awk '{{print $1}}')"
  printf '%s.rodata_sha256=%s\n' "$name" "$(sha256sum "$rodata_file" | awk '{{print $1}}')"
  rm -f "$text_file" "$rodata_file"
done
printf 'installed_file_count=%s\n' "$(find '{install_root}' -type f | wc -l)"
""".strip()
    output, record = run_wsl(ctx, f"{label}-executable-metadata", script, user=BUILD_USER)
    values = parse_key_values(output)
    result: dict[str, Any] = {"installed_file_count": int(values["installed_file_count"]), "executables": {}}
    for name in ("mindtct", "bozorth3"):
        result["executables"][name] = {
            "bytes": int(values[f"{name}.bytes"]),
            "dependencies_sha256": values[f"{name}.dependencies_sha256"],
            "dynamic_sha256": values[f"{name}.dynamic_sha256"],
            "file": values[f"{name}.file"],
            "interpreter": values[f"{name}.interpreter"],
            "path": values[f"{name}.path"],
            "rodata_sha256": values[f"{name}.rodata_sha256"],
            "sha256": values[f"{name}.sha256"],
            "symbols_sha256": values[f"{name}.symbols_sha256"],
            "text_sha256": values[f"{name}.text_sha256"],
        }
    return result, record


def phase_build(ctx: Context) -> dict[str, Any]:
    summary, manifest = verified_archive_identity(ctx)
    phase_configure(ctx)
    final_receipt = ctx.receipts / "canonical_install_receipt.json"
    if final_receipt.is_file():
        return read_json(final_receipt)

    source_cache = ctx.workspace_root / "source-archives"
    source_cache.mkdir(parents=True, exist_ok=True)
    paths_file = source_cache / "source-paths.txt"
    paths_file.write_text(
        "".join(line.split("  ", 2)[2] + "\n" for line in manifest.decode("utf-8").splitlines()),
        encoding="utf-8", newline="\n",
    )
    mounted_paths = windows_to_wsl(paths_file)
    run_wsl(
        ctx, "install-source-path-list",
        f"install -m 0644 '{mounted_paths}' /opt/nbis-input/source-paths.txt && chown root:root /opt/nbis-input/source-paths.txt",
    )

    build_receipts: dict[str, Any] = {}
    for build_id, suffix in (("BUILD_A", "a"), ("BUILD_B", "b")):
        receipt_path = ctx.receipts / f"build_{suffix}_receipt.json"
        if receipt_path.is_file():
            build_receipts[build_id] = read_json(receipt_path)
            continue
        build_parent = f"/home/{BUILD_USER}/build-{suffix}"
        source_root = f"{build_parent}/Rel_5.0.0"
        install_root = f"/home/{BUILD_USER}/install-{suffix}"
        prepare_script = f"""
set -euo pipefail
export LC_ALL=C LANG=C TZ=UTC
umask 022
test ! -e '{build_parent}'
test ! -e '{install_root}'
mkdir -p '{build_parent}' '{install_root}'
unzip -q /opt/nbis-input/{ARCHIVE_FILENAME} -d '{build_parent}'
""".strip()
        _, prepare_record = run_wsl(ctx, f"build-{suffix}-clean-extraction", prepare_script, user=BUILD_USER)
        before_output, before_record = run_wsl(
            ctx, f"build-{suffix}-source-identity-before", extracted_identity_script(source_root), user=BUILD_USER
        )
        before_identity = parse_key_values(before_output)
        if before_identity != {"file_count": str(SOURCE_FILE_COUNT), "tree_sha256": SOURCE_TREE_SHA256}:
            raise FreezeError(f"{build_id} source identity before build mismatch")
        command_script = f"""
set -euo pipefail
export LC_ALL=C LANG=C TZ=UTC
umask 022
cd '{source_root}'
./setup.sh '{install_root}' --without-X11 --without-OPENJP2 --64
make config
make it
make install LIBNBIS=no
""".strip()
        build_output, build_record = run_wsl(ctx, f"build-{suffix}-official-build", command_script, user=BUILD_USER)
        after_output, after_record = run_wsl(
            ctx, f"build-{suffix}-source-identity-after", extracted_identity_script(source_root), user=BUILD_USER
        )
        after_identity = parse_key_values(after_output)
        if after_identity != before_identity:
            raise FreezeError(f"{build_id} original source entries changed during build")
        metadata, metadata_record = executable_metadata(ctx, install_root, f"build-{suffix}")
        receipt = {
            "build_id": build_id,
            "commands": {
                "clean_extraction": prepare_record, "official_build": build_record,
                "source_before": before_record, "source_after": after_record,
                "metadata": metadata_record,
            },
            "custom_flags_used": False,
            "environment": {"LANG": "C", "LC_ALL": "C", "TZ": "UTC", "umask": "022"},
            "executables": metadata["executables"],
            "freeze_id": FREEZE_ID,
            "installed_file_count": metadata["installed_file_count"],
            "official_command_sequence": [
                "./setup.sh <INSTALL_ROOT> --without-X11 --without-OPENJP2 --64",
                "make config", "make it", "make install LIBNBIS=no",
            ],
            "source_file_count": int(before_identity["file_count"]),
            "source_modified": False,
            "source_tree_sha256_after": after_identity["tree_sha256"],
            "source_tree_sha256_before": before_identity["tree_sha256"],
            "stderr_error_count": 0,
            "warning_count": build_output.casefold().count("warning:"),
        }
        write_json(receipt_path, receipt)
        build_receipts[build_id] = receipt

    for name in ("mindtct", "bozorth3"):
        first = build_receipts["BUILD_A"]["executables"][name]
        second = build_receipts["BUILD_B"]["executables"][name]
        if first["sha256"] != second["sha256"]:
            controlled = all(first[key] == second[key] for key in (
                "text_sha256", "rodata_sha256", "dependencies_sha256", "dynamic_sha256", "symbols_sha256"
            ))
            if not controlled:
                raise FreezeError(f"uncontrolled executable variance: {name}")

    canonical_copy_script = f"""
set -euo pipefail
test -d '{CANONICAL_INSTALL}'
test -z "$(find '{CANONICAL_INSTALL}' -mindepth 1 -print -quit)"
cp -a '/home/{BUILD_USER}/install-a/.' '{CANONICAL_INSTALL}/'
chown -R root:root '{CANONICAL_INSTALL}'
""".strip()
    _, copy_record = run_wsl(ctx, "create-canonical-install", canonical_copy_script)
    canonical_metadata, metadata_record = executable_metadata(ctx, CANONICAL_INSTALL, "canonical",)
    for name in ("mindtct", "bozorth3"):
        if canonical_metadata["executables"][name]["sha256"] != build_receipts["BUILD_A"]["executables"][name]["sha256"]:
            raise FreezeError(f"canonical executable identity mismatch: {name}")
    smoke_script = f"""
set +e
export LC_ALL=C LANG=C TZ=UTC
'{CANONICAL_INSTALL}/bin/mindtct' >/tmp/mindtct.out 2>/tmp/mindtct.err; m1=$?
'{CANONICAL_INSTALL}/bin/mindtct' /definitely/missing/input /tmp/never-created >/tmp/mindtct-missing.out 2>/tmp/mindtct-missing.err; m2=$?
'{CANONICAL_INSTALL}/bin/bozorth3' >/tmp/bozorth3.out 2>/tmp/bozorth3.err; b1=$?
'{CANONICAL_INSTALL}/bin/bozorth3' /definitely/missing.xyt >/tmp/bozorth3-missing.out 2>/tmp/bozorth3-missing.err; b2=$?
printf 'mindtct_usage_exit=%s\n' "$m1"
printf 'mindtct_missing_exit=%s\n' "$m2"
printf 'bozorth3_usage_exit=%s\n' "$b1"
printf 'bozorth3_missing_exit=%s\n' "$b2"
for item in /tmp/mindtct.out /tmp/mindtct.err /tmp/mindtct-missing.out /tmp/mindtct-missing.err /tmp/bozorth3.out /tmp/bozorth3.err /tmp/bozorth3-missing.out /tmp/bozorth3-missing.err; do
  printf '%s=%s\n' "$(basename "$item").sha256" "$(sha256sum "$item" | awk '{{print $1}}')"
done
rm -f /tmp/mindtct.out /tmp/mindtct.err /tmp/mindtct-missing.out /tmp/mindtct-missing.err /tmp/bozorth3.out /tmp/bozorth3.err /tmp/bozorth3-missing.out /tmp/bozorth3-missing.err
exit 0
""".strip()
    smoke_output, smoke_record = run_wsl(ctx, "non-biometric-smoke-checks", smoke_script, user=BUILD_USER)
    receipt = {
        "build_a": build_receipts["BUILD_A"],
        "build_b": build_receipts["BUILD_B"],
        "canonical_build": "BUILD_A",
        "canonical_install": CANONICAL_INSTALL,
        "commands": {"copy": copy_record, "metadata": metadata_record, "smoke": smoke_record},
        "executables": canonical_metadata["executables"],
        "fingerprint_images_read": False,
        "fixture_processed": False,
        "freeze_id": FREEZE_ID,
        "installed_file_count": canonical_metadata["installed_file_count"],
        "minutiae_generated": False,
        "official_source_identity": summary["canonical_release_root_tree_sha256"],
        "scores_generated": False,
        "smoke_results": parse_key_values(smoke_output),
    }
    write_json(final_receipt, receipt)
    return receipt


def phase_export(ctx: Context) -> dict[str, Any]:
    canonical = phase_build(ctx)
    receipt_path = ctx.receipts / "environment_export_receipt.json"
    export_path = ctx.exports / f"{DISTRO_NAME}.tar"
    if receipt_path.is_file():
        receipt = read_json(receipt_path)
        if not export_path.is_file() or file_sha256(export_path) != receipt["export_sha256"]:
            raise FreezeError("existing export does not match its locked receipt")
        return receipt
    if export_path.exists():
        raise FreezeError("existing export lacks a matching receipt")
    ctx.exports.mkdir(parents=True, exist_ok=True)
    run_wsl(ctx, "clean-package-cache", "apt-get clean")
    _, terminate_record = run_command(ctx, "terminate-canonical-before-export", ["wsl.exe", "--terminate", DISTRO_NAME])
    _, export_record = run_command(ctx, "export-canonical-distro", ["wsl.exe", "--export", DISTRO_NAME, str(export_path)])
    receipt = {
        "canonical_executables": {name: value["sha256"] for name, value in canonical["executables"].items()},
        "commands": {"terminate": terminate_record, "export": export_record},
        "created_utc": utc_now(),
        "distribution": DISTRO_NAME,
        "export_bytes": export_path.stat().st_size,
        "export_sha256": file_sha256(export_path),
        "freeze_id": FREEZE_ID,
        "stored_outside_git": True,
    }
    write_json(receipt_path, receipt)
    return receipt


def phase_restore_check(ctx: Context) -> dict[str, Any]:
    export_receipt = phase_export(ctx)
    canonical = read_json(ctx.receipts / "canonical_install_receipt.json")
    package_receipt = read_json(ctx.receipts / "package_install_receipt.json")
    receipt_path = ctx.receipts / "restore_verification_receipt.json"
    if receipt_path.is_file():
        return read_json(receipt_path)
    if VERIFY_DISTRO_NAME in list_distros(ctx):
        raise FreezeError("verification distro already exists without a PASS receipt")
    verify_location = ctx.wsl_root / VERIFY_DISTRO_NAME
    if verify_location.exists():
        raise FreezeError("verification install location already exists")
    export_path = ctx.exports / f"{DISTRO_NAME}.tar"
    _, import_record = run_command(
        ctx, "restore-import-verification-distro",
        ["wsl.exe", "--import", VERIFY_DISTRO_NAME, str(verify_location), str(export_path), "--version", "2"],
    )
    verify_script = f"""
set -euo pipefail
export LC_ALL=C LANG=C TZ=UTC
grep -q '^VERSION_ID="24.04"' /etc/os-release
test "$(uname -m)" = "x86_64"
echo '{ARCHIVE_SHA256}  /opt/nbis-input/{ARCHIVE_FILENAME}' | sha256sum --check --strict
printf 'dpkg_status_sha256=%s\n' "$(sha256sum /var/lib/dpkg/status | awk '{{print $1}}')"
for name in mindtct bozorth3; do
  path='{CANONICAL_INSTALL}/bin/'$name
  test -x "$path"
  printf '%s.sha256=%s\n' "$name" "$(sha256sum "$path" | awk '{{print $1}}')"
  printf '%s.ldd_sha256=%s\n' "$name" "$(ldd "$path" | LC_ALL=C sort | sha256sum | awk '{{print $1}}')"
done
set +e
'{CANONICAL_INSTALL}/bin/mindtct' >/tmp/restore-mindtct.out 2>/tmp/restore-mindtct.err
'{CANONICAL_INSTALL}/bin/bozorth3' >/tmp/restore-bozorth3.out 2>/tmp/restore-bozorth3.err
set -e
printf 'smoke_payload_sha256=%s\n' "$(cat /tmp/restore-mindtct.out /tmp/restore-mindtct.err /tmp/restore-bozorth3.out /tmp/restore-bozorth3.err | sha256sum | awk '{{print $1}}')"
rm -f /tmp/restore-mindtct.out /tmp/restore-mindtct.err /tmp/restore-bozorth3.out /tmp/restore-bozorth3.err
""".strip()
    output, verify_record = run_wsl(
        ctx, "restore-verify-identities", verify_script, distro=VERIFY_DISTRO_NAME
    )
    values = parse_key_values(output)
    for name in ("mindtct", "bozorth3"):
        if values.get(f"{name}.sha256") != canonical["executables"][name]["sha256"]:
            raise FreezeError(f"restored executable mismatch: {name}")
    inventory = package_receipt["toolchain_inventory"]
    status_match = re.search(r"===DPKG_STATUS===\n([0-9a-f]{64})", inventory)
    if status_match and values.get("dpkg_status_sha256") != status_match.group(1):
        raise FreezeError("restored dpkg status identity mismatch")
    _, terminate_record = run_command(
        ctx, "terminate-verification-distro", ["wsl.exe", "--terminate", VERIFY_DISTRO_NAME]
    )
    _, unregister_record = run_command(
        ctx, "unregister-verification-distro", ["wsl.exe", "--unregister", VERIFY_DISTRO_NAME]
    )
    receipt = {
        "commands": {"import": import_record, "verify": verify_record, "terminate": terminate_record, "unregister": unregister_record},
        "dataset_accessed": False,
        "export_sha256": export_receipt["export_sha256"],
        "fingerprint_images_read": False,
        "freeze_id": FREEZE_ID,
        "restored_identities": values,
        "scores_generated": False,
        "status": "PASS",
        "verification_distribution_removed_after_pass": True,
    }
    write_json(receipt_path, receipt)
    return receipt


def phase_package(ctx: Context) -> dict[str, Any]:
    # Package material is generated only after successful restore verification.
    restore = phase_restore_check(ctx)
    validator_path = ctx.repository_root / "tools" / "validate_nbis_build_environment_v1.py"
    spec = importlib.util.spec_from_file_location("nbis_freeze_validator_for_package", validator_path)
    if spec is None or spec.loader is None:
        raise FreezeError("cannot load build-environment validator")
    validator = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = validator
    spec.loader.exec_module(validator)
    package_root = ctx.repository_root / "environments" / FREEZE_ID
    if package_root.exists():
        raise FreezeError("freeze evidence package already exists")
    documents = validator.build_documents_from_receipts(ctx.repository_root, ctx.workspace_root)
    package_root.mkdir(parents=True, exist_ok=False)
    (package_root / "README.md").write_text(validator.package_readme(), encoding="utf-8", newline="\n")
    for name, document in documents.items():
        write_json(package_root / name, document)
    code_files = {}
    for name in validator.CODE_FILES:
        path = ctx.repository_root / name
        code_files[name] = {"bytes": path.stat().st_size, "sha256": file_sha256(path)}
    locked_files = {}
    for name in validator.CORE_LOCKED_FILES:
        path = package_root / name
        locked_files[name] = {"bytes": path.stat().st_size, "sha256": file_sha256(path)}
    protected = {
        name: validator.tree_identity(ctx.repository_root / name)
        for name in validator.PROTECTED_AREAS
    }
    plan = documents["environment_plan.json"]
    executables = documents["executable_manifest.json"]["executables"]
    reproducibility = documents["reproducibility_report.json"]
    export_document = documents["export_receipt.json"]
    lock = {
        "artifact_tracking": {
            "binary_tracked": False, "dataset_tracked": False,
            "image_tracked": False, "library_tracked": False,
            "log_tracked": False, "minutiae_tracked": False,
            "rootfs_export_tracked": False, "score_tracked": False,
            "source_archive_tracked": False, "source_tree_tracked": False,
        },
        "audit_baselines": plan["audit_baselines"],
        "build_identities": {
            build_id: documents["build_results.json"]["builds"][build_id]
            for build_id in ("BUILD_A", "BUILD_B")
        },
        "canonical_executable_hashes": {
            name: item["canonical_sha256"] for name, item in executables.items()
        },
        "code_files": code_files,
        "environment_code_commit": git_output(ctx, "rev-parse", "HEAD"),
        "export": {
            "bytes": export_document["export_size_bytes"],
            "sha256": export_document["export_sha256"],
        },
        "files": locked_files,
        "freeze_id": FREEZE_ID,
        "freeze_version": FREEZE_VERSION,
        "official_archive_sha256": ARCHIVE_SHA256,
        "package_manifest_sha256": file_sha256(package_root / "package_manifest.json"),
        "prerequisite_id": PREREQUISITE_ID,
        "prerequisite_status": "RESOLVED",
        "protected_area_tree_hashes": protected,
        "reproducibility_status": reproducibility["status"],
        "restore_verification_status": "PASS",
        "source_identity": {
            "algorithm_id": SOURCE_ALGORITHM,
            "canonical_release_root_sha256": SOURCE_TREE_SHA256,
        },
        "toolchain_manifest_sha256": file_sha256(package_root / "toolchain_manifest.json"),
    }
    write_json(package_root / "environment_lock.json", lock)
    checksum_lines = []
    for name in sorted(set(validator.PACKAGE_FILES).difference({"SHA256SUMS.txt"})):
        checksum_lines.append(f"{file_sha256(package_root / name)}  {name}\n")
    (package_root / "SHA256SUMS.txt").write_text(
        "".join(checksum_lines), encoding="utf-8", newline="\n"
    )
    errors = validator.validate_package(ctx.repository_root)
    if errors:
        raise FreezeError("generated package validation failed: " + "; ".join(errors))
    return {"freeze_id": FREEZE_ID, "package": package_root.as_posix(), "restore_status": restore["status"], "valid": True}


def ensure_context(args: argparse.Namespace, *, mutating: bool) -> Context:
    repository_root = args.repository_root.resolve()
    workspace_root = args.workspace_root.resolve()
    archive = args.archive.resolve()
    if repository_root != Path(__file__).resolve().parents[1]:
        raise FreezeError("repository root does not contain this committed orchestrator")
    if archive.name != ARCHIVE_FILENAME or not archive.is_file():
        raise FreezeError("official NBIS archive is missing or has the wrong filename")
    if mutating:
        workspace_root.mkdir(parents=True, exist_ok=True)
    return Context(repository_root, workspace_root, archive)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--workspace-root", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--phase", choices=PHASES, default="preflight")
    parser.add_argument("--validate-only", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    mutating = not args.validate_only and args.phase != "preflight"
    try:
        ctx = ensure_context(args, mutating=mutating)
        if args.validate_only:
            result = phase_preflight(ctx, write_receipt_file=False)
        else:
            functions = {
                "preflight": phase_preflight,
                "install-wsl": phase_install_wsl,
                "configure": phase_configure,
                "build": phase_build,
                "export": phase_export,
                "restore-check": phase_restore_check,
                "package": phase_package,
            }
            if args.phase == "all":
                result = {}
                for name in PHASES[:-1]:
                    result[name] = functions[name](ctx)
            else:
                result = functions[args.phase](ctx)
    except (FreezeError, OSError, json.JSONDecodeError) as exc:
        print(f"NBIS build environment freeze v1: FAIL: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=True, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
