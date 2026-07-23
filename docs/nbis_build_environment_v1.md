# NBIS reproducible build environment freeze v1

`nbis_build_environment_v1` freezes an isolated Ubuntu 24.04 LTS WSL2
userspace and the evidence for two clean builds of the official, unmodified
NIST NBIS 5.0.0 release. It resolves only
`NBIS_BUILD_ENVIRONMENT_FREEZE_V1`.

## Provenance baseline

The required immutable baselines are:

- `nbis-candidate-audit-v1` at
  `6a14e4c1a960494bc2e1a8a9c351790f6cc2d571`;
- `nbis-candidate-audit-v1-erratum1` at
  `d5f8122a1b76ff79556d909155f8e3b586adcabc`.

The official archive is `nbis_v5_0_0.zip`, SHA-256
`0adf8ab0f6b0e4208de50ca00ba21d3d77112ecd66288757ddfed21f6bee92c3`,
52,595,795 bytes. Its only accepted full-tree identity uses
`nbis_source_tree_identity_v2` and is
`00ae5eff70693fa5647e3ff57232eff7abd623e4786c110a3286ac8614ac7f3e`.
The prefix-included archive-layout value `1338ea21b50a084ec4d724449af226b129aedaf70a184109590f7cb64251d2d8`
is diagnostic only.

## Isolation and authorized host changes

The canonical distribution is `NBIS-BUILD-V1`, installed as WSL2 directly from
Canonical's official `ubuntu-24.04.4-wsl-amd64.wsl` release image after both
the pinned image SHA-256 and Canonical's published `SHA256SUMS` are verified.
The task may enable only
WSL, Virtual Machine Platform, and WSL2 if needed. It does not install Docker,
Podman, Cygwin, MSYS2, MinGW, Visual Studio, a Windows compiler, or a Windows
package manager. It does not persistently change PATH, `JAVA_HOME`, Defender,
the firewall, or PowerShell execution policy.

The external workspace is `C:\fingerprint-tools\nbis_build_environment_v1`.
It holds the official WSL image, environment export, WSL virtual disk, NBIS archive, build
trees, full logs, and receipts. None of those artifacts belongs in Git.

## Ordered workflow

Commit A contains only the orchestrator, read-only validator, synthetic tests,
this document, and dataset-independent CI. It must pass CI before any WSL
distribution or Ubuntu package is installed.

After Commit A is green, run the phases in order:

```text
preflight
install-wsl
configure
build
export
restore-check
package
```

Each invocation supplies the repository root, external workspace root, and the
already verified official archive. The orchestrator is intentionally unable to
accept an image, fixture, dataset, manifest, subject, score, threshold,
decision, alternate source URL/version, or patch.

The canonical build account is `nbisbuild` with UID/GID 2000. Builds use
`LC_ALL=C`, `LANG=C`, `TZ=UTC`, and umask 022. The source is copied to the Linux
filesystem and independently extracted twice. For each extraction, all 3,879
official archive entries are verified before and after the build.

The command sequence comes directly from `INSTALL_LINUX_MACOSX.txt`:

```text
./setup.sh <INSTALL_ROOT> --without-X11 --without-OPENJP2 --64
make config
make it
make install LIBNBIS=no
```

The two builds have distinct source and install roots. Build A becomes the
canonical install at `/opt/nbis/5.0.0`; Build B is independent reproducibility
evidence. No source patch, compatibility flag, warning suppression,
optimization change, stripping, or third-party binary is allowed.

## Evidence and restoration

The freeze records package versions, Ubuntu repository origins, toolchain and
libc identities, source-entry identities, build log hashes, executable and ELF
section hashes, dynamic-dependency summaries, and non-biometric CLI smoke
checks. Exact binary reproducibility is preferred. Controlled variance is
acceptable only when `.text`, `.rodata`, symbols, dependencies, and CLI payloads
remain equal and the difference is confined to non-algorithmic ELF metadata.

The canonical distribution is exported outside Git and imported once as
`NBIS-BUILD-V1-VERIFY`. Restore verification checks Ubuntu, package state, the
official archive, canonical executable hashes, dependencies, and non-biometric
smoke behavior. The temporary verification distribution is unregistered only
after PASS; `NBIS-BUILD-V1` is retained.

Commit B contains only the normalized evidence package under
`environments/nbis_build_environment_v1`. It contains no rootfs, source,
archive, binary, library, object, full log, local path, username, hostname, or
biometric material.

## Hard boundary

No fingerprint image, fixture, cohort, qualification image path, real minutiae,
score, threshold, decision, PPI conversion, downsampling, or technical
determinism probe is accessed or executed in this task. After the environment
package passes CI and annotated tag `nbis-build-environment-v1` is pushed, the
task stops.
