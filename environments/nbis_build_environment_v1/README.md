# NBIS reproducible build environment freeze v1

This package freezes the provenance and reproducibility evidence for an isolated
Ubuntu 24.04 LTS WSL2 build of the official, unmodified NIST NBIS 5.0.0 source.
It contains no archive, source tree, WSL export, executable, library, log,
biometric input, minutiae, score, threshold, username, hostname, or local path.

The only accepted source identity is `nbis_source_tree_identity_v2` with
canonical release-root SHA-256
`00ae5eff70693fa5647e3ff57232eff7abd623e4786c110a3286ac8614ac7f3e`.
The build environment prerequisite is resolved independently; all image,
resolution-policy, and technical determinism gates remain unresolved.
