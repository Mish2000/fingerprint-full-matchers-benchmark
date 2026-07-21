# SourceAFIS Runtime Migration Report

## Scope and authority

- Migration: `sourceafis_runtime_v1`
- New-repository baseline commit: `29d8de0180403e9aa8a5e81cc468664b96dc8932`
- Audited source repository commit: `0893d50d08972fc68337749332ecdaa0faef2a70`
- Frozen protocol recovery tag: `protocol-supervisor-50x10-v1`
- Strategy: greenfield shell plus the audited, narrowed full-matcher core

The four files in `migration-audit` governed COPY/REWRITE/EXCLUDE decisions. The source repository was read-only. The frozen protocol package, curation tree, and raw datasets were not changed.

## Migrated runtime

Copied and retained in narrowed form: canonical hashing, atomic UTF-8 I/O, atomic bundle publication, provenance collection, the SourceAFIS adapter, sidecar lifecycle, and the generic Java API/build-information helpers.

Rewritten: package/configuration documentation, matcher contract, locked-manifest reader, preflight, raw-score runner, CLI, SourceAFIS client, Maven definition, Java engine/service, and Java engine tests.

New: dataset-independent Python contract/manifest/runner/client/lifecycle/static-coupling tests and GitHub Actions CI.

Excluded: all legacy protocols, results, research reports, detector/descriptor algorithms, local-feature matching, geometric verification, customized image processing, raw-pixel template ingestion, final-minutia extraction, custom template parsing, identification, score calibration, thresholds, and match decisions. No generated JAR was migrated.

The detailed per-file inventory and hashes are in `migrated_files.json`. That inventory does not list itself because a file cannot contain its own stable cryptographic hash.

## Versions and dependencies

- Python tested: 3.11.15; runtime uses only the standard library.
- Maven tested: 3.9.16.
- Java runtime used locally: OpenJDK 17.0.18; Maven compilation is pinned to Java release 11.
- SourceAFIS: `com.machinezoo.sourceafis:sourceafis:3.18.1`.
- Jackson Databind: 2.17.2.
- JUnit: 5.10.3 (test scope).
- Sidecar contract: `sourceafis-sidecar-contract-v1`.
- Sidecar implementation: 1.0.0.

`jackson-dataformat-cbor` is absent from `pom.xml` and from runtime code. Maven resolves it only as SourceAFIS 3.18.1's own transitive serialization dependency, which is required by official template serialization/deserialization; runtime code neither imports it nor parses SourceAFIS internals.

## Runtime surface

Allowed routes:

- `GET /health`
- `POST /extract-template`
- `POST /verify`

Removed routes:

- `POST /extract-template-raw`
- `POST /extract-final-minutiae`

The service binds only to loopback. Preparation passes unchanged encoded bytes and explicit 1000/2000 nominal PPI to official SourceAFIS image/template constructors. Verification deserializes official templates and returns the finite score from `FingerprintMatcher.match` without normalization.

## Verification results

- Frozen protocol validator: PASS (50 subjects, 500 identities, 8 manifests, 4,000 locked rows).
- Frozen protocol tests: PASS, 20/20.
- New Python runtime tests: PASS, 35/35.
- Java unit/integration tests: PASS, 6/6.
- Java shaded JAR build: PASS; generated under `target` and ignored by Git.
- Dataset-independent sidecar integration: PASS for health, invalid DPI, invalid encoded image, invalid serialized template, lifecycle shutdown, and exact 404 behavior for both removed routes.
- Static forbidden-coupling scan: PASS.
- Successful extraction/verification smoke: **BLOCKED** — no permitted tracked non-SD300 fingerprint fixture exists in the audited source repository.
- Old/new score parity: **BLOCKED** for the same fixture constraint; 0/0 permissible pairs were available.

No SD300 image, frozen manifest pair, downloaded image, or invented fingerprint image was used to bypass the fixture rule.

## Risks and limitations

Successful encoded-image extraction and numerical score parity remain intentionally unverified until a small, licensed, tracked, non-cohort fixture meeting the audit rules is supplied. Negative integration verifies that both allowed POST routes are active, but it cannot establish a successful biometric path without such a fixture. The runtime records raw scores and technical failures only.

No research benchmark was executed. No matcher accessed the frozen 50-subject cohort. No research report, score distribution, accuracy analysis, calibration, threshold, or decision policy was produced.
