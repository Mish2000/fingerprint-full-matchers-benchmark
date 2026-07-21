# Fingerprint Full-Matcher Benchmark

This repository contains the minimal runtime for reproducible, raw-score evaluation of complete external fingerprint matchers. The current runtime supports only the official SourceAFIS 3.18.1 encoded-image pipeline.

The frozen `supervisor_50x10_v1` protocol is an immutable input. Runtime code reads one locked manifest at a time, preserves both identities and all source metadata, and publishes validated result bundles atomically. It does not define thresholds, normalize scores, or make match decisions.

## Install

Python 3.11 is required. The Python package has no third-party runtime dependencies.

```powershell
python -m pip install -e .
```

Build the Java 11 sidecar:

```powershell
mvn -f apps/sourceafis-sidecar/pom.xml clean package
```

Java 11 is the compatibility runtime used by CI and the Maven compiler target is release 11. The locked local successful-path qualification used the historical research environment instead: Zulu OpenJDK 17.0.18 and Maven 3.9.16, identically for the old and new sidecars.

## Commands

```text
fingerprint-benchmark validate-protocol --protocol-root <protocol> --curation-root <stage0> --dataset-root <NIST-root>
fingerprint-benchmark sourceafis-smoke --jar <sidecar.jar>
fingerprint-benchmark run-sourceafis-manifest --manifest <csv> --dataset-root <NIST-root> --output-root <results> --jar <sidecar.jar>
fingerprint-benchmark validate-result-bundle --bundle <bundle>
```

Do not execute the manifest command as part of runtime migration or validation. See [the benchmark contract](docs/benchmark_contract.md) and [runtime notes](docs/sourceafis_runtime_v1.md).

## Successful-path qualification

`sourceafis_runtime_v1` passed technical successful-path qualification on one deterministically selected non-cohort subject. The locked package is under `qualification/sourceafis_runtime_v1`; it records three independent repetitions per implementation, exact template and score parity, and 404 results for the removed routes. It contains paths and hashes only—no image bytes, serialized templates, threshold, decision, or research conclusion.
