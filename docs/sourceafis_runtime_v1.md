# SourceAFIS runtime v1

The only supported biometric path is:

```text
encoded image bytes
-> SourceAFIS FingerprintImage with explicit DPI
-> SourceAFIS FingerprintTemplate
-> SourceAFIS FingerprintMatcher.match
-> finite raw similarity score
```

The Java sidecar binds to loopback and exposes exactly `GET /health`, `POST /extract-template`, and `POST /verify`. Python keeps one persistent HTTP connection and manages the sidecar lifecycle. Templates are official SourceAFIS serialized templates; callers cannot provide pixels, minutiae, or custom feature structures.

SourceAFIS is pinned to 3.18.1, Jackson Databind to 2.17.2, and Java compilation to release 11. There is no external image preprocessing, template cache, thresholding, decision logic, identification, or score normalization.

CI continues to use Java 11 for compatibility compilation and sidecar checks. The canonical local successful-path qualification used the existing historical Conda environment with Zulu OpenJDK 17.0.18 and Maven 3.9.16; both old and new sidecars were built and launched with those identical executables while `maven.compiler.release` remained 11.

## Successful-path qualification

The locked `sourceafis_runtime_v1` package records a PASS on subject `00001000`, canonical finger 1. Fixture selection was metadata-only: the lexicographically smallest eligible subject after excluding the frozen 50-subject cohort, fixed duplicate exclusions, all manual-review subjects, and all selection-blocked subjects. No matcher result, score, image quality, or fallback influenced selection.

The qualification used exactly four hash-verified encoded images: PLAIN and ROLL from SD300B at 1000 PPI and PLAIN and ROLL from SD300C at 2000 PPI. Each old/new implementation ran in three fresh processes. All four serialized-template hashes and all six finite raw scores were internally deterministic and exactly equal across implementations. The new sidecar returned 404 for `/extract-template-raw` and `/extract-final-minutiae`.

This is technical runtime evidence, not a research benchmark. It defines no threshold or decision, interprets no score, performs no impostor or cross-release comparison, and never exposes the frozen cohort to the matcher. The committed package stores no image bytes, template bytes, Base64 payloads, JARs, user paths, or host identity.
