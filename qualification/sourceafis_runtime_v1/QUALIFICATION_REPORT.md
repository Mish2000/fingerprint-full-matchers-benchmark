# SourceAFIS Successful-Path Runtime Qualification

## Purpose and final status

**PASS** — technical successful-path qualification for `sourceafis_runtime_v1`.

This qualification proves encoded-image extraction, official SourceAFIS 3.18.1 template serialization, official pairwise verification, deterministic finite raw scores, and old/new parity. It is not a research result and provides no biometric interpretation.

## Canonical JVM selection

The first attempt stopped before matcher execution because Java 11 was treated as a runtime requirement.
It published no PASS package and left the partial BLOCKED report untouched until this successful replacement.

The historical research environment was verified to contain Zulu OpenJDK 17.0.18 and Maven 3.9.16 using the same Java home. Both sidecars were built and run with this same existing environment, while the compiler target remained Java release 11. No Java installation, Conda change, or persistent system-environment change was made.

Supporting read-only old-run provenance: `results/detector_only_joint_500_v1/sd300b/roll_self/sourceafis_final_minutiae_rootsift_geometric/run_metadata.json` recorded Java runtime 17.0.18 and SourceAFIS 3.18.1.

## Deterministic fixture selection

The selected subject is `00001000`, canonical finger `1`. It is the lexicographically smallest Stage 0 subject with complete matching PLAIN/ROLL coverage in both releases after removing the frozen 50-subject cohort, fixed duplicate exclusions, all manual-review subjects, and all selection-blocked subjects. No quality, dimensions, matcher success, or score informed selection, and no fallback was allowed.

The subject is not part of the frozen cohort. Exactly four images were used:

- `sd300b_plain`: `sd300b/images/1000/png/plain/00001000_plain_1000_11.png` — `743c73d4a5ae6a270fc6d3c86f8385987c39af674b1d9fe2944a43b204ac7ba4` (1000 PPI)
- `sd300b_roll`: `sd300b/images/1000/png/roll/00001000_roll_1000_01.png` — `1415297dfc29b0c5f4507cf51486f235194915714d9437464082db64d6ccba13` (1000 PPI)
- `sd300c_plain`: `sd300c/images/2000/png/plain/00001000_plain_2000_11.png` — `256872ede3e8dcf281aae04dceaaf19aefc630f19ca0bd177f20051b879576df` (2000 PPI)
- `sd300c_roll`: `sd300c/images/2000/png/roll/00001000_roll_2000_01.png` — `1bc89b63edc8e42c7d89cc0cf079ce62fcac2d485e8ea1fb4cea16f0e169c3df` (2000 PPI)

## Environment and implementations

- Runtime: Zulu OpenJDK 17.0.18 (`17.0.18+8-LTS`), vendor `Azul Systems, Inc.`, architecture `amd64`
- Maven: 3.9.16
- Compiler release: 11
- SourceAFIS: 3.18.1
- Old source commit: `0893d50d08972fc68337749332ecdaa0faef2a70`
- New runtime baseline: `db1e499f0ee3a5457ec71fbc7feba22214d34116`
- Old JAR SHA-256: `5245f2a1847d489b2199e0c87879ca0fb2465efd7175f60096240f8c0edca9b5`
- New JAR SHA-256: `f930a51337363dbc0ae94bc1b8781b8370e05360507e96a22574c7034410b75b`

## Qualification results

- Old successful extraction: PASS
- New successful extraction: PASS
- Old successful verification: PASS
- New successful verification: PASS
- Old internal determinism: PASS
- New internal determinism: PASS
- Template parity: PASS
- Score parity: PASS
- Removed routes return 404: PASS

All four templates and all six raw scores were identical across three independent repetitions per implementation. Old and new template hashes and parsed double scores were exactly equal. Serialized templates remained in memory and were never written to disk.

## Research boundary

No threshold, calibration, decision, acceptance classification, accuracy metric, or score-height interpretation was used. No impostor or cross-release comparison was performed. No research benchmark ran, and none of the frozen 50 subjects was accessible to the matcher. The frozen protocol, source repository, curation, and raw datasets remained unchanged.
