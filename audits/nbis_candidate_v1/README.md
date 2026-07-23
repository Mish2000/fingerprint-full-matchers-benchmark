# NBIS candidate suitability audit v1

This package is a static, provenance-locked suitability audit of official NIST NBIS Release 5.0.0, specifically the proposed `MINDTCT -> BOZORTH3` one-to-one verification pipeline for protocol `supervisor_50x10_v1`.

The audit status is `PASS`. The candidate verdict is `SUITABLE_WITH_PREREQUISITES`.

The source-level core is suitable for a future adapter: NBIS directly decodes 8-bit grayscale PNG, MINDTCT emits the XYT representation consumed by BOZORTH3, BOZORTH3 has a raw nonnegative integer score with higher meaning more similar, and technical failures can be represented. Runtime integration is not authorized yet.

Four blocking gates remain:

1. Freeze a reproducible supported build environment and build both executables from the unmodified locked archive.
2. Lock and validate a conformant implementation of NIST's documented 1000-to-500 PPI method.
3. Approve a separate official or scientifically validated resolution policy for 2000 PPI; 1000 PPI guidance is not evidence for 2000 PPI.
4. Run the authorized three-repetition technical fixture probe only after the preceding gates resolve.

No matcher integration, cohort execution, score analysis, threshold selection, decision policy, or SourceAFIS comparison was performed. No source archive, binary, image, minutiae output, local log, or score value is included here.

Validate the package from the repository root with:

```text
python tools/validate_nbis_candidate_audit_v1.py
python -m pytest -q tests/test_nbis_candidate_audit_v1.py
```

The validator is standard-library only, read-only, and does not require NBIS source, a dataset, WSL, Cygwin, a compiler, or a network connection.
