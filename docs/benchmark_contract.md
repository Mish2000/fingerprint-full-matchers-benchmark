# Benchmark contract

`sourceafis-runtime-v1` separates image preparation from pair comparison:

- `prepare(image_path, image_metadata) -> PrepareOutcome`
- `compare(representation_a, representation_b) -> CompareOutcome`

Preparation receives the original encoded bytes and an explicit nominal PPI. Comparison returns the finite, unmodified matcher score. The contract has no threshold, normalized score, calibration, or accept/reject field.

A technical failure is represented by a non-`ok` status, an absent raw score, and an explicit error code. A successful comparison may legitimately return `0.0`; it remains `status=ok` and must never be confused with failure.

Each output row preserves all frozen manifest fields for sides A and B. Timing fields are diagnostic. The deterministic `score_payload_sha256` excludes timings, run identifiers, local paths, and other nondeterministic values.

Result publication uses a candidate directory. A complete candidate is validated before an atomic rename. Existing bundles are reused only after full validation and are replaced only when explicitly requested.
