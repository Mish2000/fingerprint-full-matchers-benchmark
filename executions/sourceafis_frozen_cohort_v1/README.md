# SourceAFIS frozen-cohort raw-score execution v1

`sourceafis_frozen_cohort_v1` records the first execution of the qualified SourceAFIS runtime over the
frozen supervisor protocol. It produces raw similarity scores only. No threshold is applied,
no biometric decision is derived, and no accuracy, FMR or FNMR figure is computed here.

## Manifests and order

The eight frozen manifests always run in this order, and the tool exposes no way to select a
subset, reorder them, or add another manifest:

1. `sd300b/plain_self.csv`
2. `sd300b/roll_self.csv`
3. `sd300b/plain_roll_genuine.csv`
4. `sd300b/plain_roll_next_subject.csv`
5. `sd300c/plain_self.csv`
6. `sd300c/roll_self.csv`
7. `sd300c/plain_roll_genuine.csv`
8. `sd300c/plain_roll_next_subject.csv`

Each manifest contributes 500 planned pairs, for
4000 result rows in total.

## Environment and runtime

The series runs in the qualified environment `conda_env/fingerprint-recognition-research` using
Zulu OpenJDK 17.0.18 (Azul Systems, Inc.), Maven
3.9.16, compiler release 11 and SourceAFIS
3.18.1. Exactly one shaded JAR is built for the whole series and every
manifest reuses that same canonical copy; its SHA-256 is recorded in
`execution_environment.json` and `execution_lock.json`. Every manifest runs in a fresh
process and a fresh JVM, so no template or representation cache is carried between
manifests.

## Results, resume and failures

Raw bundles are written to `results/sourceafis_frozen_cohort_v1` inside the working copy and are
deliberately **not** tracked by Git; this package records only their identities, hashes and
counts. An existing bundle is reused only when it validates completely and its manifest
hash, protocol lock hash, JAR hash, execution code commit and Java runtime all match the
current series; any other provenance is reported as BLOCKED and is never overwritten. There
is no resume from the middle of a CSV: an interrupted manifest is discarded with its
candidate directory and re-run in full.

A pair-level extraction or comparison failure is preserved in its own row with an error code
and no score. Such failures are never retried selectively and never converted into a score,
a zero, or a `different` outcome. For every bundle,
`successful_scores + technical_failures = 500`.

## Validation

The committed package can be checked, with no dataset and no matcher, from the repository
root:

```text
python tools/validate_sourceafis_frozen_cohort_v1.py
```

Adding `--results-root` to that command additionally re-validates every local raw bundle
row-by-row against its source manifest.

## Stopping point

This package is the end of the execution stage. Applying the frozen decision policy,
producing the supervisor report, and computing FMR, FNMR, accuracy, score distributions or
timing comparisons are all separate, later stages.
