# SourceAFIS frozen policy application v1

`sourceafis_policy_application_v1` is the deterministic bridge between the frozen
SourceAFIS execution and later research reporting. It applies only the committed
`sourceafis_decision_policy_v1` policy to all eight registered bundles. It does not
start Java, Maven, the sidecar, a matcher, a manifest, or an HTTP client.

## Frozen identity

The repository's existing `sourceafis-frozen-cohort-v1` tag resolves to
`173ff0299537bdccb0f609f06114b2d0d22a14d6`. The task prompt named the obsolete
object `4c9640bb95e39f3e44cefbd33db10d6c67bf67b1`; the user explicitly authorized
bypassing that identity gate without moving the tag. The application records this
deviation in its validation report and uses the existing tagged package.

The policy is `sourceafis-decision-policy-v1` at
`fdef2e36a347e952a0509c07725a222e47aca9c3`. The threshold is read only from the
frozen policy package and must be the decimal string `40.0`; the operator must be
`>=`, and the SourceAFIS version must be `3.18.1`.

## Safety and ordering

Before opening any bundle `results.csv`, the tool verifies the main branch, clean
index and worktree, required tags, protected Git trees, frozen package checksums,
execution registry, eight bundle file hashes, canonical JAR hash, external archive,
application-code commit, and absence of an existing evaluation package. The
application has no threshold, policy, bundle-subset, retry, replacement, or
skip-validation option.

Preservation copies `raw` and `runtime` byte-for-byte to a sibling candidate
directory, verifies all files, writes `archive_receipt.json`, and atomically renames
the candidate. An existing archive is never overwritten. A mismatch is `BLOCKED`.

For successful rows, the complete score string is parsed using `Decimal`. There is
no quantization, rounding, epsilon, integer conversion, or formatting before the
comparison. A valid failure has no score, has an error code, and becomes
`no_decision` / `technical_failure`. Invalid, missing, duplicate, or reordered input
blocks the entire publication as `INVALID_INPUT`.

## Commands

Use the canonical conda environment's Python interpreter. Validation performs no
writes:

```powershell
& "C:\Users\sirak\.conda\envs\fingerprint-recognition-research\python.exe" `
  tools\apply_sourceafis_decision_policy_v1.py `
  --repository-root C:\fingerprint-full-matchers-benchmark `
  --results-root C:\fingerprint-full-matchers-benchmark\results\sourceafis_frozen_cohort_v1 `
  --archive-root C:\fingerprint-results-archive\sourceafis_frozen_cohort_v1 `
  --derived-output-root C:\fingerprint-full-matchers-benchmark\results\sourceafis_policy_application_v1 `
  --validate-only
```

`--preserve-only` stops after verified external preservation. Omitting both mode
flags performs the complete application and atomic publication.

The committed package can be validated in CI without local raw bundles:

```powershell
python tools\validate_sourceafis_policy_application_v1.py
```

Local deep validation replays all decisions and compares every decision payload:

```powershell
python tools\validate_sourceafis_policy_application_v1.py `
  --results-root C:\fingerprint-full-matchers-benchmark\results\sourceafis_frozen_cohort_v1
```

Validators never print score values.

## Outputs and reporting boundary

Row-level decisions are local-only under
`results/sourceafis_policy_application_v1/derived`. They contain decision identities
and payload hashes, but not scores, image paths, image hashes, timing data, template
metadata, or full error messages. Raw bundles, the JAR, and derived rows remain
untracked.

The committed evaluation contains exactly eight primary units in frozen execution
order and two per-release verification aggregates. `plain_self` and `roll_self`
remain separate and are excluded from verification aggregation. Every machine rate
stores its numerator, denominator, and six-place decimal string (or `null` for a zero
denominator). Human rates always include counts and a two-place percentage.

The official threshold recommendation is not an observed experiment FMR. Empirical
FMR is reported only as false matches divided by successful impostor comparisons.
This stage stops before the Supervisor Report, distributions, ROC, EER, alternative
thresholds, timing analysis, or comparison with another matcher.
