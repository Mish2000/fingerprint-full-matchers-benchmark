# sourceafis_policy_application_v1

This frozen application deterministically applies the committed
`sourceafis_decision_policy_v1` policy to the eight bundles in `sourceafis_frozen_cohort_v1`.

## Frozen inputs and preservation

The source execution is the existing `sourceafis-frozen-cohort-v1` tag at `173ff0299537bdccb0f609f06114b2d0d22a14d6`.
The policy is `sourceafis-decision-policy-v1` at `fdef2e36a347e952a0509c07725a222e47aca9c3`. The external evidence archive is
identified as `external_archive/sourceafis_frozen_cohort_v1` and was verified byte-for-byte.

## Decision and failure policy

The threshold is exactly `40.0` and the operator is `>=`. Each complete raw score string
is parsed with `Decimal`; it is not rounded, quantized, converted to an integer, or compared
with an epsilon. `plain_self`, `roll_self`, and `plain_roll_genuine` expect `same`;
`plain_roll_next_subject` expects `different`. A valid technical failure receives
`no_decision` and `technical_failure`, never a numeric score or biometric error outcome.

## Primary units

Self-consistency units remain separate from verification. Counts and denominators are:

- `sd300b/plain_self`: planned=500, successful=500, failures=0, correct=492, incorrect=8; coverage 500/500 (100.00%).
- `sd300b/roll_self`: planned=500, successful=500, failures=0, correct=500, incorrect=0; coverage 500/500 (100.00%).
- `sd300b/plain_roll_genuine`: planned=500, successful=500, failures=0, correct=321, incorrect=179; coverage 500/500 (100.00%).
- `sd300b/plain_roll_next_subject`: planned=500, successful=500, failures=0, correct=500, incorrect=0; coverage 500/500 (100.00%).
- `sd300c/plain_self`: planned=500, successful=500, failures=0, correct=495, incorrect=5; coverage 500/500 (100.00%).
- `sd300c/roll_self`: planned=500, successful=500, failures=0, correct=500, incorrect=0; coverage 500/500 (100.00%).
- `sd300c/plain_roll_genuine`: planned=500, successful=500, failures=0, correct=308, incorrect=192; coverage 500/500 (100.00%).
- `sd300c/plain_roll_next_subject`: planned=500, successful=500, failures=0, correct=500, incorrect=0; coverage 500/500 (100.00%).

## Verification aggregates

- `sd300b` uses only genuine and next-subject impostor comparisons: FNMR 179/500 (35.80%); FMR 0/500 (0.00%).
- `sd300c` uses only genuine and next-subject impostor comparisons: FNMR 192/500 (38.40%); FMR 0/500 (0.00%).

The official SourceAFIS threshold recommendation is not reported as an empirical FMR;
every empirical rate is shown with its observed numerator and denominator.

## Reproducibility boundary

No matcher, Java process, threshold sweep, distribution, ROC, EER, or timing analysis was run.
Row-level decisions remain local under `results/sourceafis_policy_application_v1/derived`; raw bundles and
derived rows are not tracked by Git. This package is the stopping point before the
SourceAFIS Supervisor Report.
