# SourceAFIS decision and reporting policy v1

`sourceafis_decision_policy_v1` freezes the SourceAFIS decision and reporting rules before any frozen-cohort score is produced. This prevents evaluation data, qualification scores, challenge records, or earlier project results from influencing the primary decision threshold.

## Decision rule

The policy applies to SourceAFIS 3.18.1 raw similarity values returned by `FingerprintMatcher.match`. A higher raw score means greater similarity. A successful, finite, non-negative, unrounded score is classified with exactly one fixed rule:

```text
score >= 40.0  -> same
score < 40.0   -> different
```

There is no epsilon comparison, integer conversion, pre-decision rounding, per-release threshold, per-kind threshold, challenge-specific threshold, threshold sweep, or post-hoc replacement of this policy. Any later exploratory threshold analysis must use a new policy ID and cannot replace the primary result at 40.

The only decision values are `same`, `different`, and `no_decision`. A valid technical failure has a non-`ok` status, a present error code, and no score. It becomes `no_decision`; it is never score zero, `different`, a false match, or a false non-match. Structurally inconsistent rows are `INVALID_INPUT` and block final reporting. This policy adds no retry behavior.

## Expected classes and reporting units

Expected class comes only from the frozen `comparison_kind`:

| comparison kind | expected class | reporting category |
| --- | --- | --- |
| `plain_self` | `same` | self consistency |
| `roll_self` | `same` | self consistency |
| `plain_roll_genuine` | `same` | genuine verification |
| `plain_roll_next_subject` | `different` | impostor verification |

All challenge records remain in `planned_pairs` and use the same rule and denominators. Primary results are reported separately for every dataset release and comparison kind. In particular, self comparisons compare an image with itself and are endpoint-consistency checks, not genuine comparisons between different captures; they must not be pooled with `plain_roll_genuine`.

Every primary unit retains raw counts for planned pairs, successful scores, technical failures, the three decisions, and correct and incorrect decisions. The required rates are decision coverage, technical-failure rate, valid-only correct rate, and strict correct-completion rate. Technical failures are excluded from valid biometric-rate denominators but remain in planned-pair denominators. A zero valid-score denominator produces `null`, not zero. Machine ratios use six decimal places and human percentages use two, both with `ROUND_HALF_UP`; human percentages are always accompanied by numerator and denominator.

A secondary verification aggregate may combine only `plain_roll_genuine` and `plain_roll_next_subject` within one release. It must preserve counts and cannot replace the eight primary reporting units.

## Research interpretation boundary

The official SourceAFIS documentation recommends threshold 40 as a starting point and associates it approximately with FMR 0.01%, while warning that the relationship varies with fingerprint quality and that threshold selection is application-dependent. That association is external guidance, not a result observed by this benchmark. With only 500 planned impostor comparisons per release, even zero false matches must be reported as a raw count such as `0/500`; this experiment cannot claim to have validated an observed FMR of 0.01%.

Official sources are recorded in `source_provenance.json`: the [SourceAFIS for Java documentation](https://sourceafis.machinezoo.com/java) and the [SourceAFIS 3.18.1 `FingerprintMatcher.match` Javadoc](https://sourceafis.machinezoo.com/javadoc/com.machinezoo.sourceafis/com/machinezoo/sourceafis/FingerprintMatcher.html).

## Validation only

Run the dataset-independent validator from the repository root:

```text
python tools/validate_sourceafis_decision_policy_v1.py
```

The validator is read-only and standard-library only. It validates static policy artifacts, synthetic decision behavior, the lock, checksums, provenance, and protected-area hashes. It does not import the benchmark runner, read manifests or result bundles semantically, start the Java sidecar, execute the matcher, generate cohort scores, or produce a research-results report.
