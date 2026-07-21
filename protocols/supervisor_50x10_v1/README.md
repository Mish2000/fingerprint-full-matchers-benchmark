# supervisor_50x10_v1

This package freezes the supervisor-approved 50-subject, 10-canonical-finger evaluation protocol derived from the historical `stage0_v1` curation outputs. It is a data/protocol artifact, not a benchmark implementation.

## Frozen cohort and comparisons

- The exact 50 selected subjects and their existing `subject_index` order are copied byte-for-byte from Stage 0. No subject was reselected, replaced, added, removed, or reordered.
- Every release contains 500 logical finger identities: 50 subjects times 10 canonical fingers.
- Each release contains four 500-row manifests: `plain_self`, `roll_self`, `plain_roll_genuine`, and `plain_roll_next_subject`.
- Self manifests are deterministic projections of the frozen genuine manifests. They do not perform discovery or selection.
- The next-subject comparison uses cyclic offset 1 in frozen subject order: subject 1 to 2 through subject 50 to 1, always at the same canonical finger.

## Dataset and PPI policy

- `sd300b` uses nominal PPI 1000.
- `sd300c` uses nominal PPI 2000.
- PNG metadata is diagnostic only and is never used as the protocol PPI source.
- Manifest paths are normalized with `/` and are relative to the NIST dataset root.
- Existing image hashes and statuses come from the frozen base manifests; images are not decoded or rehashed.
- Challenge records are retained without filtering or status improvement.

## Curation provenance and caveats

- No matcher was executed and no biometric result influenced this protocol freeze.
- No SourceAFIS code, adapter, sidecar, execution, or run instruction is part of this package.
- `manual_review_decisions.csv` is copied byte-for-byte, hashed, and treated as mandatory selection provenance. All 11 recorded decisions retain their `challenge` classification.
- Subjects `00001585` and `00001586` were conservatively blocked by Stage 0 based on an unverified prior report. They are not among the frozen 50, no new biometric evidence was produced, and the suspicion is not claimed as biometrically proven.
- The historical locked Stage 0 config hash and current config hash differ. Both hashes are recorded, but the old Stage 0 config is not an authority or runtime input for this package.
- `_analysis` remains external corroborating evidence and is not a protocol input.

## Read-only validation

From the repository root, run only the validator:

```text
python tools/validate_supervisor_50x10_v1.py --protocol-root protocols/supervisor_50x10_v1 --curation-root C:\fingerprint-datasets\NIST\_curation\stage0_v1 --dataset-root C:\fingerprint-datasets\NIST
```

The validator reads manifests, provenance, locks, and referenced file existence only. It performs no image decoding, image processing, matching, sampling, scoring, or calibration.
