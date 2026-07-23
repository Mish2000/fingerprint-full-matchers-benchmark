# NBIS Candidate Suitability Audit v1

## 1. Executive conclusion

Official NIST NBIS Release 5.0.0 has a coherent source-level `MINDTCT -> BOZORTH3` path for one-to-one fingerprint verification and directly supports the protocol's 8-bit grayscale PNG encoding. It is not ready for integration: no supported build environment was available, the exact 5.0.0 archive lacks the documented NIST 1000-to-500 downsampler, no applicable official 2000 PPI operational policy was found in the audited sources, and the gated determinism probe therefore was not run.

## 2. Audit status

`PASS`. Source acquisition, provenance, build inventory, source inspection, input-format analysis, separate 1000 and 2000 PPI analyses, contract proposal, risk classification, and static package validation were completed. A missing runtime prerequisite is recorded as a candidate prerequisite, not as an incomplete audit.

## 3. Candidate verdict

`SUITABLE_WITH_PREREQUISITES`. The core pipeline is suitable, but integration is blocked until every prerequisite in `risks_and_open_questions.json` is resolved.

## 4. Scope and exclusions

The scope was official source provenance, build feasibility, input decoding, resolution handling, image-to-minutiae-to-score semantics, failure semantics, and determinism-gate design for `supervisor_50x10_v1`, SD300B at nominal 1000 PPI and SD300C at nominal 2000 PPI. Excluded work includes an adapter, production preprocessing, cohort execution, score analysis, performance comparison, calibration, threshold selection, decision generation, and SourceAFIS comparison.

## 5. Official identity and provenance

NIST's product page and NIGOS release listing identify NBIS 5.0.0, MINDTCT, and BOZORTH3. The archive was acquired only from the official NIST NIGOS endpoint. Its SHA-256 is locked in `source_archive.json`. No mirror, fork, alternate implementation, or prebuilt binary was used.

## 6. Licensing

NIST describes NBIS as public-domain software. This finding applies to the official release identified here; it does not authorize substituting third-party packaging or binaries without a new provenance review.

## 7. Source acquisition

The official archive returned HTTP 200 and contained top-level directory `Rel_5.0.0`. The archive, complete source tree, MINDTCT subtree, BOZORTH3 subtree, build scripts, and inspected evidence files have immutable hashes. The source was inspected unmodified and was not added to Git.

## 8. Build environment

The host inventory found no native gcc/gmake/Cygwin combination, no installed WSL distribution, and no Docker or Podman runtime. The audit did not install software. NIST documents gcc/gmake and reports testing on Linux, macOS, and Cygwin, so a new, separately reviewed frozen build environment is required.

## 9. Build result

`NOT_RUN`. There is no claim that MINDTCT or BOZORTH3 executables were built. There are no executable hashes, linked-runtime claims, or runtime warnings. This prevents a `SUITABLE` verdict but is a finite reproducible-build prerequisite rather than evidence of a source defect.

## 10. MINDTCT findings

MINDTCT accepts an input image and output root, decodes supported grayscale formats, and writes several products including XYT. Its XYT rows contain integer x, y, theta, and quality values and are the documented BOZORTH3 input. Optional contrast boosting is not part of the proposed canonical invocation. When decoded PPI is unavailable, MINDTCT assumes 500 PPI. It does not resample dimensions; the sample rate reaches the reliability/quality-neighborhood calculation while detection and binarization retain fixed pixel-domain parameters. Empty XYT output is possible when no minutiae are detected and must not be confused with a process failure.

## 11. BOZORTH3 findings

BOZORTH3 accepts a direct probe XYT and gallery XYT for one-to-one operation. Its default output format is a single integer score line. Higher scores indicate greater similarity. The proposed command omits score-threshold options and filename-output formats. Nonzero process exit, malformed output, absent output, or extra output is a technical failure; a numeric zero is a valid score, including the documented case where either input has fewer than ten minutiae.

## 12. Input format findings

The release identifies PNG input, dispatches it to the compiled PNG decoder, copies decoded scan-line bytes, and requires 8-bit grayscale depth for this path. Therefore protocol PNG can be decoded directly and no format converter is required. Because no conversion is performed, pixel-equivalence testing is not applicable. No inversion, enhancement, crop, lossy conversion, or generic resize was approved.

## 13. 1000 PPI findings

NISTIR 7839 studies 1000-to-500 PPI conversion. NIST SP 500-289 specifies Gaussian low-pass filtering with sigma 0.8475, radius 4, followed by odd-column/odd-row decimation. The study describes a 9-by-9 kernel and mirrored or duplicated edge pixels. NIST SP 500-306 later defines conformance testing against a NIST reference downsampler. The locked NBIS 5.0.0 archive predates SP 500-306 and does not contain this downsampler. Thus official guidance exists and an official reference implementation is described, but the implementation is not part of this candidate release and no local implementation was validated. SD300B's canonical path is `PREREQUISITE`.

## 14. 2000 PPI findings

No official operational policy for direct MINDTCT use at 2000 PPI, 2000-to-1000 conversion, 2000-to-500 conversion, or a 2000-to-1000-to-500 cascade was found in the audited NIST sources. NIST SP 500-306 discusses 2000 PPI scans only while describing aligned reference regions; its certification pathway remains 1000-to-500 PPI. This bounded search result is not a claim that no other official document can exist. No inference from the 1000 PPI method is permitted. SD300C's canonical path is `PREREQUISITE`.

## 15. Technical fixture probe

The only authorized fixture identity is subject `00001000`. The fixture manifest and image bytes were not accessed because prerequisite gates failed before probe authorization. No fallback subject was selected and no cohort subject was processed.

## 16. Determinism

`NOT_RUN`. Source inspection found no deliberate path or timestamp fields in default XYT or score output, but that is not runtime determinism evidence. Three fresh-process repetitions must be performed only after build and resolution gates resolve, without committing score values.

## 17. Proposed pipeline contract

`prepare(image_path, metadata) -> PrepareOutcome` decodes the approved PNG, applies only the approved declared-PPI policy, invokes official MINDTCT without optional contrast boost, and retains canonical XYT. `compare(representation_a, representation_b) -> CompareOutcome` invokes official BOZORTH3 in direct one-to-one mode and parses exactly one integer line. The contract carries method identity, success/failure status, finite raw score, and cleanup policy. It contains no threshold, decision, normalization, calibration, filtering, clipping, or subject policy.

## 18. Compatibility with benchmark contract

The source-level path maps to encoded input, explicit nominal PPI metadata, structured prepare and compare outcomes, a finite raw score, and error codes without changing the protocol. The resolution-policy identity must become part of representation/cache identity. No change to SourceAFIS, manifests, existing results, or the frozen protocol is proposed here.

## 19. Risks

The blocking risks are absent build evidence, absent in-release 1000 PPI implementation, unresolved 2000 PPI scientific policy, and an unexecuted determinism probe. Additional risks include legacy build portability, PNG PPI metadata not being consumed, equal-quality cutoff ordering, and provenance drift. Structured evidence and resolution criteria appear in `risks_and_open_questions.json`.

## 20. Prerequisites

The four gates are `NBIS_BUILD_ENVIRONMENT_FREEZE_V1`, `NBIS_1000_PPI_DOWNSAMPLER_CONFORMANCE_V1`, `NBIS_2000_PPI_PREPROCESSING_POLICY_V1`, and `NBIS_TECHNICAL_DETERMINISM_PROBE_V1`. Each records its exact question, blocking reason, acceptable evidence, prohibited shortcuts, and recommended task. Integration remains prohibited until all four are `RESOLVED`.

## 21. Final recommendation

Retain official NBIS 5.0.0 as a candidate, but do not create an adapter or process protocol images yet. The core source contract warrants completing the finite prerequisites. If the 2000 PPI policy gate cannot establish a fair canonical path, revisit the verdict as `NOT_SUITABLE` rather than inventing preprocessing.

## 22. Exact next step

Start a separate task named `NBIS Reproducible Build Environment Freeze`. It should define an immutable supported environment, build the unmodified locked release, and record both executable identities. Stop there; resolution-policy and probe work remain separate gates.
