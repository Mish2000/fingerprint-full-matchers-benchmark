# Dependency graphs for the audited migration

Legend: `[COPY]`, `[REWRITE]`, `[EXCLUDE]`, `[UNCERTAIN]` describe the future migration decision. No node has been migrated.

## 1. SourceAFIS runtime

```text
fingerprint-benchmark CLI [REWRITE]
  keep: sourceafis-smoke, run-sourceafis, run-sourceafis-all, summarize
  remove: SIFT, GFTT-Harris, detector-joint500 commands/imports
  |
  +--> manifest reader + preflight [REWRITE]
  |      input: frozen Stage 0 manifests [COPY after approval]
  |      verify: schema, identity A/B, order, paths, nominal PPI, SHA-256
  |
  +--> benchmark runner [REWRITE]
         keep: serial prepare/compare, timing, failure statuses,
               config/implementation/manifest hashes, score-payload hash,
               candidate validation and atomic publication
         change: Stage 0 schema and impostor subject A/B result fields
         |
         +--> contract.py [REWRITE: preserve API; bump result schema]
         +--> hashing.py [COPY]
         +--> io.py [COPY]
         +--> bundle.py [COPY]
         +--> provenance.py [COPY]
         |
         +--> SourceAfisAdapter [COPY]
                prepare(encoded image bytes, nominal PPI)
                compare(serialized template A, serialized template B)
                raw score only
                |
                +--> SourceAfisSidecarClient [REWRITE]
                |      keep: loopback HTTP, persistent connection, /health,
                |            /extract-template, /verify, explicit errors
                |      remove: raw-template and final-minutiae contracts
                |      |
                |      +--> ManagedSourceAfisSidecar [COPY]
                |             JVM lifecycle, safe output drains,
                |             JAR path/SHA-256, health readiness
                |             |
                |             +--> shaded sidecar JAR [EXCLUDE from Git]
                |                    regenerate from pinned pom.xml [REWRITE]
                |                    |
                |                    +--> SourceAfisSidecarService [REWRITE]
                |                    |      routes: /health, /extract-template, /verify
                |                    |      remove: /extract-template-raw,
                |                    |              /extract-final-minutiae
                |                    |
                |                    +--> SourceAfisV2Engine [REWRITE]
                |                           keep: health, extractTemplate, verify,
                |                                 DPI validation, Base64/errors/timing
                |                           remove: raw pixels, native CBOR,
                |                                   final minutiae, template SHA helper
                |                           |
                |                           +--> official SourceAFIS 3.18.1 [COPY/PIN]
                |                                  FingerprintImage(encoded bytes, DPI)
                |                                  -> FingerprintTemplate
                |                                  -> FingerprintMatcher.match
                |                                  -> raw similarity score
                |
                +--> health/adapter contract tests [REWRITE]
```

### Forbidden side branch

```text
OpenCV pixels [EXCLUDE]
  -> /extract-template-raw [EXCLUDE]
  -> /extract-final-minutiae [EXCLUDE]
  -> SourceAfisFinalMinutiaeDetector [EXCLUDE]
  -> project-owned orientation/RootSIFT/matching/RANSAC/scoring [EXCLUDE]
```

`/extract-template-raw` is not used by `SourceAfisAdapter`; it exists for detector-only raw-pixel parity and is not required by the full SourceAFIS runtime.

## 2. Protocol data

```text
raw SD300B images + published checksums [EXCLUDE from Git / external read-only]
  nominal PPI = 1000
  |
  +-------------------------------------------------------------+
                                                                |
raw SD300C images + published checksums [EXCLUDE from Git / external read-only]
  nominal PPI = 2000; PNG pHYs may say 5080
  |                                                             |
  +-------------------------------------------------------------+
                                                                v
Stage 0 curation tree [EXCLUDE from benchmark Git / reference external]
  inventories, content diagnostics, code, caches, reports
  |
  +--> frozen structural pool: 832 subjects
  |      |
  |      +--> duplicate prior-report block [UNCERTAIN]
  |             00001585 + 00001586
  |             -> eligible pool: 830
  |
  +--> manual review decisions [COPY, but currently not input-locked]
  |      11 records retained as challenge
  |      indirect material effect on seeded cohort
  |
  +--> selected subjects + provenance [COPY after approval]
  |      50 subjects; fixed sorted order; seed 20260720
  |
  +--> base_500_genuine_sd300b.csv [COPY]
  +--> base_500_genuine_sd300c.csv [COPY]
  +--> base_500_impostor_sd300b.csv [COPY]
  +--> base_500_impostor_sd300c.csv [COPY]
  |      500 rows each; 50/finger; identical logical B/C structure
  |
  +--> manifest_lock.json + MANIFEST_SHA256SUMS.txt [UNCERTAIN]
         artifact hashes valid; current config hash mismatch;
         manual decisions absent as independently hashed input
         |
         +--> future minimal protocol lock [REWRITE]
                binds copied Stage 0 inputs and their upstream hashes
                |
                +--> future PLAIN-self B/C [REWRITE / not generated]
                |      deterministic projection from genuine plain_* fields
                |
                +--> future ROLL-self B/C [REWRITE / not generated]
                |      deterministic projection from genuine roll_* fields
                |
                +--> benchmark manifest reader/preflight [REWRITE]
                       -> SourceAFIS benchmark runner [REWRITE]
```

## 3. `_analysis` relationship

```text
_analysis [EXCLUDE as protocol input / reference external read-only]
  master_index + genuine_pairs + subset_gold_*  ------+
  sd300c_bad_ppi_files                          ------+--> corroborate Stage 0
  subject_quality_rank + roll_density_1000      ------+--> heuristics only

Stage 0 _curation [authoritative after open questions]
```

The 832 analysis gold subjects exactly equal the 832 structurally complete Stage 0 subjects. Analysis does not encode the later duplicate block, manual-review trail, frozen 50 selection, impostor pairing or protocol lock, so it is unsafe as the final protocol source.

## 4. Hash/provenance chain required after migration

```text
upstream raw checksum reports
  -> upstream Stage 0 artifact hashes
  -> copied protocol artifact hashes
  -> self-manifest generator source hash + input manifest hash
  -> minimal protocol lock hash
  -> run manifest hash
  -> config hash
  -> Python implementation source hashes
  -> Maven coordinates + Java source hashes + sidecar JAR SHA-256
  -> result CSV SHA-256
  -> timing-independent score_payload_sha256
```

The current audit stopped before creating any node in the destination implementation graph.
