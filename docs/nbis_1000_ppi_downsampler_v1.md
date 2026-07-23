# NBIS 1000 PPI downsampler conformance audit v1

This audit determines whether an exact, deterministic 1000 PPI grayscale to
500 PPI grayscale downsampling contract can be justified from official NIST
evidence. It does not integrate runtime image decoding, process a dataset, run
MINDTCT or BOZORTH3, or measure matcher performance.

## Identity and decision boundary

- Audit: `nbis_1000_ppi_downsampler_v1`
- Prerequisite: `NBIS_1000_PPI_DOWNSAMPLER_CONFORMANCE_V1`
- Candidate method: Gaussian low-pass filtering followed by factor-2 decimation
- Evidence policy: official NIST material only
- Possible prerequisite verdicts: `RESOLVED` and `UNRESOLVED`

`RESOLVED` requires authoritative evidence for every output-affecting pixel
semantic, or an identifiable official NIST reference implementation that
decides those semantics. A plausible library default, a third-party
implementation, visual similarity, or agreement with a single local
implementation is not an oracle. If any critical semantic remains ambiguous,
the scientifically valid result is `PASS + UNRESOLVED` and no canonical
downsampler is added.

Local test success is not NIST certification. The audit records submission and
certification as separate evidence states and permits no certification claim
without an explicit NIST result for the exact implementation identity.

## Required evidence

The review covers the official PDFs for NISTIR 7839, NIST SP 500-289, and NIST
SP 500-306. Each acquired file is kept outside Git and recorded by official and
resolved URL, UTC retrieval time, title, report number, publication date, byte
size, SHA-256, page count, relevant pages and sections, and normative status.

The specification matrix has one record for each of the 38 required questions.
The critical output-affecting fields include coefficient precision,
normalization, border extension, output rounding, clipping, row and column
parity, and odd-dimension behavior. `INFORMATIVE_ONLY`, `CONFLICTING`, and
`NOT_SPECIFIED` cannot support a resolved contract without an official oracle.

The official-reference search is restricted to NIST-controlled sources. A
candidate may be an oracle only when its publisher, identity, relationship to
SP 500-289 or SP 500-306, terms, input/output semantics, and current
availability are documented and it can be tested using synthetic input only.

## Synthetic test design

`tools/audit_nbis_1000_ppi_downsampler_v1.py` prepares an external audit
workspace and a deterministic plan. Its matrices are synthetic numeric
patterns, including constants, impulses, gradients, alternating stripes,
checkerboards, edge-sensitive and parity-sensitive patterns, dimensions 1
through 12, and fixed-seed pseudorandom cases. The fixed seeds are `0`, `1`,
`7839`, `500289`, and `500306`.

Diagnostic border hypotheses explicitly cover zero padding, edge replication,
repeated-edge reflection, reflect-101, a separately defined symmetric-mirror
hypothesis, and periodic wrapping. Four zero-based decimation origins are
tested: `(row=0, column=0)`, `(0, 1)`, `(1, 0)`, and `(1, 1)`. Human one-based
row and column language must always be translated to those exact indices.

Expected output is admissible only when it comes from an official NIST
reference, agreement of two structurally independent implementations after the
specification is complete, or a hand-derived exact case. An unresolved audit
may keep diagnostic inputs, but it must not store invented canonical outputs.

## Validator and CI contract

`tools/validate_nbis_1000_ppi_downsampler_v1.py` is standard-library only and
read-only. It requires no network, WSL, external PDF, NBIS executable, image,
dataset, minutiae, score, or threshold. It checks baseline tags and identities,
the complete evidence matrix, official provenance, verdict consistency,
synthetic-only vector coverage, diagnostic test coverage, certification claim
boundaries, protected-tree identities, locks, checksums, and prohibited tracked
artifact types.

CI always runs the synthetic tests. It runs the package validator when the
result package exists, and retains the NBIS candidate, provenance erratum, and
build-environment validators plus the existing project test suite. CI does not
download official evidence or reference software.

## External evidence handling

PDFs, archives, official software, binaries, full logs, output images, external
test data, and environment exports remain outside Git. The repository contains
only evidence metadata, compact synthetic matrices, results, locks, and
checksums. Protected project areas are read only throughout this audit.

## Test isolation and controlled restart

Attempt 1 is permanently recorded as failed because unrestricted pytest
collection reached a dataset-backed protocol test. Its outputs are discarded
and cannot be used as audit evidence. Attempt 2 uses
`tools/run_nbis_1000_ppi_downsampler_tests_v1.py`, which accepts only named
fixed suites, never accepts positional test paths, and excludes the
dataset-backed supervisor test. The audit suite disables repository conftest
loading and installs a filesystem audit hook before importing pytest. The hook
blocks the external dataset tree and committed protocol manifests before an
operation can open them.
