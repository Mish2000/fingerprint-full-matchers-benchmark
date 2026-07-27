# NBIS 1000-to-500 PPI manual policy v1

This package records a deterministic project-local manual policy selected by
the project owner after the official-source conformance audit concluded
`PASS + UNRESOLVED`.

The earlier audit result and audit tag remain unchanged. This package does not
claim to reproduce an official NIST reference implementation and does not claim
NIST conformance, approval, or certification.

The policy uses a frozen symmetric Q31 Gaussian kernel for sigma 0.8475 and
radius 4, exact integer accumulation, edge replication, filtering before
factor-two decimation, zero-based odd row and column origins, one final
truncating fixed-point division, and u8 clamping. Exact coefficients and all
input, output, dimension, border, parity, rounding, and clipping rules are
recorded in `policy.json`.

The canonical implementation uses a two-pass separable structure. The
independent reference uses direct two-dimensional convolution. Forty-seven
synthetic vectors include constants, impulses, gradients, stripes,
checkerboards, border and parity patterns, dimensions 1 through 12, and five
fixed random seeds. Every expected output is retained only after both
implementations agree exactly.

No biometric input, dataset, fixture, protocol image manifest, NBIS executable,
minutiae, matcher output, or decision threshold is used by implementation,
testing, package generation, or validation.
