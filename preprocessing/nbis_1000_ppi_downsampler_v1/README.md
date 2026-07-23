# NBIS 1000 PPI downsampler conformance audit v1

Result: `PASS + UNRESOLVED`.

The official NIST guidance establishes a Gaussian low-pass treatment with
sigma 0.8475, radius 4, filtering before factor-two decimation, and a named
odd-column/odd-row strategy. It does not establish one reproducible byte-level
implementation. NISTIR 7839 describes border handling as mirroring or
duplicating edge pixels, while Appendix C substitutes the current convolution
center pixel for every out-of-bounds tap. The guidance also does not
authoritatively fix coefficient precision, finite-kernel normalization,
rounding, clipping, the zero-based parity origin, or odd-dimension behavior.

SP 500-306 identifies a NIST Downsampler used to generate conformance reference
outputs and says it was released with NBIS. The current official NIST release
index exposes NBIS 5.0.0, but that source tree and its official changelog do not
contain an identified SP 500-289 downsampler artifact. No usable, versioned
official oracle was therefore acquired or executed.

The synthetic vectors in this package are diagnostic numeric matrices only.
They contain no canonical expected outputs because inventing those outputs
would resolve the documented ambiguity arbitrarily. No canonical or independent
downsampler implementation is included, and no conformance or determinism run
of a downsampler was performed.

Attempt 1 remains permanently `FAIL`: unrestricted test collection executed a
dataset-backed protocol test. Its results were discarded and are not audit
evidence. Attempt 2 used only fixed dataset-independent test allowlists and did
not access biometric inputs, datasets, fixtures, protocol image manifests,
MINDTCT, BOZORTH3, minutiae, or matcher outputs.

NIST submission was not performed and NIST certification was not received.
The only permitted claim is local audit completion with an unresolved
prerequisite. Work stops before any 2000 PPI policy or biometric processing.
