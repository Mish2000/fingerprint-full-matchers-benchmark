# NBIS 1000-to-500 PPI manual policy v1

This package is a project-owner-authorized manual preprocessing policy. It is
not an official NIST reference implementation, is not NIST-certified, and does
not revise the historical `PASS + UNRESOLVED` result recorded by
`nbis-1000-ppi-downsampler-audit-v1`.

## Exact pixel contract

The pure function is:

```python
downsample_u8_matrix(input_rows) -> output_rows
```

The input is a nonempty rectangular matrix of integers in `0..255`. No color,
file-format, PPI-metadata, alpha, compression, or automatic conversion behavior
is included. The output is a list-of-lists matrix of integers in `0..255`.

The policy freezes these choices:

- Gaussian sigma: decimal `0.8475`.
- Radius: `4`; one-dimensional width: `9`.
- Numeric representation: exact integer convolution with a frozen Q31 kernel.
- Q31 scale: `2147483648`.
- Q31 kernel, offsets `-4..+4`:
  `14706, 1922071, 62430569, 503934447, 1010880062, 503934447, 62430569, 1922071, 14706`.
- Kernel generation record: normalized one-dimensional Gaussian values were
  quantized using round-half-even; the center tap absorbs the residual so the
  integer taps sum exactly to the Q31 scale.
- Convolution: separable, with no division between horizontal and vertical
  passes; the only division is after the full two-dimensional accumulation.
- Border rule: edge replication by clamping each source coordinate.
- Processing order: filter first, then factor-two decimation.
- Parity: retain zero-based source rows and columns `1, 3, 5, ...`.
- Output dimensions: `floor(width/2)` by `floor(height/2)`.
- Output rounding: truncation of the nonnegative fixed-point accumulator using
  integer floor division by `Q31_scale²`.
- Clipping: clamp the truncated result to `0..255`.

Inputs with a dimension of one are valid. The retained zero-based odd origin
then produces a zero-sized output dimension: a one-row image produces no output
rows; a one-column image with retained rows produces empty output rows.

## Implementation and verification

`tools/nbis_downsample_1000_to_500_manual_v1.py` is the canonical local
implementation. It uses a two-pass separable structure with one final exact
division. `tools/nbis_downsample_1000_to_500_manual_reference_v1.py` is an
independent direct two-dimensional implementation and does not import or call
the canonical implementation.

Both implementations are Python standard-library only. The package includes
synthetic constants, impulses, gradients, stripes, checkerboards, border and
parity patterns, every dimension from 1 through 12, and fixed-seed random
matrices. Tests require byte-identical agreement, input validation, three fresh
processes with varied working directories and environment settings, and a
read-only package validator.

The dedicated runner accepts no user-provided paths and collects exactly one
dataset-independent test file with repository conftest loading disabled. Its
filesystem guard blocks the external dataset tree and committed protocol
manifests before Python can open them. The dedicated GitHub Actions workflow
does not download evidence or software and does not invoke NBIS executables.

## Claim boundary

The permitted claim is: deterministic conformance to
`NBIS_1000_TO_500_MANUAL_POLICY_V1`. The following claims remain prohibited:

- NIST-conformant;
- official NIST reference behavior;
- NIST-certified or NIST-approved;
- resolution of the earlier official-source ambiguity.

No biometric image, project fixture, protocol image manifest, minutiae,
matcher output, or decision threshold is needed or permitted for this policy's
tests or validation.
