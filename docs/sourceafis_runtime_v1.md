# SourceAFIS runtime v1

The only supported biometric path is:

```text
encoded image bytes
-> SourceAFIS FingerprintImage with explicit DPI
-> SourceAFIS FingerprintTemplate
-> SourceAFIS FingerprintMatcher.match
-> finite raw similarity score
```

The Java sidecar binds to loopback and exposes exactly `GET /health`, `POST /extract-template`, and `POST /verify`. Python keeps one persistent HTTP connection and manages the sidecar lifecycle. Templates are official SourceAFIS serialized templates; callers cannot provide pixels, minutiae, or custom feature structures.

SourceAFIS is pinned to 3.18.1, Jackson Databind to 2.17.2, and Java compilation to release 11. There is no external image preprocessing, template cache, thresholding, decision logic, identification, or score normalization.

No permitted tracked non-SD300 fingerprint fixture exists in the audited source repository. Consequently successful extraction/verification smoke and old/new score parity are blocked. Dataset-independent health, route, malformed-input, unit, and lifecycle checks cover the runtime without accessing the frozen cohort.
