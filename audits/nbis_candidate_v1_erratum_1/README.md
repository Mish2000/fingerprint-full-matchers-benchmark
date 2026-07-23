# NBIS candidate audit provenance erratum 1

This immutable erratum corrects only the full source-tree identity claim in `nbis_candidate_v1`. The original audit package, commit, tag, scientific verdict, component evidence, PPI findings, and blocking prerequisites remain unchanged.

The official NBIS 5.0.0 archive remains valid. Its canonical source identity is now defined by `nbis_source_tree_identity_v2`, which hashes uncompressed file entries after removing exactly the single `Rel_5.0.0/` prefix. The canonical release-root tree SHA-256 is:

```text
00ae5eff70693fa5647e3ff57232eff7abd623e4786c110a3286ac8614ac7f3e
```

The archive-layout diagnostic identity, which retains `Rel_5.0.0/` in every path, is:

```text
1338ea21b50a084ec4d724449af226b129aedaf70a184109590f7cb64251d2d8
```

The original `058aeb46...` value is non-reproducible and prohibited for future use. Its precise generating cause was not recovered. This does not change the original `SUITABLE_WITH_PREREQUISITES` verdict and does not authorize an NBIS build, runtime integration, biometric processing, or resolution-policy work.

The committed validator is standard-library only, read-only, archive-independent, and dataset-independent:

```text
python tools/validate_nbis_candidate_v1_erratum_1.py
python -m pytest -q tests/test_nbis_candidate_v1_erratum_1.py
```
