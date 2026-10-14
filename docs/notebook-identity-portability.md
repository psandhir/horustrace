# Wave A04 — portable notebook identity references

Notebook source is extracted into a randomized temporary Python path for
static parsing. Previously adapter-generated instance keys such as
`/tmp/horustrace-notebooks-XYZ/human_approval-15.py:83:request_approval`
escaped into Effective Authority and caused false semantic deltas (#528).

Wave A04 now rewrites **only path-prefixed metadata from the known temporary
extractor** into a source-relative, cell-qualified reference:
`notebook:relative/path.ipynb#cell-3:line-12:request_approval`.

SourceLocations continue to refer to the original notebook, and graph
relationships are constructed from consistent rewritten instance references.
Nested delegation/provenance metadata attached to notebook-origin graph nodes
is likewise normalized. No ordinary Python workspace keys are changed.

Tests cover two different extraction paths for the same original code, matching
delegation references, and repeat scans of a real notebook to verify identical
Effective Authority relationship documents and scanner findings. This addresses
temporary notebook-path nondeterminism; it does **not** prove arbitrary notebook
execution, cross-cell runtime state, or full repo-level reproducibility.

The Wave A03 passive trace can then compare source-stable notebook identities.
Regression study artifacts must confirm that pinned Fresh-16/Full-60 claims
are neither lost nor altered without source-backed disposition.
