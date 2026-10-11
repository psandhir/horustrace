# Static-flow metamorphic regression harness

Issue #511. This is an **offline static-scanner correctness suite**; it does not
execute target modules, start model providers, run MCP servers or test exploits.

The source authored in src/horustrace/evaluation/metamorphic.py provides eight
transformation families with three deterministic harmless variations per family.
Each case has a paired negative. The expected protected semantic claim is a
source-backed agent tool input reaching process-executable selection. The negative
uses a fixed program and passes the same input only via stdin, which must **not**
be upgraded to a supported source-to-executable-selection path.

Families: import-module alias, imported-symbol alias, parameter rename,
bounded helper extraction, import reordering, comment-only change,
inline parameterless local class/method, and assigned local class instance.

The manifest in tests/fixtures/adversarial_static/manifest.json pins 24 source
cases, their review rationale, expected source/sink semantics and negative
qualification. Tests additionally exercise source shadowing, dynamic construction
and distinct local agent/tool instances to defend against false positive edges.

CI executes:
    pytest -q tests/test_metamorphic_flow_regression.py
    python scripts/run_static_metamorphic.py

The second command emits per-family supported/lost and near-miss rejection
counts. These counts are **fixture preservation metrics**, not precision/recall
against independent real-world ground truth. The fresh-source evaluation
protocol in research/STUDY_EVALUATION_CONTRACT.md remains required for quality
claims. Regressions in exact in-scope semantic relationships fail CI even if
aggregate finding counts remain unchanged.

Only simple direct local methods on classes without decorators, inheritance or
custom construction are eligible for supported flow proof. Imported module
identities are canonicalized before detection but are invalidated by lexical
shadowing and top-level rebinding. Unknown dynamic constructor-method dispatch
from a source-visible registered tool with tainted parameters produces explicit
unresolved coverage rather than fabricated supported path evidence.

Known limitations: dynamic receivers, monkeypatching, polymorphism, imported
classes, descriptors and arbitrary Python execution remain unresolved. This
suite does not establish runtime exploitability or policy-control effectiveness.
