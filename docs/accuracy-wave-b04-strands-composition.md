# Wave B04 — passive Strands orchestrator → tool wrapper → inner Agent candidates

This opt-in source-only slice of issue #540 recognizes a conservative import
chain in the pinned Strands demo
aws-samples/sample-multi-agent-region-expansion-planner at
30d03d7c9f6512e5bf10601879382fac9c3a16b1:

1. A function creates an Agent whose tools keyword is a concatenation of
   exactly two source-visible local lists, one containing imported agent-tools.
2. Those names are explicitly imported from the local agents package and
   re-exported by its __init__.py from one local Python module each.
3. The matched function in that module carries a source-visible @tool
   decorator, constructs a local Agent, and invokes that exact local instance.

For every resolved case this yields two PARTIAL source-candidate INVOKES edges:
orchestrator Agent → @tool wrapper, and wrapper → nested Agent instance.
Both Agent instances get distinct source-qualified identities and exact lines.
The sidecar is source_native_strands (SemanticDiscovery v2).

**Security limits:** @tool wrappers in this pinned example contain a
conditional Strands import and a fallback decorator; even a complete source
chain does not prove the library was available, the wrapper was invoked, the
model chose that tool, the nested Agent executed, or that any credentials and
capabilities are effective. Do not create AGENT_CAN_CALL, EXPOSES_TOOL, or
unconditional DELEGATES_TO edges. Unexported names, dynamic tools expressions,
shadowed wrappers, missing nested invocations, aliases and cross-package
functions remain unresolved. No Graph, effective authority, finding, ADG or
attack-path migration occurs in this PR.

**Next evidence gate:** reconcile the historic 10-discovered / 2-consolidated
agent stage delta with distinct per-source candidates, including unexported
names and source/runtime context, rather than declaring eight false negatives.
Independent blinded adjudication and Fresh-16/Full-60 source regression are
required before any production projection cutover. This is partial B04, not a
wave completion or measured precision/recall improvement.
