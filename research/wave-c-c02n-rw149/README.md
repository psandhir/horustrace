# Wave C C02n — rw-149 conditional source-tool opinion reference

**Provisional model review, not independent blind truth.** Parent #606, follows source-only cohort evidence #617.

Pinned real Pydantic AI source: `LeonieFreisinger/pydanticai-base-agent@0cf88a4caf2b5da29ff7af8364d4db14ac9e50b4`, four Git blobs with 37 source-line witnesses in `research/wave-c-c02j-rw149/conditional-tool-source-candidates.json`.

This reference adds 20 exact-blob/line **source-level opinions** (10 positive, 7 selected hard-negative, 3 effective-authority UNKNOWN). The source selection branches are: level 1 selects zero, level 2 selects `list_tables` and `describe_table`, levels 3/4 select five; `BaseAgent` iterates the selected list and calls `self._agent.tool(tool)`. A Chainlit `SQLQueryAgent()` wrapper is not another direct SDK constructor. Environment-configured `DEMO_LEVEL`, installed SDK registration semantics, successful imports, deployed sessions and actual tool reachability remain UNKNOWN.

All four pinned source blob URLs and all 37 line strings were separately checked against GitHub source objects at the pinned commit on 24 October 2026; this is **anchor verification, not independent semantic adjudication**. The selected source statements are not an exhaustive positive or negative universe. This is the **same assistant's unblinded model review**, not a second independent reviewer.

The versioned C02a scorer is required to return `not_assessed` with `aggregate=null`, precision/recall null and no claimed TP/FP/FN/TN on this provisional reference. New test verifies the original 37-site lineage, branch-specific positives/near-misses and fail-closed release gates.

**Next missing evidence:** truly source-first external independent reviewers, full relevant positive and negative universes, context-stratified scanner predictions at the same exact source commit, runtime SDK/execution checks where needed, and a new unseen D01 holdout. Active145 excludes LangGraph; Frozen180 and original gates remain unchanged. No production Graph, authority, findings, paths or UX code is modified.
