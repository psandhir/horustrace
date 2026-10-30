# Wave C C02s — independent mechanical source parser for MCP syntax

Parent: [#606](https://github.com/psandhir/horustrace/issues/606) and [#543](https://github.com/psandhir/horustrace/issues/543).
This is a **separate-source verifier for bounded syntax**, not an independent
human adjudication, semantic truth for all framework versions, or release GO.

## Engineering goal

Validate four exact pinned FastMCP source implementation declarations and all
28 statically decorated tool function sites in
`Amlan66/SSEEnabledMCPAgent@11531239e71b123f25b3c6103ee36a9d614d0032`,
using Python's standard-library `ast`, **not** HorusTrace's `mcp_python`
adapter, source-graph reconciliation or a scanner-suggested candidate set.

The bounded universe is the full AST of these four pinned source files:
`mcp_server_1.py`, `mcp_server_2.py`, `mcp_server_3.py`,
`mcp_telegram_server.py`. It is **only** the declared module-level literal
FastMCP and function-decorator syntax construct; this is not a complete MCP
runtime catalogue, all repo files, indirect registration, transitive imports,
effective authority, or a complete real-world V2 truth universe.

The oracle parses original pinned **Git blob** bytes and checks exact
commit, tree mode/path and SHA1 object digest. It rejects missing
source and parses every top-level decorated function in scope rather than
copying the 25 candidate labels from HorusTrace. Source digests and
independent stable identifiers are emitted.

## Negative and metamorphic cases

- Two `FastMCP("Calculator")` implementations in **different files** are
  distinct source instances even if displayed names match.
- `@mcp.resource` and `@mcp.prompt` function declarations are **not**
  `EXPOSES_TOOL`. The pinned source has one resource and two prompts.
- Commented-out decorators never become tool declarations.
- Unknown owners, reassigned source symbols, dynamic exported names, direct
  `add_tool` registrations and invalid syntax become rejected/unresolved,
  not confident absence or guessed runtime metadata.
- Metamorphic comment append keeps tool count unchanged. Changed tool
  declarations or source blob hashes fail the pinned study.

## Cross-check of real current scanner against independently parsed source

`scripts/wave_c_c02s_independent_ast_mcp_study.py` runs the scanner statically
on the identical pinned revision and creates the read-only #629 source shadow.
It aligns **exact file + function-definition line + name** witnesses:

- 4 FastMCP source implementations in the oracle.
- 28 static `@mcp.tool` functions; 3 non-tool negatives.
- Of those, 3 locally configured stdio implementations and 25 source tool
  witnesses should match #629's shadow. The Telegram implementation and 3
  tool source sites are already retained in production ADG and are not
  duplicated by the local stdio shadow.

Any missing or extra site fails the dedicated pinned workflow. A mismatch
would be a **source declaration discrepancy for review**, not a certified
false positive/false negative. The study asserts the scanner ADG remains
byte-for-byte unchanged after projection.

The output always reports `certified_precision=null`,
`certified_recall=null`, effective runtime callability UNKNOWN, no claim of
independent human verification, and `production_cutover_authorized=false`.

## Validation and remaining requirements

Dedicated GitHub Actions study records original-source AST inventory,
pinned blobs, scanner differential and hard negatives as artifact JSON.
Changed `src/horustrace/**` triggers the existing unmodified full
Fresh-16, Full-60, CI, CodeQL and same-head accuracy-regression workflows.

This is the first mechanically corroborated MCP declaration-scope study,
**not** completion of #606. Broader source/cross-framework coverage,
external reviewer provenance, a genuinely unseen D01, #558 required
branch-protection gate, installed runtime authority contracts and the
12 Amazon unresolved cases remain blocking. C03/C04 production cutover
remains **NO-GO**, not switched on by this change.
