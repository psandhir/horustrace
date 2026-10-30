# Wave C C02x — exact source evidence attestation and stale-claim rejection

Related: Wave C [#543](https://github.com/psandhir/horustrace/issues/543), independently complete reference [#606](https://github.com/psandhir/horustrace/issues/606), C02r source shadow #629 and C02w Workbench #638.

## Purpose

The earlier C02r `source-shadow.json` exposed MCP client configuration,
distinct local stdio server source implementations, static tool declarations
and source file/line locations. C02w rendered that evidence in the
standard Security Workbench after checking that each source location existed.
It **could not detect a same-line or same-length edit** that changed a source
file, or a stale artifact reused for another source commit.

C02x introduces a **fail-closed v2 source-only artifact**. The source
shadow projector itself remains unchanged and continues to emit a v1
in-memory diagnostic. The pinned C02r source-study writer **seals** that
diagnostic into a v2 JSON artifact by reading the exact committed checkout.

### Attestation fields

`schema_version: 2` adds `source_revision`:

- `mode: c02x_exact_git_sha1_blob_and_worktree_sha256`
- `commit_sha`: full 40-character Git SHA-1 `HEAD` of the source checkout
- `claims_sha256`: SHA-256 of the version, node/edge identifiers,
  relation data and safety-sensitive scanner/source-only claim fields
- `files`: **complete, deterministic, sorted witness universe** drawn
  from all projected source nodes. Each file has repository-relative
  `path`, `sha256` of exact worktree bytes, Git `git_blob_sha`,
  `git_mode` and exact `size_bytes`
- Explicitly `runtime_effective_authority_verified: false` and
  `independently_adjudicated: false`

The sealer requires a Git repository root at an exact SHA-1 `HEAD`,
verifies every witnessed path is an ordinary tracked Git blob,
checks Git tree mode and blob object hash against actual working bytes,
rejects symlink escapes and oversized inputs, and emits no verification
claims for missing/untracked files.

The Workbench's `--mcp-source-shadow` loader **requires v2**. It rejects
missing/legacy attestation, source HEAD mismatch, dirty files (including
same-line and same-length modifications), changed/missing node or edge
claims, cherry-picked file manifests, duplicate/extra paths, invalid SHA
values, and untracked/symlink witnesses **before producing an HTML report**.
It checks every referenced source file, not only a proposed positive
example; no source witness may be silently excluded.

### User workflow

Generate the source shadow on a pinned checkout (without executing the
target project):

```bash
python -m scripts.wave_c_c02r_pinned_mcp_shadow_study \
  --checkout /path/to/pinned-rw080-checkout \
  --output /path/to/artifacts
```

Then, on **the same exact Git checkout**:

```bash
horustrace report /path/to/pinned-rw080-checkout \
  --mcp-source-shadow /path/to/artifacts/source-shadow.json \
  --output workbench-with-mcp-source-evidence.html
```

The pinned rw080 GitHub Actions workflow creates and archives both
`source-shadow.json` and
`workbench-with-mcp-source-evidence.html` and runs browser drilldowns.
An old v1 artifact is deliberately **not eligible** for the opt-in
Workbench view; regenerate it from its original pinned checkout.

The separate standalone source HTML diagnostic continues to support
the existing v1 source-only JSON input, which is *not source-freshness
attested* unless it is rendered from a v2 artifact and independently
checked with its source checkout. **Offline standalone HTML cannot
reverify a changed checkout by itself.**

## Limitations and NO-GO

This is a **same-commit, file-byte and artifact-integrity consistency
check**, not cryptographic independent authentication: someone controlling
both a repository and its attestation could regenerate hashes; this does
not certify the truth of scanner node semantics, exhaustive V2 positives
and negatives, installed SDK behavior, deployed MCP runtime callability,
effective agent authority, security findings or attack-path reachability.

C03/C04 production Graph/authority/path migration remains NO-GO until
the independent complete source oracle and truly unseen D01 under #606,
versioned runtime control evidence where required, and repository-admin
enforcement of the accuracy gate under #558. There are no relaxed
Fresh16/Full60 thresholds and no changes to canonical production reports
without explicit opt-in.

## Test coverage

- Clean Git SHA-1 HEAD and complete two-file source witness manifests.
- Byte-for-byte and same-length/same-line source edits detected.
- Non-source commits causing HEAD drift detected even with identical files.
- Missing/untracked files, symlink escapes, malformed and forged digests,
  duplicate/partial/extra file lists, and modified node claims rejected.
- Legacy v1 Workbench input fails closed.
- Current pinned rw080 C02r study verifies all witness files against
  original Git blobs and replays **3 separate local stdio implementation
  source sites and 25 static tool exposures**.
- Existing CLI and standalone Workbench real Chromium navigation/tests,
  CodeQL, Python 3.11/3.12, Fresh16, Full60 and same-head accuracy
  regression are unchanged and required.
