# ADK + Pydantic AI 10-case post-fix litmus

Final scanner head validated: `328a3a20c3dcdb2bd3edfd394a673c23fdca2d17`

GitHub Actions run: `36721670948`

- Scanned: **10/10**
- Scan errors: **0**
- Findings: **39**
- Attack paths: **9**
- The workflow is non-mutating; the full per-case JSON reveal is retained as the workflow artifact `framework-litmus-adk-pydantic-10-postfix`.

| Case | Framework | Findings | Paths | Bound MCP | Result |
|---|---|---:|---:|---:|---|
| rw-009 | Google ADK | 0 | 0 | 0 | Fixed-provider GitHub egress remains constrained; false NET002/PATH009 removed |
| rw-017 | Google ADK | 11 | 2 | 0 | Public-default authentication predicate carried into both delegated write paths |
| rw-004 | Google ADK | 13 | 0 | 0 | Runtime source blockers surfaced separately from declared authority |
| rw-007 | Google ADK | 2 | 1 | 0 | Model-selected local-file -> Document AI path retained |
| rw-012 | Google ADK | 0 | 0 | 0 | Precision control remains clean |
| rw-155 | Pydantic AI | 1 | 0 | 1 | Only AGT054 remains: configuration-derived MCP catalogue without detected per-call approval |
| rw-152 | Pydantic AI | 7 | 3 | 0 | Code-execution paths retained with runtime-blocker qualification |
| rw-147 | Pydantic AI | 2 | 1 | 0 | Search-result-derived destination now modeled |
| rw-150 | Pydantic AI | 2 | 1 | 0 | Direct dynamic URL path retained |
| rw-164 | Pydantic AI | 1 | 1 | 0 | RAG directory exposure path retained |

## P0/P1 closure

- **P0 Pydantic dynamic MCP:** configuration-derived MCP toolsets are represented as bound-but-catalogue-unresolved authority; concrete tools are not invented.
- **P0 fixed-provider destination propagation:** fixed provider origins survive helper/delegation projection, preventing unrestricted-egress false positives.
- **P1 second-order destination provenance:** provider search-result URLs dereferenced by server-side HTTP are represented distinctly from direct arbitrary-URL authority.
- **P1 runtime viability:** import/constructor blockers qualify findings and paths without erasing declared static authority.
- **P1 Pydantic control/resource precision:** command allowlists, injection filters, .shotgun path confinement, internal RunContext plan state, and same-name agent instances are preserved.
- **P1 ingress predicates:** public-default/authentication metadata is carried into composed runtime ingress paths.

The dedicated litmus workflow runs targeted semantic regressions first, scans the exact ten pinned repositories, and uploads the reveal as an artifact without writing back to the PR branch.
