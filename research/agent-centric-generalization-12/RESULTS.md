# Agent-centric generalization rerun — results

## Executive result

The exact 12 frozen Google ADK, Pydantic AI and OpenAI Agents repositories from #290
were rerun on the current agent-centric scanner after #291, #292 and #293.

All **12/12 scans completed successfully** on scanner commit
`faec409216bbbd77c8800f3fc041f31e1212132c` in workflow run
`37042400793`.

Across the three supported framework strata, findings changed from **70 to 61** and
attack paths from **7 to 5**. Claim/path comparison found **no new semantic claims or
attack paths**.

The final #290 adjudication cannot be carried forward by treating all nine removed
claims as false positives: two of the removed constrained-eval findings were previously
adjudicated **partial**, not FP. The corrected post-rerun materially-supported precision
is therefore **54/61 = 88.5%**.

## Scope-normalized comparison

The full #290 20-repository study included Google ADK, Pydantic AI, OpenAI Agents,
LangGraph and MCP/custom and reported 59/82 = 72.0% materially-supported precision.

For the three frameworks that remain in product scope, the #290 baseline was already:

- Google ADK: 23/24 supported
- Pydantic AI: 15/21 supported
- OpenAI Agents: 18/25 supported
- **Total: 56/70 = 80.0%**

The current rerun is therefore compared against **80.0%**, not against the 72.0%
five-stratum headline.

## Finding result

| Framework | #290 findings | Current findings | TP | Partial | FP | Supported precision |
|---|---:|---:|---:|---:|---:|---:|
| Google ADK | 24 | 24 | 16 | 7 | 1 | **23/24 = 95.8%** |
| Pydantic AI | 21 | 17 | 4 | 9 | 4 | **13/17 = 76.5%** |
| OpenAI Agents | 25 | 20 | 2 | 16 | 2 | **18/20 = 90.0%** |
| **Total** | **70** | **61** | **22** | **32** | **7** | **54/61 = 88.5%** |

Compared with the same frozen framework strata in #290:

- materially-supported precision: **80.0% -> 88.5%** (**+8.5 pp**)
- explicit false positives: **14 -> 7**
- strict true positives: **22 -> 22**
- partial findings: **34 -> 32**
- explicit FP rate: **20.0% -> 11.5%**

This is a meaningful precision improvement, but it is not 91.8%.

## Exact claim delta

The 61 current findings were matched to #290 by case, rule, agent, claim text and source
location.

- new semantic claims: **0**
- removed claims: **9**
- retained claims: **61**
- retained claims with material evidence-shape changes: **2**
  - PharmIQ AGT053 drops the unsupported `process.execute` capability while retaining
    data-write/secrets authority.
  - Pydantic Research Agent Gmail AGT040 gains network-external evidence; the approval
    claim itself is unchanged.

### Removed findings and prior verdicts

**OpenAI Agents — 5 false positives removed**

- one `NET002` Search Agent claim in `openai-agents-demos`
- four `NET002` AgentOps WebSearch/ImageGeneration claims

All five were previously adjudicated FP because the destination is fixed or
provider-managed rather than arbitrary model-selected egress. These fixes came from
#291.

**Pydantic AI / PharmIQ — 2 false positives removed**

- `PATH001`: MCP server bootstrap represented as model-reachable process execution
- `PATH006`: MCP startup/environment composition represented as combined model
  authority

Both were previously adjudicated FP. These fixes came from #292.

**Pydantic AI Research Agent — 2 partial findings removed**

- `AGT020`: restricted in-process calculator `eval` described as shell/process
  execution
- `CAP004`: the corresponding process + network aggregate

The final #290 rule-level adjudication classified these as **partial**, not FP:
`AGT020` had 2 TP / 3 partial / 2 FP, with the Pydantic calculator supplying the third
partial; `CAP004` had 1 TP / 1 partial, with the Pydantic calculator supplying the
partial. #292 correctly suppresses these overbroad process-execution claims while
retaining constrained privileged-execution representation through AGT040.

## Attack paths

The scoped #290 cohort had seven attack paths:

- four Google ADK Pipeline Reviewer command paths — partial because the executable and
  command structure are fixed
- one PharmIQ MCP state-changing data path — partial/materially supported
- two PharmIQ process/bootstrap paths — false positive

The current rerun has exactly the five supported/qualified paths:

- TP: **0**
- partial: **5**
- FP: **0**
- materially-supported path rate: **5/5 = 100%**

This is an improvement from **5/7 = 71.4%**. The 100% figure should not be read as five
strictly proven arbitrary-impact paths; all five retain material scope qualifications.

## Residual false positives

The remaining seven FPs are concentrated in four semantic defects:

1. **Google ADK — 1**
   - Pipeline Reviewer `NET001`: fixed PyPI/Maven hosts are still described as broad
     or unrestricted destination reachability.

2. **Pydantic AI — 3 destination-provenance FPs**
   - Gmail/Brave-backed `NET002` claims still lose fixed/provider destination
     semantics at agent aggregation.

3. **Pydantic AI — 1 capability-type FP**
   - `compose_email_content` is classified as a privileged AGT040 capability although
     it is an in-process composition helper rather than an external high-impact action.

4. **OpenAI Agents mixed repository — 2 scope-leakage FPs**
   - AgentOps `langgraph_example.py` and notebook still produce AGT020 findings for
     an **unbound** LangGraph/LangChain `calculate` tool.
   - After #293, LangGraph is not a supported security-analysis framework; generic
     inventory discovery should not manufacture effective-authority findings from this
     code.

If the two LangGraph-only mixed-repository findings are excluded analytically, the
intended-framework claim set is **54/59 = 91.5% materially supported**. Operational
scanner precision remains **88.5%** until that scope leakage is fixed.

## Attribution

The precision delta must not be attributed to #293 alone.

- #291 removed the five OpenAI provider-destination FPs.
- #292 removed the two PharmIQ bootstrap FPs and two overbroad constrained-eval
  partials.
- #293 removes LangGraph framework support and production plumbing.

The value of this rerun for #293 is therefore primarily **non-regression and product
scope validation**: ADK, Pydantic AI and OpenAI Agents continue to scan successfully,
and no new claim/path appears after LangGraph removal.

It also exposes one incomplete aspect of the cleanup: generic unbound-tool logic can
still emit LangGraph-only findings inside a mixed repository.

## Conclusion

The agent-centric direction is supported by the scoped data, but the current quality
level is uneven:

- **Google ADK: 95.8% materially supported** — strong unseen precision.
- **OpenAI Agents: 90.0% raw; effectively 100% on the retained OpenAI claims once the
  two LangGraph-only scope leaks are excluded** — strong framework semantics, one
  cross-framework cleanup defect.
- **Pydantic AI: 76.5%** — still the main semantic-fidelity problem.

The next product work should target the seven residual FPs before another fresh unseen
cohort. In particular, fixed/provider destination provenance and strict
supported-agent binding should be treated as framework-level invariants rather than
additional one-off rule exceptions.

## Caveat

This is an apples-to-apples precision/regression study over the same frozen repositories.
The #290 evaluator saw HorusTrace claims, so this does **not** establish blind recall.
A new unseen three-framework cohort remains necessary after the residual systematic
defects are fixed.
