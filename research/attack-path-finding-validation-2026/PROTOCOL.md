# Human-Adjudicated Attack-Path and Finding Validation Protocol

> **Scope clarification (2026-10-08):** This document defines human-grounded review for the historical validation effort. New independent source-cohort studies must also comply with [the shared study evaluation contract](../STUDY_EVALUATION_CONTRACT.md), which permits two independently locked **LLM** reviewers for automated source adjudication with escalation. Such evidence must **not** be labelled two-human-reviewer ground truth.


## Objective

Measure two product-quality questions that the automated frozen source reference cannot answer exhaustively:

1. Are HorusTrace attack paths valid security-relevant paths?
2. Are individual HorusTrace findings factually supported and correctly classified?

This study is independent from the frozen 2026 automated truth artifacts. Those artifacts remain immutable.

## Blinding rule

Reviewer packets must not contain HorusTrace attack-path or finding output.

Reviewers receive only:

- pinned repository and commit SHA;
- bounded source files;
- application/deployment context required to understand the case;
- a proposed source-level path/assertion question;
- standardized adjudication fields.

The raw scanner output and scoring metadata are not revealed to reviewers before their relevant review phase is locked. Phase B neutral claims may be derived from scanner findings, but their HorusTrace origin, rule ID and severity remain hidden.

## Reviewers

Each case requires **two independent human reviewers**.

A review is invalid when:

- reviewer identity is missing;
- reviewer 1 and reviewer 2 are the same person;
- either reviewer declares that HorusTrace output was seen before adjudication;
- the review is not explicitly locked.

ChatGPT-generated review content does not satisfy the independent-human-review requirement.

## Attack-path pack

Target: **20–30 cases** stratified across:

- source-proven valid paths;
- invalid near-misses;
- approval-gated paths;
- delegated reachability;
- MCP allow/deny filtered paths;
- dynamic/unresolved constructs;
- cross-agent paths;
- deployment/identity-aware paths where evidence exists.

Each case asks whether a specific source-level relationship chain is security-reachable under the static evidence contract.

Allowed verdicts:

- `valid`
- `invalid`
- `unresolved`

Reviewers must provide evidence paths and a concise rationale.

## Finding validation phases

Finding recall and finding precision use separate blinded phases.

### Phase A — source-blind recall reference

Before HorusTrace finding output is used for sampling, reviewers adjudicate a source-derived assertion pack. This establishes a locked denominator of source-supported assertions that can later be mapped to scanner detections for recall analysis.

The Phase A pack is stratified by source assertion type and repository, not by HorusTrace rule ID or severity.

### Phase B — rule/severity-stratified precision sample

Only after Phase A is locked may the study coordinator inspect HorusTrace finding output to construct the precision sample.

Phase B must:

- stratify scanner findings by rule ID and scanner-reported severity;
- convert each selected finding into a neutral factual claim plus bounded source scope;
- hide rule ID, scanner severity, confidence, finding ID and whether the claim originated from HorusTrace from the reviewers;
- use two independent human reviewers under the same evidence/rationale/lock requirements;
- compare reviewer-supported factual truth and independently assigned severity to the hidden scanner metadata only after the Phase B reviews are locked.

For Phase B, the reviewer field `horustrace_output_seen: false` means the reviewer did not see the raw HorusTrace record or its rule/severity metadata. Reviewers necessarily see the neutral claim they are asked to adjudicate.

## Finding sample

Findings are sampled by **rule and severity**, not by convenience.

The pack should include:

- critical/high/medium/low severities where present;
- common high-volume rules;
- rare rules;
- findings involving approval, identity, MCP, network/resource scope and delegation;
- negative controls / near-miss cases.

For each assertion reviewers record:

- factual support: `supported | unsupported | unresolved`;
- severity: `critical | high | medium | low | informational | unresolved`;
- evidence paths;
- rationale.

## Consensus

A case is consensus-adjudicated only when both locked reviews agree on the primary verdict.

Disagreements are retained and reported separately; they are not silently resolved by majority or scanner output.

A third reviewer may resolve disagreements in a later revision, but the original two reviews remain immutable.

## Metrics

After reviewer lock and scanner reveal, publish:

### Attack paths

- precision;
- recall over the curated valid/invalid case pack;
- unresolved rate;
- false-positive causes;
- false-negative causes;
- disagreement rate.

### Findings

- assertion precision;
- assertion recall over the curated assertion pack;
- severity exact-match rate;
- severity one-level disagreement rate;
- severity disagreement taxonomy;
- false-positive / false-negative causes.

## Safety and evidence rules

- target application code is not installed or executed;
- pinned source is authoritative for static truth;
- runtime behavior that cannot be proven statically is `unresolved`;
- no truth edits based on scanner output;
- post-hoc corrections are separate adjudications;
- original frozen 2026 truth remains unchanged.

## Acceptance

Issue #157 is complete only when:

- the review pack is locked;
- two independent reviewers have completed all scored cases;
- scanner output is evaluated only after lock;
- attack-path precision/recall is published;
- finding assertion precision/recall is published;
- severity disagreement taxonomy is published;
- FP/FN causes are documented.
