# Visual security report

HorusTrace can render a scan as a self-contained interactive HTML assessment:

```bash
horustrace report .
```

By default this writes `horustrace-report.html`. Choose an explicit path when the
report should be retained as a CI artifact:

```bash
horustrace report . --output artifacts/horustrace-report.html
```

Cross-repository Terraform authority evidence is supported in the same way as the
other scan-oriented commands:

```bash
horustrace report ./agent-app \
  --authority-source ../platform-infra \
  --output horustrace-report.html
```

## What the report contains

The landing dashboard summarizes discovered agents, tools, MCP servers, identities,
reachable resources, effective-authority relationships, attack paths, active
findings, Authority Contract violations, unresolved contract checks, and scan
coverage.

The agent inventory is the primary drill-down surface. Every discovered agent has a
security profile with five views:

- **Overview** — authority counts, identities, reachable resources and destinations,
  write-capable relationships, finding severity, and contract posture.
- **Agency map** — an interactive, agent-scoped path from the agent to tools/MCP
  servers, effective identities, resources, and destinations.
- **Findings** — rule findings attributed to the selected agent, including evidence,
  provenance, and remediation.
- **Contract** — the declared Authority Contract compared with reconstructed
  effective authority, including exact violated or unresolved clauses.
- **Evidence** — relationship IDs, resolution state, source locations, ADG evidence,
  approval/control state, and semantic evidence.

The report also includes repository-level findings, attack paths, contract posture,
and scan-coverage diagnostics.

## Security and trust model

The HTML renderer does not make security decisions. It consumes the same normalized
scanner graph, Effective Authority v1, Authority Contract evaluation, and Agent
Security Graph (ASG) used by HorusTrace's machine-readable outputs.

The report is local-first and offline:

- no CDN resources;
- no remote JavaScript, CSS, fonts, or images;
- no telemetry or network requests;
- scan data is embedded directly in the generated HTML;
- a restrictive Content Security Policy prevents network loading.

Because the report contains a map of agent identities, resources, destinations, and
security findings, treat it as security-sensitive evidence. Do not publish generated
reports unless the underlying scan data is suitable for disclosure.

All effective-authority and attack-path information remains static evidence.
`runtime_effectiveness` is not verified.

## Visualization contract

The visual report has its own versioned projection,
`horustrace.visual_report` schema version 1. The underlying security topology is
the existing ASG v1 document rather than a second analysis graph.

This separation is intentional: future renderers (for example a richer graph engine,
IDE integration, or hosted enterprise UI) can consume the same security model without
moving security inference into JavaScript.
