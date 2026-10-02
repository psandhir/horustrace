# Blind source review schema

Each `source-reviews/<case_id>.json` must be created before scanner reveal.

```json
{
  "schema_version": 1,
  "case_id": "fresh-...",
  "repo": "owner/name",
  "sha": "<exact sha>",
  "framework": "google-adk | pydantic-ai | openai-agents",
  "review_status": "blind_source_review_complete",
  "horustrace_output_seen": false,
  "effective_agents": [
    {
      "name": "...",
      "binding": "...",
      "source_context": "runtime | example | test",
      "evidence": ["path:line or source description"]
    }
  ],
  "expected_claims": [
    {
      "claim_id": "<case>-c01",
      "category": "capability | control | resource | destination | identity | mcp | other",
      "agent": "...",
      "statement": "...",
      "severity": "informational | low | medium | high | critical",
      "qualifications": ["..."],
      "evidence": ["path:line or source description"],
      "confidence": "high | medium | low"
    }
  ],
  "expected_paths": [
    {
      "path_id": "<case>-p01",
      "agent": "...",
      "source": "...",
      "sink": "...",
      "statement": "...",
      "qualifications": ["..."],
      "evidence": ["..."],
      "confidence": "high | medium | low"
    }
  ],
  "negative_controls": [
    {
      "control_id": "<case>-n01",
      "statement": "A claim that must not be made from this source.",
      "evidence": ["..."]
    }
  ],
  "coverage_notes": ["..."]
}
```

Reviews should capture effective authority and material security semantics, not enumerate every benign function.
