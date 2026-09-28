import json
from pathlib import Path

from horustrace.scanner import scan


def test_remote_http_without_auth_is_flagged(tmp_path: Path) -> None:
    config = tmp_path / "mcp.json"
    config.write_text(
        json.dumps({"mcpServers": {"tools": {"url": "http://example.test/mcp"}}}),
        encoding="utf-8",
    )

    _, findings = scan(tmp_path)
    ids = {f.rule_id for f in findings}
    assert "AGT030" in ids
    assert "AGT031" in ids


def test_unpinned_npx_server_is_flagged(tmp_path: Path) -> None:
    config = tmp_path / "mcp.json"
    config.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "filesystem": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-filesystem", "."],
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    _, findings = scan(tmp_path)
    ids = {f.rule_id for f in findings}
    assert "AGT050" in ids
    assert "AGT001" in ids



def test_loopback_mcp_does_not_require_remote_tool_allowlist(tmp_path: Path) -> None:
    config = tmp_path / "mcp.json"
    config.write_text(
        json.dumps({"mcpServers": {"local": {"url": "http://localhost:8000/mcp"}}}),
        encoding="utf-8",
    )

    _, findings = scan(tmp_path)
    ids = {f.rule_id for f in findings}
    assert "AGT030" not in ids
    assert "AGT031" not in ids
    assert "AGT032" not in ids


def test_mcp_config_redacts_literal_credentials_and_flags_broad_surface(
    tmp_path: Path,
) -> None:
    config = tmp_path / "mcp.json"
    config.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "stripe": {
                        "command": "npx",
                        "args": [
                            "-y",
                            "@stripe/mcp",
                            "--tools=all",
                            "--api-key",
                            "sk_test_example_secret",
                        ],
                    },
                    "supabase": {
                        "command": "npx",
                        "args": [
                            "-y",
                            "@supabase/mcp-server-supabase@latest",
                            "--access-token=sbp_example_secret",
                        ],
                    },
                }
            }
        ),
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    servers = {server.name: server for server in graph.all_mcp_servers()}

    stripe = servers["stripe"]
    assert "sk_test_example_secret" not in " ".join(stripe.args)
    assert "<redacted>" in " ".join(stripe.args)
    assert stripe.metadata["credential_values_redacted"] is True
    assert stripe.metadata["broad_tool_surface"] is True

    supabase = servers["supabase"]
    assert "sbp_example_secret" not in " ".join(supabase.args)
    assert "--access-token=<redacted>" in supabase.args

    ids = [finding.rule_id for finding in findings]
    assert ids.count("AGT051") == 2
    assert "AGT052" in ids

    serialized_evidence = "\n".join(
        evidence
        for finding in findings
        for evidence in finding.evidence
    )
    assert "sk_test_example_secret" not in serialized_evidence
    assert "sbp_example_secret" not in serialized_evidence


def test_mcp_config_environment_placeholder_is_not_literal_credential(
    tmp_path: Path,
) -> None:
    config = tmp_path / "mcp.json"
    config.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "tools": {
                        "command": "npx",
                        "args": [
                            "-y",
                            "@example/mcp@1.2.3",
                            "--api-key",
                            "${MCP_API_KEY}",
                        ],
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    server = graph.all_mcp_servers()[0]

    assert server.metadata["literal_credential_sources"] == []
    assert not any(finding.rule_id == "AGT051" for finding in findings)


def test_mcp_runtime_provided_token_is_treated_as_placeholder(
    tmp_path: Path,
) -> None:
    config = tmp_path / "mcp.json"
    config.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "tickets": {
                        "url": "https://mcp.example.test/mcp",
                        "token": "runtime-provided",
                        "allowedTools": ["read_ticket"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    _, findings = scan(tmp_path)

    assert not any(finding.rule_id == "AGT051" for finding in findings)
