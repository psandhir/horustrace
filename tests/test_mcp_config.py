import json
from pathlib import Path

from horustrace.scanner import scan


def test_unbound_plaintext_remote_is_config_only_not_agent_authority(tmp_path: Path) -> None:
    config = tmp_path / "mcp.json"
    config.write_text(
        json.dumps({"mcpServers": {"tools": {"url": "http://example.test/mcp"}}}),
        encoding="utf-8",
    )

    graph, findings = scan(tmp_path)
    server = next(item for item in graph.unbound_mcp_servers if item.name == "tools")
    assert server.authenticated is False
    assert server.metadata["binding_state"] == "unbound"
    config_findings = [f for f in findings if f.rule_id == "AGT031"]
    assert len(config_findings) == 1
    assert config_findings[0].severity.label() == "medium"
    assert "assessment_scope=mcp_configuration" in config_findings[0].evidence
    assert "agent_reachability=not_proven" in config_findings[0].evidence
    assert config_findings[0].agent is None
    assert not any(f.rule_id in {"AGT030", "AGT032"} for f in findings)


def test_unbound_unpinned_npx_server_is_inventory_only(tmp_path: Path) -> None:
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

    graph, findings = scan(tmp_path)
    server = next(
        item for item in graph.unbound_mcp_servers if item.name == "filesystem"
    )
    assert server.command == "npx"
    assert server.metadata["binding_state"] == "unbound"
    assert not any(f.rule_id in {"AGT001", "AGT050"} for f in findings)



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

    literal_credentials = [f for f in findings if f.rule_id == "AGT051"]
    wildcard_surfaces = [f for f in findings if f.rule_id == "AGT052"]
    assert len(literal_credentials) == 2
    assert len(wildcard_surfaces) == 1
    assert all(
        "assessment_scope=mcp_configuration" in f.evidence
        and "agent_reachability=not_proven" in f.evidence
        and f.agent is None
        for f in [*literal_credentials, *wildcard_surfaces]
    )

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


def test_unbound_https_no_auth_does_not_invent_agent_control_gap(
    tmp_path: Path,
) -> None:
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {"mcpServers": {"ide": {"url": "https://example.test/mcp"}}}
        ),
        encoding="utf-8",
    )
    graph, findings = scan(tmp_path)
    assert graph.unbound_mcp_servers
    assert not any(
        finding.rule_id in {"AGT030", "AGT031", "AGT032", "AGT051", "AGT052"}
        for finding in findings
    )


def test_unbound_config_credential_fields_report_redacted_sources(
    tmp_path: Path,
) -> None:
    (tmp_path / "mcp.json").write_text(
        json.dumps(
            {"mcpServers": {
                "one": {
                    "url": "https://example.test/mcp",
                    "headers": {"Authorization": "Bearer hardcoded-example-secret"},
                }
            }}
        ),
        encoding="utf-8",
    )
    graph, findings = scan(tmp_path)
    assert not graph.agents
    issue = next(f for f in findings if f.rule_id == "AGT051")
    assert "header:authorization" in " ".join(issue.evidence)
    assert "hardcoded-example-secret" not in str(issue)
    assert issue.authority_relationship_id is None
