import json
from pathlib import Path

import pytest

from horustrace.cli import main
from horustrace.config import ConfigError, load_config


def test_config_disables_rule_and_overrides_severity(tmp_path: Path, capsys):
 (tmp_path/'agent.py').write_text("from agents import Agent, ShellTool\nagent=Agent(name='ops', tools=[ShellTool()])")
 (tmp_path/'.horustrace.yaml').write_text('version: 1\nrules:\n  AGT040: {enabled: false}\n  AGT020: {severity: low}\n')
 assert main(['scan',str(tmp_path),'--format','json','--fail-on','none'])==0
 report=json.loads(capsys.readouterr().out)
 assert 'AGT040' in report['configuration']['disabled_rules']
 assert not any(item['rule_id']=='AGT040' for item in report['findings'])
 assert next(item for item in report['findings'] if item['rule_id']=='AGT020')['severity']=='low'

def test_invalid_config_fails_closed(tmp_path: Path):
 (tmp_path/'.horustrace.yaml').write_text('version: 1\nrules: {NOPE: {enabled: true}}')
 with pytest.raises(ConfigError): load_config(tmp_path)


@pytest.mark.parametrize("contents", [
    "version: 1\nversion: 1\n",
    "version: 1\nrules:\n  ADK004: {enabled: false}\n  ADK004: {enabled: true}\n",
    "version: 1\nrules:\n  ADK004: {enabled: false, enabled: true}\n",
])
def test_duplicate_config_keys_fail_closed(tmp_path: Path, contents: str) -> None:
    (tmp_path / ".horustrace.yaml").write_text(contents)
    with pytest.raises(ConfigError, match="duplicate configuration key"):
        load_config(tmp_path)


def test_inventory_metadata_is_parsed_for_aibom(tmp_path: Path) -> None:
    (tmp_path / ".horustrace.yaml").write_text(
        """
version: 1
inventory:
  repository_id: github.com/acme/agents
  project: payments-ai
  owner: alice@example.com
  team: platform-security
  business_service: payments
  environment: production
  lifecycle: active
""",
        encoding="utf-8",
    )

    config = load_config(tmp_path)

    assert config.inventory.repository_id == "github.com/acme/agents"
    assert config.inventory.project == "payments-ai"
    assert config.inventory.owner == "alice@example.com"
    assert config.inventory.team == "platform-security"
    assert config.inventory.business_service == "payments"
    assert config.inventory.environment == "production"
    assert config.inventory.lifecycle == "active"


def test_invalid_inventory_metadata_fails_closed(tmp_path: Path) -> None:
    (tmp_path / ".horustrace.yaml").write_text(
        "version: 1\ninventory:\n  owner: ''\n",
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match="inventory.owner"):
        load_config(tmp_path)

