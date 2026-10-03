import ast
import re
from pathlib import Path

import pytest

from horustrace.models import Finding, Graph, Severity
from horustrace.provenance import attach_findings
from horustrace.rule_registry import RULE_REGISTRY, get_rule_metadata, iter_rule_metadata

ROOT = Path(__file__).resolve().parents[1]
DOCUMENTED_RULE_ID_LIST = re.findall(r"`([A-Z]+\d+)`", (ROOT / "docs/rules.md").read_text())
DOCUMENTED_RULE_IDS = set(DOCUMENTED_RULE_ID_LIST)


def _emitted_rule_ids(path: Path, constructor: str, keyword: str) -> set[str]:
    identifiers: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
            continue
        if node.func.id != constructor:
            continue
        for item in node.keywords:
            if item.arg == keyword and isinstance(item.value, ast.Constant):
                identifiers.add(str(item.value.value))
        if keyword == "rule_id" and node.args and isinstance(node.args[0], ast.Constant):
            identifiers.add(str(node.args[0].value))
    return identifiers


def _emitted_default_severities(
    path: Path, constructor: str, id_keyword: str
) -> dict[str, Severity]:
    defaults: dict[str, Severity] = {}
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
            continue
        if node.func.id != constructor:
            continue
        values = {item.arg: item.value for item in node.keywords if item.arg}
        rule_node = values.get(id_keyword)
        severity_node = values.get("severity")
        if rule_node is None and node.args:
            rule_node = node.args[0]
        if severity_node is None and len(node.args) > 1:
            severity_node = node.args[1]
        if not isinstance(rule_node, ast.Constant) or not isinstance(severity_node, ast.Attribute):
            continue
        if isinstance(severity_node.value, ast.Name) and severity_node.value.id == "Severity":
            defaults[str(rule_node.value)] = Severity[severity_node.attr]
    return defaults


def test_registry_contains_all_documented_rules() -> None:
    assert set(RULE_REGISTRY) == DOCUMENTED_RULE_IDS
    assert len(DOCUMENTED_RULE_ID_LIST) == len(DOCUMENTED_RULE_IDS)


def test_registry_rule_ids_are_unique() -> None:
    metadata = iter_rule_metadata()
    assert len(RULE_REGISTRY) == len({rule.rule_id for rule in metadata})


def test_registry_layers_are_1_to_5() -> None:
    assert {rule.layer for rule in RULE_REGISTRY.values()} == {1, 2, 3, 4, 5}
    assert all(1 <= rule.layer <= 5 for rule in RULE_REGISTRY.values())


def test_registry_order_is_deterministic() -> None:
    metadata = iter_rule_metadata()
    assert metadata == tuple(sorted(metadata, key=lambda rule: (rule.layer, rule.rule_id)))
    assert iter_rule_metadata() == metadata


def test_builtin_findings_reference_registered_rule_ids() -> None:
    emitted = _emitted_rule_ids(ROOT / "src/horustrace/rules/builtin.py", "Finding", "rule_id")
    emitted.update(_emitted_rule_ids(ROOT / "src/horustrace/analysis.py", "AttackPath", "path_id"))
    assert emitted <= set(RULE_REGISTRY)


def test_registry_default_severities_match_emitted_rules() -> None:
    defaults = _emitted_default_severities(
        ROOT / "src/horustrace/rules/builtin.py", "Finding", "rule_id"
    )
    defaults.update(
        _emitted_default_severities(
            ROOT / "src/horustrace/analysis.py", "AttackPath", "path_id"
        )
    )
    assert {rule_id: RULE_REGISTRY[rule_id].default_severity for rule_id in defaults} == defaults


def test_unknown_rule_metadata_raises_key_error() -> None:
    with pytest.raises(KeyError):
        get_rule_metadata("UNKNOWN999")


def test_policy_violation_annotation_follows_registry_metadata() -> None:
    policy_rules = [
        rule for rule in RULE_REGISTRY.values()
        if rule.assessment == "policy_violation"
    ]
    findings = [
        Finding(
            rule_id=rule.rule_id,
            severity=rule.default_severity,
            title=rule.title,
            message="test",
            recommendation="test",
            layer=rule.layer,
        )
        for rule in policy_rules
    ]

    attach_findings(Graph(), findings)

    assert {finding.rule_id for finding in findings if finding.assessment == "policy_violation"} == {
        rule.rule_id for rule in policy_rules
    }
