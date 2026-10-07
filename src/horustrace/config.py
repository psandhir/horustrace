"""Repository scanner configuration, separate from security intent manifests."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from horustrace.models import Finding, Severity
from horustrace.rule_registry import RULE_REGISTRY

CONFIG_FILENAME = ".horustrace.yaml"


class ConfigError(ValueError):
    """Repository scanner configuration is invalid."""


class _UniqueLoader(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        mapping = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in mapping:
                raise ConfigError(f"duplicate configuration key '{key}' at line {key_node.start_mark.line + 1}")
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


@dataclass(frozen=True)
class RuleOverride:
    enabled: bool = True
    severity: Severity | None = None


@dataclass(frozen=True)
class InventoryConfig:
    repository_id: str | None = None
    project: str | None = None
    owner: str | None = None
    team: str | None = None
    business_service: str | None = None
    environment: str | None = None
    lifecycle: str | None = None


@dataclass(frozen=True)
class ScanConfig:
    strict: bool = False
    rules: dict[str, RuleOverride] = field(default_factory=dict)
    source_path: Path | None = None
    inventory: InventoryConfig = field(default_factory=InventoryConfig)


def load_config(root: Path, explicit: Path | None = None) -> ScanConfig:
    if explicit is not None:
        path = explicit
    else:
        path = root / CONFIG_FILENAME
    if not path.exists():
        if explicit:
            raise ConfigError(f"{path}: configuration file does not exist")
        return ScanConfig()
    try:
        raw = yaml.load(path.read_text(encoding="utf-8"), Loader=_UniqueLoader)
    except ConfigError as exc:
        raise ConfigError(f"{path}: {exc}") from exc
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ConfigError(f"{path}: cannot read configuration") from exc
    if not isinstance(raw, dict) or set(raw) - {"version", "rules", "scanner", "inventory"} or type(raw.get("version")) is not int or raw["version"] != 1:
        raise ConfigError(f"{path}: invalid configuration schema")
    scanner = raw.get("scanner", {})
    if not isinstance(scanner, dict) or set(scanner) - {"strict"} or type(scanner.get("strict", False)) is not bool:
        raise ConfigError(f"{path}: invalid scanner configuration")
    inventory_raw = raw.get("inventory", {})
    inventory_fields = {
        "repository_id",
        "project",
        "owner",
        "team",
        "business_service",
        "environment",
        "lifecycle",
    }
    if not isinstance(inventory_raw, dict) or set(inventory_raw) - inventory_fields:
        raise ConfigError(f"{path}: invalid inventory configuration")
    for key, value in inventory_raw.items():
        if not isinstance(value, str) or not value.strip():
            raise ConfigError(f"{path}: inventory.{key} must be a non-empty string")
    inventory = InventoryConfig(
        repository_id=inventory_raw.get("repository_id"),
        project=inventory_raw.get("project"),
        owner=inventory_raw.get("owner"),
        team=inventory_raw.get("team"),
        business_service=inventory_raw.get("business_service"),
        environment=inventory_raw.get("environment"),
        lifecycle=inventory_raw.get("lifecycle"),
    )

    rules = raw.get("rules", {})
    if not isinstance(rules, dict):
        raise ConfigError(f"{path}: rules must be a mapping")
    parsed = {}
    for rule_id, item in rules.items():
        if rule_id not in RULE_REGISTRY or not isinstance(item, dict) or set(item) - {"enabled", "severity"}:
            raise ConfigError(f"{path}: invalid rule configuration for {rule_id}")
        if "enabled" in item and type(item["enabled"]) is not bool:
            raise ConfigError(f"{path}: enabled must be boolean for {rule_id}")
        try:
            severity = Severity.parse(item["severity"]) if "severity" in item else None
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"{path}: invalid severity for {rule_id}") from exc
        parsed[rule_id] = RuleOverride(item.get("enabled", True), severity)
    return ScanConfig(scanner.get("strict", False), parsed, path, inventory)


def apply(config: ScanConfig, findings: list[Finding]) -> tuple[list[Finding], list[str]]:
    active, disabled = [], []
    for finding in findings:
        override = config.rules.get(finding.rule_id)
        if override and not override.enabled:
            disabled.append(finding.rule_id)
            continue
        if override and override.severity is not None:
            finding.severity = override.severity
        active.append(finding)
    return active, sorted(set(disabled))
