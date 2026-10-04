from __future__ import annotations

import re
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from horustrace.models import Graph, Identity, ResourceScope, Tool


_TF_BLOCK_RE = re.compile(
    r'^\s*(resource|data)\s+"([^"]+)"\s+"([^"]+)"\s*\{',
)
_TF_ASSIGNMENT_RE = re.compile(r'^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*$', re.MULTILINE)
_STRING_RE = re.compile(r'"([^"\\]*(?:\\.[^"\\]*)*)"')
_TF_REF_RE = re.compile(r'\b(?:aws_iam_role|aws_iam_policy)\.[A-Za-z_][A-Za-z0-9_]*')


@dataclass(slots=True)
class _Authority:
    permissions: set[str] = field(default_factory=set)
    resources: set[str] = field(default_factory=set)
    sources: set[str] = field(default_factory=set)

    def merge(self, other: _Authority) -> None:
        self.permissions.update(other.permissions)
        self.resources.update(other.resources)
        self.sources.update(other.sources)


@dataclass(slots=True)
class _TerraformBlock:
    kind: str
    block_type: str
    name: str
    text: str
    path: Path

    @property
    def ref(self) -> str:
        return f"{self.block_type}.{self.name}"


def _terraform_blocks(path: Path, text: str) -> list[_TerraformBlock]:
    lines = text.splitlines()
    result: list[_TerraformBlock] = []
    index = 0
    while index < len(lines):
        match = _TF_BLOCK_RE.match(lines[index])
        if not match:
            index += 1
            continue
        kind, block_type, name = match.groups()
        start = index
        depth = lines[index].count("{") - lines[index].count("}")
        index += 1
        while index < len(lines) and depth > 0:
            depth += lines[index].count("{") - lines[index].count("}")
            index += 1
        result.append(
            _TerraformBlock(
                kind=kind,
                block_type=block_type,
                name=name,
                text="\n".join(lines[start:index]),
                path=path,
            )
        )
    return result


def _tf_assignment(block: str, name: str) -> str | None:
    for match in _TF_ASSIGNMENT_RE.finditer(block):
        if match.group(1) == name:
            return match.group(2).strip().rstrip(",")
    return None


def _unquote(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip().rstrip(",")
    if len(value) >= 2 and value[0] == value[-1] == '"':
        return value[1:-1]
    return value or None


def _quoted_values(text: str) -> set[str]:
    return {bytes(value, "utf-8").decode("unicode_escape") for value in _STRING_RE.findall(text)}


def _tf_policy_authority(text: str, *, source: str) -> _Authority:
    authority = _Authority(sources={source})
    # Covers both aws_iam_policy_document HCL (actions, resources) and
    # jsonencode-style IAM documents (Action, Resource).
    for key in ("actions", "Action"):
        pattern = re.compile(
            rf'\b{key}\s*=\s*(\[[^\]]*\]|"[^"]+")',
            re.DOTALL,
        )
        for match in pattern.finditer(text):
            authority.permissions.update(_quoted_values(match.group(1)))
    for key in ("resources", "Resource"):
        pattern = re.compile(
            rf'\b{key}\s*=\s*(\[[^\]]*\]|"[^"]+")',
            re.DOTALL,
        )
        for match in pattern.finditer(text):
            authority.resources.update(_quoted_values(match.group(1)))
    # Also accept JSON-string policy documents, including heredocs.
    for match in re.finditer(
        r'"Action"\s*:\s*(\[[^\]]*\]|"[^"]+")',
        text,
        re.DOTALL,
    ):
        authority.permissions.update(_quoted_values(match.group(1)))
    for match in re.finditer(
        r'"Resource"\s*:\s*(\[[^\]]*\]|"[^"]+")',
        text,
        re.DOTALL,
    ):
        authority.resources.update(_quoted_values(match.group(1)))
    return authority


def _normalize_tf_ref(value: str | None) -> str | None:
    if not value:
        return None
    value = _unquote(value) or ""
    match = re.search(r'\b(aws_iam_role\.[A-Za-z_][A-Za-z0-9_]*)', value)
    if match:
        return match.group(1)
    return value or None


def _terraform_authority(paths: list[Path]) -> tuple[dict[str, _Authority], dict[str, set[str]]]:
    blocks: list[_TerraformBlock] = []
    for path in paths:
        try:
            blocks.extend(_terraform_blocks(path, path.read_text(encoding="utf-8")))
        except (OSError, UnicodeDecodeError):
            continue

    policy_documents: dict[str, _Authority] = {}
    managed_policies: dict[str, _Authority] = {}
    role_aliases: dict[str, set[str]] = {}

    for block in blocks:
        if block.kind == "data" and block.block_type == "aws_iam_policy_document":
            policy_documents[f"data.{block.ref}"] = _tf_policy_authority(
                block.text,
                source=f"{block.path}:{block.ref}",
            )
            continue
        if block.kind != "resource":
            continue
        if block.block_type == "aws_iam_role":
            canonical = block.ref
            aliases = {
                canonical,
                f"{canonical}.arn",
                f"{canonical}.id",
                f"{canonical}.name",
            }
            role_name = _unquote(_tf_assignment(block.text, "name"))
            if role_name:
                aliases.add(role_name)
            role_aliases[canonical] = aliases
            continue
        if block.block_type == "aws_iam_policy":
            policy = _tf_assignment(block.text, "policy")
            authority = _tf_policy_authority(
                block.text,
                source=f"{block.path}:{block.ref}",
            )
            if policy:
                doc_match = re.search(
                    r'\b(data\.aws_iam_policy_document\.[A-Za-z_][A-Za-z0-9_]*)\.json\b',
                    policy,
                )
                if doc_match and doc_match.group(1) in policy_documents:
                    authority.merge(policy_documents[doc_match.group(1)])
            managed_policies[block.ref] = authority

    by_role: dict[str, _Authority] = {
        canonical: _Authority() for canonical in role_aliases
    }
    for block in blocks:
        if block.kind != "resource":
            continue
        if block.block_type == "aws_iam_role_policy":
            role_ref = _normalize_tf_ref(_tf_assignment(block.text, "role"))
            if role_ref not in by_role:
                continue
            authority = _tf_policy_authority(
                block.text,
                source=f"{block.path}:{block.ref}",
            )
            policy = _tf_assignment(block.text, "policy")
            if policy:
                doc_match = re.search(
                    r'\b(data\.aws_iam_policy_document\.[A-Za-z_][A-Za-z0-9_]*)\.json\b',
                    policy,
                )
                if doc_match and doc_match.group(1) in policy_documents:
                    authority.merge(policy_documents[doc_match.group(1)])
            by_role[role_ref].merge(authority)
        elif block.block_type == "aws_iam_role_policy_attachment":
            role_ref = _normalize_tf_ref(_tf_assignment(block.text, "role"))
            policy_expr = _tf_assignment(block.text, "policy_arn") or ""
            policy_match = re.search(
                r'\b(aws_iam_policy\.[A-Za-z_][A-Za-z0-9_]*)\.arn\b',
                policy_expr,
            )
            if role_ref in by_role and policy_match:
                authority = managed_policies.get(policy_match.group(1))
                if authority:
                    by_role[role_ref].merge(authority)
        elif block.block_type == "aws_iam_role":
            canonical = block.ref
            if canonical in by_role and "inline_policy" in block.text:
                by_role[canonical].merge(
                    _tf_policy_authority(
                        block.text,
                        source=f"{block.path}:{block.ref}:inline_policy",
                    )
                )

    return by_role, role_aliases


def _cfn_value(value: Any) -> str | None:
    if isinstance(value, str):
        return value
    if not isinstance(value, dict):
        return None
    if "Ref" in value:
        return f"Ref:{value['Ref']}"
    get_att = value.get("Fn::GetAtt")
    if isinstance(get_att, list) and len(get_att) >= 2:
        return f"GetAtt:{get_att[0]}.{get_att[1]}"
    if isinstance(get_att, str):
        return f"GetAtt:{get_att}"
    return None


def _string_values(value: Any) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, list):
        return {item for item in value if isinstance(item, str)}
    return set()


def _cfn_policy_authority(document: Any, *, source: str) -> _Authority:
    authority = _Authority(sources={source})
    if not isinstance(document, dict):
        return authority
    statements = document.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return authority
    for statement in statements:
        if not isinstance(statement, dict):
            continue
        effect = str(statement.get("Effect") or "Allow").lower()
        if effect != "allow":
            continue
        authority.permissions.update(_string_values(statement.get("Action")))
        authority.resources.update(_string_values(statement.get("Resource")))
    return authority


def _cloudformation_authority(
    paths: list[Path],
) -> tuple[dict[str, _Authority], dict[str, set[str]]]:
    by_role: dict[str, _Authority] = {}
    role_aliases: dict[str, set[str]] = {}
    pending_policies: list[tuple[dict[str, Any], Path, str]] = []

    for path in paths:
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, yaml.YAMLError):
            continue
        if not isinstance(raw, dict) or not isinstance(raw.get("Resources"), dict):
            continue
        for logical_id, resource in raw["Resources"].items():
            if not isinstance(resource, dict):
                continue
            resource_type = resource.get("Type")
            props = (
                resource.get("Properties")
                if isinstance(resource.get("Properties"), dict)
                else {}
            )
            if resource_type == "AWS::IAM::Role":
                canonical = str(logical_id)
                role_aliases[canonical] = {
                    canonical,
                    f"Ref:{canonical}",
                    f"GetAtt:{canonical}.Arn",
                    f"GetAtt:{canonical}.RoleName",
                }
                role_name = props.get("RoleName")
                if isinstance(role_name, str):
                    role_aliases[canonical].add(role_name)
                authority = by_role.setdefault(canonical, _Authority())
                policies = props.get("Policies")
                if isinstance(policies, list):
                    for index, policy in enumerate(policies):
                        if not isinstance(policy, dict):
                            continue
                        authority.merge(
                            _cfn_policy_authority(
                                policy.get("PolicyDocument"),
                                source=f"{path}:{logical_id}:Policies[{index}]",
                            )
                        )
            elif resource_type == "AWS::IAM::Policy":
                pending_policies.append((props, path, str(logical_id)))

    alias_to_role = {
        alias: role
        for role, aliases in role_aliases.items()
        for alias in aliases
    }
    for props, path, logical_id in pending_policies:
        authority = _cfn_policy_authority(
            props.get("PolicyDocument"),
            source=f"{path}:{logical_id}",
        )
        roles = props.get("Roles")
        if not isinstance(roles, list):
            continue
        for raw_role in roles:
            role_value = _cfn_value(raw_role)
            if role_value is None:
                continue
            canonical = alias_to_role.get(role_value)
            if canonical:
                by_role.setdefault(canonical, _Authority()).merge(authority)
    return by_role, role_aliases


def _role_name_from_arn(value: str) -> str | None:
    marker = ":role/"
    if marker not in value:
        return None
    return value.split(marker, 1)[1].split("/")[-1]


def _identity_aliases(identity: Identity) -> set[str]:
    aliases = {identity.name} | set(identity.roles)
    expanded = set(aliases)
    for alias in aliases:
        role_name = _role_name_from_arn(alias)
        if role_name:
            expanded.add(role_name)
        tf_match = re.search(r'\b(aws_iam_role\.[A-Za-z_][A-Za-z0-9_]*)', alias)
        if tf_match:
            canonical = tf_match.group(1)
            expanded.update(
                {
                    canonical,
                    f"{canonical}.arn",
                    f"{canonical}.id",
                    f"{canonical}.name",
                }
            )
        if alias.startswith("GetAtt:"):
            expanded.add(alias.removeprefix("GetAtt:").split(".", 1)[0])
        if alias.startswith("Ref:"):
            expanded.add(alias.removeprefix("Ref:"))
    return expanded


def _merge_authority_into_identity(identity: Identity, authority: _Authority) -> None:
    if not authority.permissions and not authority.resources:
        return
    identity.permissions.update(authority.permissions)
    if authority.resources == {"*"}:
        identity.resource_scope = "*"
    elif len(authority.resources) == 1:
        identity.resource_scope = next(iter(authority.resources))
    if authority.resources:
        identity.metadata["iam_resource_scopes"] = sorted(authority.resources)
    identity.metadata["iam_authority_sources"] = sorted(authority.sources)
    identity.metadata["iam_authority_resolved"] = True
    identity.metadata["iam_unrestricted_resource"] = "*" in authority.resources


def _apply_role_authority(
    graph: Graph,
    authorities: dict[str, _Authority],
    aliases_by_role: dict[str, set[str]],
) -> None:
    alias_to_role = {
        alias: role
        for role, aliases in aliases_by_role.items()
        for alias in aliases
    }
    for identity in graph.all_identities():
        if identity.provider != "aws":
            continue
        matched_roles = {
            alias_to_role[alias]
            for alias in _identity_aliases(identity)
            if alias in alias_to_role
        }
        combined = _Authority()
        for role in matched_roles:
            authority = authorities.get(role)
            if authority:
                combined.merge(authority)
        _merge_authority_into_identity(identity, combined)


def _normalize_bedrock_agent_ref(value: str | None) -> str | None:
    if not value:
        return None
    match = re.search(
        r'\b(aws_bedrockagent_agent\.[A-Za-z_][A-Za-z0-9_]*)',
        value,
    )
    return match.group(1) if match else value


def _link_terraform_action_groups(graph: Graph) -> None:
    agents_by_ref = {
        str(agent.metadata["terraform_resource_ref"]): agent
        for agent in graph.agents
        if agent.metadata.get("terraform_resource_ref")
    }
    if not agents_by_ref:
        return
    retained: list[Tool] = []
    for tool in graph.unbound_tools:
        if tool.kind != "bedrock_action_group":
            retained.append(tool)
            continue
        agent_ref = _normalize_bedrock_agent_ref(
            str(tool.metadata.get("agent_reference") or "")
        )
        agent = agents_by_ref.get(agent_ref or "")
        if agent is None:
            retained.append(tool)
            continue
        bound = deepcopy(tool)
        bound.metadata["authority_binding"] = "bedrock_agent_action_group"
        bound.metadata["authority_binding_basis"] = "terraform_agent_id_reference"
        agent.tools.append(bound)
    graph.unbound_tools = retained


def enrich_amazon_repository_authority(
    graph: Graph,
    root: Path,
    candidates: list[Path],
) -> None:
    """Correlate Amazon agents with source-visible IAM and Bedrock IaC authority."""
    del root  # reserved for future repository-relative evidence normalization
    terraform_paths = [path for path in candidates if path.suffix.lower() == ".tf"]
    yaml_paths = [
        path
        for path in candidates
        if path.suffix.lower() in {".yaml", ".yml"}
    ]

    tf_authorities, tf_aliases = _terraform_authority(terraform_paths)
    cfn_authorities, cfn_aliases = _cloudformation_authority(yaml_paths)
    _apply_role_authority(graph, tf_authorities, tf_aliases)
    _apply_role_authority(graph, cfn_authorities, cfn_aliases)
    _link_terraform_action_groups(graph)
