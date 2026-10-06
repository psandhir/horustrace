from __future__ import annotations

import fnmatch
import re
from urllib.parse import urlparse

CAPABILITY_PATTERNS: list[tuple[re.Pattern[str], set[str]]] = [
    (re.compile(r"\b(shell|exec|execute|command|terminal|bash|powershell)\b", re.IGNORECASE), {"process.execute"}),
    (re.compile(r"\b(delete|remove|destroy|purge|drop|terminate|clear|unsubscribe|revoke|erase)\b", re.IGNORECASE), {"destructive.write"}),
    (re.compile(r"\b(send|email|post|publish|upload|notify|notification|message|push)\b", re.IGNORECASE), {"external.write", "network.external"}),
    (re.compile(r"\b(http|https|web|request|fetch|browser|url|api)\b", re.IGNORECASE), {"network.external"}),
    (re.compile(r"\b(write|update|create|modify|edit|patch|apply|schedule|subscribe|enqueue|add|append|insert|save|store|upsert)\b", re.IGNORECASE), {"data.write"}),
    (re.compile(r"\b(read|search|lookup|get|retrieve|document|file|query|list|open|load|view|inspect)\b", re.IGNORECASE), {"data.read"}),
    (re.compile(r"\b(secret|credential|token|password|key|vault)\b", re.IGNORECASE), {"secrets.read"}),
    (re.compile(r"\b(admin|iam|permission|role|grant)\b", re.IGNORECASE), {"identity.admin"}),
]


NAME_HINT_REQUIRES_BODY_CAPABILITIES = {
    "data.write",
    "destructive.write",
    "external.write",
    "identity.admin",
    "network.external",
    "process.execute",
    "secrets.read",
}


def corroborate_name_inferred_authority(
    name_capabilities: set[str],
    body_capabilities: set[str],
) -> tuple[set[str], set[str]]:
    """Filter ambiguous name-only effects unless the function body corroborates them.

    This is intentionally a filter, not a body-to-authority promotion step.
    Concrete sink inference remains adapter-owned. Privileged authority inferred
    only from names requires source-visible body support; names may aid discovery
    but cannot manufacture execution, mutation, egress, secret, or admin effects.
    """
    unsupported = (
        name_capabilities
        & NAME_HINT_REQUIRES_BODY_CAPABILITIES
        - body_capabilities
    )
    return name_capabilities - unsupported, unsupported


PRIVILEGED_CAPABILITIES = {
    "process.execute",
    "destructive.write",
    "external.write",
    "data.write",
    "secrets.read",
    "identity.admin",
}

HIGH_RISK_CAPABILITIES = {
    "process.execute",
    "destructive.write",
    "secrets.read",
    "identity.admin",
}

SENSITIVE_CLASSES = {"confidential", "restricted", "secret", "highly-confidential", "regulated"}
UNTRUSTED_INPUT_KINDS = {"web", "browser", "email", "document", "retrieval", "external", "webhook"}


ADMIN_ROLE_PATTERNS = (
    "owner",
    "admin",
    "administrator",
    "editor",
    "contributor",
    "*",
    "fullaccess",
    "poweruser",
)

BROAD_OAUTH_SCOPES = {
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/drive",
    "https://graph.microsoft.com/.default",
    "offline_access",
    "*",
}


def infer_capabilities(name: str) -> set[str]:
    capabilities: set[str] = set()
    normalized = re.sub(r"[_\-.]+", " ", name)
    for pattern, values in CAPABILITY_PATTERNS:
        if pattern.search(normalized):
            capabilities.update(values)
    return capabilities


def package_is_unpinned(command: str | None, args: list[str]) -> bool:
    if not command or command.lower() not in {"npx", "bunx", "pnpx"}:
        return False
    package = next((arg for arg in args if not arg.startswith("-")), None)
    if not package:
        return False
    if package.endswith("@latest"):
        return True
    if package.startswith("@"):
        return package.count("@") < 2
    return "@" not in package


def role_looks_admin(role: str) -> bool:
    value = role.lower().replace("_", "").replace("-", "")
    return any(pattern.replace("_", "").replace("-", "") in value for pattern in ADMIN_ROLE_PATTERNS)


def permission_looks_wildcard(permission: str) -> bool:
    return permission.strip() in {"*", "*:*"} or permission.endswith(".*") or ":*" in permission


def destination_is_broad(target: str) -> bool:
    normalized = target.strip().lower()
    if normalized in {"*", "0.0.0.0/0", "::/0", "any", "internet", "all"}:
        return True
    if normalized.startswith("*. "):
        return True
    return normalized.startswith("*.")


def resource_is_broad(selector: str) -> bool:
    normalized = selector.strip()
    return normalized in {"*", "/", "~", ".", "..", "${HOME}", "/**", "**", "/*"}


def matches_any(value: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(value, pattern) for pattern in patterns)


def host_from_target(target: str) -> str:
    parsed = urlparse(target)
    return parsed.hostname or target
