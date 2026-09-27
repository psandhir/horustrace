"""Version 1 manifest schema, including the documented legacy field aliases."""
from __future__ import annotations

# Shapes are types, tuples of types, nested mappings, or single-item list schemas.
STRINGS = (str, list)
IDENTITY = dict.fromkeys(
    ('name', 'service_account', 'principal', 'provider', 'resource_scope', 'credential_source'), str
) | dict.fromkeys(('roles', 'permissions', 'oauth_scopes', 'scopes'), STRINGS)
RESOURCE = dict.fromkeys(('kind', 'selector', 'path', 'resource', 'classification'), str) | {'access': STRINGS}
DATA = dict.fromkeys(('name', 'source', 'classification', 'capability', 'selector', 'path', 'resource'), str)
INPUT = dict.fromkeys(('name', 'source', 'trust', 'kind'), str)
NETWORK = dict.fromkeys(('target', 'destination', 'host', 'direction'), str) | {'restricted': bool}
AUTHORITY_SCOPE = dict.fromkeys(
    (
        'capabilities',
        'identities',
        'resources',
        'destinations',
        'iam_roles',
        'permissions',
        'oauth_scopes',
        'mcp_servers',
    ),
    STRINGS,
)
MCP_TOOL_CONTRACT = {'server': str, 'allow': STRINGS, 'deny': STRINGS}
AUTHORITY_CONTRACT = {
    'allow': AUTHORITY_SCOPE,
    'deny': AUTHORITY_SCOPE,
    'require_approval_for': STRINGS,
    'mcp_tools': [MCP_TOOL_CONTRACT],
}
POLICY = dict.fromkeys(
    ('required', 'required_capabilities', 'deny', 'denied_capabilities', 'allowed_resources',
     'resources', 'allowed_destinations', 'destinations', 'require_approval_for'), STRINGS
) | {'max_privileged_capabilities': int, 'authority': AUTHORITY_CONTRACT}
TOOL = dict.fromkeys(('name', 'kind', 'identity'), str) | dict.fromkeys(
    ('capabilities', 'capability', 'destinations', 'destination'), STRINGS
) | dict.fromkeys(('approval', 'human_approval', 'guardrails'), bool) | {'resources': [(str, RESOURCE)]}
DEPLOYMENT = {'workload_id': str, 'name': str}
MCP = dict.fromkeys(('name', 'transport', 'url', 'command', 'identity'), str) | dict.fromkeys(
    ('authenticated', 'approval', 'guardrails'), bool
) | {'args': [str], 'allowed_tools': STRINGS, 'denied_tools': STRINGS}
AGENT = {'name': str, 'data': [(str, DATA)], 'inputs': [(str, INPUT)],
         'identities': [(str, IDENTITY)], 'network': [(str, NETWORK)], 'tools': [TOOL],
         'mcp_servers': [MCP], 'policy': POLICY, 'permissions': POLICY,
         'deployment': DEPLOYMENT}
SCHEMA = {'version': int, 'agents': [AGENT], 'agent': AGENT, 'identities': [IDENTITY]}


def validate(raw, fail, field='document', shape=SCHEMA):
    if isinstance(shape, dict):
        if not isinstance(raw, dict):
            fail(field, 'must be a mapping')
        for key, value in raw.items():
            child = str(key) if field == 'document' else f'{field}.{key}'
            if key not in shape:
                fail(child, 'is an unknown field')
            validate(value, fail, child, shape[key])
    elif isinstance(shape, list):
        if not isinstance(raw, list):
            fail(field, 'must be a list')
        for index, value in enumerate(raw):
            validate(value, fail, f'{field}[{index}]', shape[0])
    elif isinstance(shape, tuple) and any(isinstance(s, dict) for s in shape):
        if isinstance(raw, str):
            return
        validate(raw, fail, field, next(s for s in shape if isinstance(s, dict)))
    elif shape == STRINGS:
        if not isinstance(raw, str) and not (
            isinstance(raw, list) and all(isinstance(v, str) for v in raw)
        ):
            fail(field, 'must be a string or list of strings')
    elif type(raw) is not shape:
        fail(field, f'must be {shape.__name__}')
    if field.endswith('.trust') and raw not in {'trusted', 'untrusted'}:
        fail(field, 'must be trusted or untrusted')
    if field.endswith('.direction') and raw not in {'inbound', 'outbound'}:
        fail(field, 'must be inbound or outbound')
    if field == 'version' and raw != 1:
        fail(field, 'must be supported schema version 1')
    if field.endswith('max_privileged_capabilities') and raw < 0:
        fail(field, 'must be nonnegative')
    if isinstance(raw, dict) and 'agent' in raw and 'agents' in raw:
        fail(field, 'cannot contain both agent and agents')
