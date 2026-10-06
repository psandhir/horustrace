from pathlib import Path

import pytest

from horustrace.adapters.claude_agent_sdk_typescript import (
    _balanced,
    _exported_string_arrays,
    _has_property,
    _string_array,
    scan_claude_agent_sdk_typescript_file,
)
from horustrace.adapters.csharp_source import balanced_end, mask_non_code


@pytest.mark.parametrize(
    "noise",
    [
        "// operator's note contains } ] ) and \"quotes\"\n",
        "/* comment contains } ] ) ' apostrophe and \"quote\" */",
        "note: \"literal with } ] ) and escaped \\\" quote\",",
        "note: 'literal with } ] ) and escaped \\\' quote',",
        "note: __BT__template has } ] ) and \\__BT__ escaped tick__BT__,",
    ],
)
def test_typescript_balancing_ignores_non_code_delimiters(noise: str) -> None:
    noise = noise.replace("__BT__", chr(96))
    source = "{ before: { nested: [1, 2] }, " + noise + " after: true }TAIL"

    segment = _balanced(source, 0, "{", "}")

    assert segment is not None
    body, end = segment
    assert "after: true" in body
    assert source[end:] == "TAIL"


def test_typescript_property_detection_ignores_commented_controls() -> None:
    body = """
allowedTools: ["Bash"],
// canUseTool: fakeGuard,
/* hooks: { PreToolUse: [{ hooks: [fakeHook] }] } */
permissionMode: "default",
"""

    assert _has_property(body, "allowedTools")
    assert not _has_property(body, "canUseTool")
    assert not _has_property(body, "hooks")


def test_typescript_static_array_ignores_comments_and_quoted_comment_text() -> None:
    body = """
allowedTools: [
  "Read",
  // "Write" is intentionally excluded; don't treat this as a value.
  "Bash",
  /* "WebFetch" is documentation only. */
],
"""

    assert _string_array(body, "allowedTools") == ["Read", "Bash"]


def test_typescript_exported_arrays_ignore_commented_out_declarations() -> None:
    source = """
// export const FAKE = ["Write", "Bash"];
export const SAFE = [
  "Read",
  // "Write" is intentionally excluded.
  "Glob",
];
"""

    arrays = _exported_string_arrays(source)

    assert arrays == {"SAFE": ["Read", "Glob"]}


def test_claude_commented_control_properties_do_not_become_enforcement(
    tmp_path: Path,
) -> None:
    path = tmp_path / "agent.ts"
    path.write_text(
        """
import { query } from "@anthropic-ai/claude-agent-sdk";

const options = {
  allowedTools: ["Bash"],
  // canUseTool: fakeGuard,
  /* hooks: { PreToolUse: [{ hooks: [fakeHook] }] }, */
  permissionMode: "default",
};

async function run() {
  for await (const message of query({ prompt: "inspect", options })) {
    console.log(message);
  }
}
""",
        encoding="utf-8",
    )

    graph = scan_claude_agent_sdk_typescript_file(path)
    agent = next(item for item in graph.agents if item.name == "options")

    assert agent.metadata.get("tool_control_enforcing") is not True
    assert "tool_control_mechanism" not in agent.metadata


def test_csharp_balancing_ignores_comment_and_literal_delimiters() -> None:
    source = (
        "var options = new Options {\n"
        "  Name = \"literal } ] )\",\n"
        "  // operator's note has } ] )\n"
        "  Description = @\"verbatim }\",\n"
        "  /* block } ] ) */\n"
        "  Enabled = true,\n"
        "};\n"
    )
    masked = mask_non_code(source)
    start = masked.index("{")

    end = balanced_end(masked, start, "{", "}")

    assert end is not None
    assert source[end] == "}"
    assert source[end + 1 :].startswith(";")
