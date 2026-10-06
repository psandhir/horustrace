from __future__ import annotations

from pathlib import Path

SOURCE_CONTEXTS = (
    "runtime",
    "cli",
    "application-support",
    "test",
    "example",
    "tutorial",
    "notebook",
    "template-generated",
    "unknown",
)

NON_RUNTIME_SOURCE_CONTEXTS = frozenset(
    {
        "cli",
        "application-support",
        "test",
        "example",
        "tutorial",
        "notebook",
        "template-generated",
    }
)

_TEST_DIRS = {"test", "tests", "testing"}
_CONFORMANCE_MARKERS = {"conformance"}
_EXAMPLE_DIRS = {"example", "examples", "sample", "samples", "demo", "demos"}
_TUTORIAL_DIRS = {
    "tutorial",
    "tutorials",
    "training",
    "lab",
    "labs",
    "workshop",
    "workshops",
    "course",
    "courses",
}
_TEMPLATE_DIRS = {
    "template",
    "templates",
    "generated",
    "fixtures",
    "benchmark",
    "benchmarks",
}
_CLI_DIRS = {"cli", "command", "commands"}
_APPLICATION_SUPPORT_DIRS = {
    "ci",
    "cicd",
    "deploy",
    "deployment",
    "infra",
    "infrastructure",
    "migration",
    "migrations",
    "script",
    "scripts",
    "setup",
}

_TEST_FILENAMES = {
    "smoketest.py",
    "smoke_test.py",
    "integration_test.py",
}
_TEST_INFIXES = (
    ".test.",
    ".spec.",
)
_EXAMPLE_INFIXES = (".example.",)
_GENERATED_INFIXES = (".generated.",)


def path_parts_match(parts: set[str], markers: set[str]) -> bool:
    return any(
        part == marker
        or part.startswith((f"{marker}_", f"{marker}-"))
        or part.endswith((f"_{marker}", f"-{marker}"))
        for part in parts
        for marker in markers
    )


def _contextual_path(path: Path, root: Path | None) -> Path:
    if root is None:
        return path
    try:
        return path.resolve().relative_to(root.resolve())
    except ValueError:
        return path


def classify_source_context(path: Path | None, root: Path | None = None) -> str:
    """Classify a source path without reading or executing the target.

    When a root is provided, classification is based on the path relative to
    the scan root. This prevents unrelated parent-directory names from
    contaminating source context.
    """
    if path is None:
        return "unknown"

    contextual = _contextual_path(path, root)
    lowered_parts = {part.lower() for part in contextual.parts}
    name = contextual.name.lower()
    stem = contextual.stem.lower()
    marker_parts = {*lowered_parts, stem}

    if contextual.suffix.lower() == ".ipynb":
        return "notebook"

    if (
        path_parts_match(marker_parts, _TEST_DIRS)
        or path_parts_match(marker_parts, _CONFORMANCE_MARKERS)
        or name.startswith(("test_", "tests_", "test-", "tests-"))
        or name in _TEST_FILENAMES
        or any(marker in name for marker in _TEST_INFIXES)
    ):
        return "test"

    if (
        path_parts_match(marker_parts, _EXAMPLE_DIRS)
        or any(marker in name for marker in _EXAMPLE_INFIXES)
    ):
        return "example"

    if path_parts_match(marker_parts, _TUTORIAL_DIRS):
        return "tutorial"

    if (
        path_parts_match(marker_parts, _TEMPLATE_DIRS)
        or any(marker in name for marker in _GENERATED_INFIXES)
        or ".template." in name
        or name.endswith((".template", ".j2", ".jinja", ".jinja2"))
    ):
        return "template-generated"

    if (
        path_parts_match(marker_parts, _CLI_DIRS)
        or name == "__main__.py"
        or name == "cli.py"
        or name.endswith("_cli.py")
    ):
        return "cli"

    if path_parts_match(marker_parts, _APPLICATION_SUPPORT_DIRS):
        return "application-support"

    return "runtime"


def is_non_runtime_source_context(value: str | None) -> bool:
    return (value or "unknown") in NON_RUNTIME_SOURCE_CONTEXTS
