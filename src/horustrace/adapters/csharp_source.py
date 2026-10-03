"""Small source-only helpers for conservative C# adapter parsing.

This is not a general C# parser. It preserves source offsets while masking
comments/strings and provides balanced-delimiter extraction for framework
adapters that only need source-proven constructor/argument relationships.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from horustrace.models import SourceLocation


@dataclass(slots=True)
class CSharpAssignment:
    name: str
    expression: str
    offset: int


_ASSIGNMENT_RE = re.compile(
    r"""
    (?<![\w.])
    (?:
        var
        | [A-Za-z_][\w.]*
          (?:\s*<[^;={}\n]+>)?
          (?:\s*\[\])?
          \??
    )
    \s+
    (?P<name>[A-Za-z_]\w*)
    \s*=
    """,
    re.VERBOSE,
)


def location(path: Path, source: str, offset: int) -> SourceLocation:
    offset = max(0, min(offset, len(source)))
    line = source.count("\n", 0, offset) + 1
    last_newline = source.rfind("\n", 0, offset)
    column = offset + 1 if last_newline < 0 else offset - last_newline
    return SourceLocation(path=path, line=line, column=column)


def mask_non_code(source: str) -> str:
    """Mask comments and literals while preserving offsets and newlines."""
    result = list(source)
    n = len(source)
    i = 0

    def blank(start: int, end: int) -> None:
        for j in range(start, min(end, n)):
            if result[j] != "\n":
                result[j] = " "

    while i < n:
        if source.startswith("//", i):
            end = source.find("\n", i + 2)
            end = n if end < 0 else end
            blank(i, end)
            i = end
            continue
        if source.startswith("/*", i):
            end = source.find("*/", i + 2)
            end = n if end < 0 else end + 2
            blank(i, end)
            i = end
            continue

        if source[i] == '"':
            q = i
            while q < n and source[q] == '"':
                q += 1
            count = q - i
            if count >= 3:
                marker = '"' * count
                end = source.find(marker, q)
                end = n if end < 0 else end + count
                blank(i, end)
                i = end
                continue

        if (
            source.startswith('@"', i)
            or source.startswith('$@"', i)
            or source.startswith('@$"', i)
        ):
            quote = source.find('"', i)
            j = quote + 1
            while j < n:
                if source[j] == '"':
                    if j + 1 < n and source[j + 1] == '"':
                        j += 2
                        continue
                    j += 1
                    break
                j += 1
            blank(i, j)
            i = j
            continue

        if source[i] == '"' or (
            source[i] == "$" and i + 1 < n and source[i + 1] == '"'
        ):
            start = i
            j = i + 1 if source[i] == '"' else i + 2
            escaped = False
            while j < n:
                ch = source[j]
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == '"':
                    j += 1
                    break
                j += 1
            blank(start, j)
            i = j
            continue

        if source[i] == "'":
            j = i + 1
            escaped = False
            while j < n:
                ch = source[j]
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == "'":
                    j += 1
                    break
                j += 1
            blank(i, j)
            i = j
            continue
        i += 1

    return "".join(result)


def balanced_end(
    masked: str,
    start: int,
    opener: str,
    closer: str,
) -> int | None:
    if start >= len(masked) or masked[start] != opener:
        return None
    depth = 0
    for i in range(start, len(masked)):
        ch = masked[i]
        if ch == opener:
            depth += 1
        elif ch == closer:
            depth -= 1
            if depth == 0:
                return i
    return None


def statement_end(masked: str, start: int) -> int:
    paren = bracket = brace = 0
    for i in range(start, len(masked)):
        ch = masked[i]
        if ch == "(":
            paren += 1
        elif ch == ")":
            paren = max(0, paren - 1)
        elif ch == "[":
            bracket += 1
        elif ch == "]":
            bracket = max(0, bracket - 1)
        elif ch == "{":
            brace += 1
        elif ch == "}":
            brace = max(0, brace - 1)
        elif ch == ";" and paren == bracket == brace == 0:
            return i
    return len(masked)


def assignments(source: str, masked: str) -> dict[str, CSharpAssignment]:
    result: dict[str, CSharpAssignment] = {}
    for match in _ASSIGNMENT_RE.finditer(masked):
        start = match.end()
        end = statement_end(masked, start)
        expression = source[start:end].strip()
        if expression:
            result[match.group("name")] = CSharpAssignment(
                match.group("name"),
                expression,
                start,
            )
    return result


def named_string(expression: str, name: str) -> str | None:
    for pattern in (
        rf'\b{re.escape(name)}\s*:\s*@?"([^"]*)"',
        rf'\b{re.escape(name)}\s*=\s*@?"([^"]*)"',
    ):
        match = re.search(pattern, expression, re.IGNORECASE)
        if match:
            return match.group(1)
    return None


def collection_strings(expression: str, name: str) -> list[str]:
    match = re.search(
        rf"\b{re.escape(name)}\s*=\s*\[(?P<body>.*?)\]",
        expression,
        re.IGNORECASE | re.DOTALL,
    )
    return (
        re.findall(r'@?"([^"]+)"', match.group("body"))
        if match
        else []
    )


def argument_value(expression: str, name: str) -> str | None:
    """Extract one named argument/object-property value."""
    masked = mask_non_code(expression)
    patterns = (
        re.compile(rf"\b{re.escape(name)}\s*:", re.IGNORECASE),
        re.compile(rf"\b{re.escape(name)}\s*=", re.IGNORECASE),
    )
    for pattern in patterns:
        match = pattern.search(masked)
        if not match:
            continue
        start = match.end()
        while start < len(masked) and masked[start].isspace():
            start += 1
        paren = bracket = brace = 0
        for i in range(start, len(masked)):
            ch = masked[i]
            if ch == "(":
                paren += 1
            elif ch == ")":
                if paren == 0 and bracket == brace == 0:
                    return expression[start:i].strip()
                paren = max(0, paren - 1)
            elif ch == "[":
                bracket += 1
            elif ch == "]":
                if bracket == 0 and paren == brace == 0:
                    return expression[start:i].strip()
                bracket = max(0, bracket - 1)
            elif ch == "{":
                brace += 1
            elif ch == "}":
                if brace == 0 and paren == bracket == 0:
                    return expression[start:i].strip()
                brace = max(0, brace - 1)
            elif ch == "," and paren == bracket == brace == 0:
                return expression[start:i].strip()
        return expression[start:].strip()
    return None


def environment_source(expression: str) -> str | None:
    match = re.search(
        r'Environment\.GetEnvironmentVariable\s*\(\s*"([^"]+)"\s*\)',
        expression,
    )
    return match.group(1) if match else None


def unquote(value: str) -> str | None:
    match = re.fullmatch(r'@?"([^"]*)"', value.strip(), re.DOTALL)
    return match.group(1).replace('""', '"') if match else None


def literal_or_configured(
    expression: str,
    known_assignments: dict[str, CSharpAssignment],
) -> tuple[str | None, str | None]:
    value = expression.strip()
    literal = unquote(value)
    if literal is not None:
        return literal, None

    uri = re.fullmatch(r"new\s+Uri\s*\(\s*(.*?)\s*\)", value, re.DOTALL)
    if uri:
        return literal_or_configured(uri.group(1), known_assignments)

    if re.fullmatch(r"[A-Za-z_]\w*", value):
        item = known_assignments.get(value)
        if item:
            direct = unquote(item.expression.split("??", 1)[0].strip())
            if direct is not None:
                return direct, None
            env = environment_source(item.expression)
            if env:
                return None, env

    env = environment_source(value)
    return (None, env) if env else (None, None)


def refs(expression: str) -> set[str]:
    return set(re.findall(r"\b[A-Za-z_]\w*\b", expression))


def method_body(
    source: str,
    masked: str,
    method_name: str,
) -> tuple[str, int] | None:
    pattern = re.compile(
        rf"""
        (?:(?:public|private|protected|internal|static|async|virtual|override|
             sealed|partial|unsafe|extern|new)\s+)*
        (?:[\w.<>,?\[\]\(\)\s]+?)
        \b{re.escape(method_name)}\s*\(
        """,
        re.VERBOSE,
    )
    for match in pattern.finditer(masked):
        params = masked.find("(", match.start(), match.end() + 1)
        if params < 0:
            continue
        params_end = balanced_end(masked, params, "(", ")")
        if params_end is None:
            continue
        i = params_end + 1
        while i < len(masked) and masked[i].isspace():
            i += 1
        if masked.startswith("=>", i):
            end = statement_end(masked, i + 2)
            return source[i + 2:end], match.start()
        if i < len(masked) and masked[i] == "{":
            end = balanced_end(masked, i, "{", "}")
            if end is not None:
                return source[i + 1:end], match.start()
    return None
