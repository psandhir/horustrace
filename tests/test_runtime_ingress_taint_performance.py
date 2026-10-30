"""Regression controls for linear-in-parameters runtime-ingress taint indexing."""
import ast
from unittest.mock import patch

from horustrace import runtime_ingress


def _function(text: str) -> ast.FunctionDef:
    return ast.parse(text).body[0]


def test_preindexed_taint_preserves_assignments_mutations_and_walrus() -> None:
    fn = _function(
        """
def handler(payload, ignored):
    text = payload
    values = []
    values.append(text)
    result = {}
    result.update({"value": values})
    output: str = text
    nested = (alias := output)
    unrelated = ignored
    return result
"""
    )
    prepared = runtime_ingress._taint_analysis(fn)
    expected = {
        "payload", "text", "values", "result", "output", "alias", "nested",
    }
    assert runtime_ingress._propagate_taint(fn, {"payload"}) == expected
    assert runtime_ingress._propagate_taint(
        fn, {"payload"}, prepared=prepared
    ) == expected
    other = runtime_ingress._propagate_taint(
        fn, {"ignored"}, prepared=prepared
    )
    assert "unrelated" in other
    assert "result" not in other


def test_multi_step_mutation_and_nested_body_keep_original_fixed_point() -> None:
    fn = _function(
        """
def handler(source, other):
    end = mid
    mid = start
    start = source
    values = []
    values.insert(0, end)
    records = set()
    records.add(values)
    child = other
    return records
"""
    )
    index = runtime_ingress._taint_analysis(fn)
    plain = runtime_ingress._propagate_taint(fn, {"source"})
    cached = runtime_ingress._propagate_taint(
        fn, {"source"}, prepared=index
    )
    assert plain == cached
    assert {"start", "mid", "end", "values", "records"} <= cached
    assert "child" not in cached


def test_many_parameters_reuse_one_ast_index_without_rewalking() -> None:
    names = [f"p_{n}" for n in range(100)]
    code = (
        f"def handler({', '.join(names)}):\n"
        + "    output = p_0\n"
        + "".join(f"    name_{n} = output\n" for n in range(250))
        + "    result = []\n"
        + "    result.append(name_249)\n"
        + "    return result\n"
    )
    fn = _function(code)
    # The hotspot was a full AST walk for every parameter and every RHS
    # expression across eight fixed-point passes. The shared plan must only
    # be constructed once, with identical source propagation semantics.
    with patch.object(
        runtime_ingress,
        "_taint_analysis",
        wraps=runtime_ingress._taint_analysis,
    ) as build:
        shared = runtime_ingress._taint_analysis(fn)
        for name in names:
            observed = runtime_ingress._propagate_taint(
                fn, {name}, prepared=shared
            )
            assert name in observed
            assert ("result" in observed) == (name == "p_0")
        assert build.call_count == 1
