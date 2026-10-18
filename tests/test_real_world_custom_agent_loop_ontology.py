"""Positive/negative research fixtures for source-backed model-to-tool loops."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.real_world_custom_agent_loop_ontology import loop_evidence

BASE = Path(__file__).resolve().parents[1]


MODEL_LOOP = '''
class MCPClient:
    def __init__(self):
        self.client = Client()
        self.messages = []

    async def run(self):
        while True:
            response = self.client.chat.completions.create(
                model="qwen", messages=self.messages,
                tools=self.available_tools,
            )
            if response.choices[0].message.tool_calls:
                for tc in response.choices[0].message.tool_calls:
                    value = await self.session.call_tool(tc.function.name, {})
                    self.messages.append({"role": "tool", "content": value})
                continue
            break
'''


def test_source_supported_client_is_agent_construct_by_behavior() -> None:
    evidence = loop_evidence(MODEL_LOOP, "MCPClient")
    assert evidence["classification"] == "source_supported_agent_construct"
    assert evidence["method"] == "run"
    assert evidence["model_call_lines"]
    assert evidence["dispatch_lines"]
    assert evidence["tool_choice_lines"]
    assert evidence["result_feedback_lines"]
    assert evidence["runtime_deployment"] == "unresolved"
    assert evidence["per_tool_effective_authority"] == "unresolved"


def test_renamed_agent_does_not_change_behavioral_classification() -> None:
    evidence = loop_evidence(MODEL_LOOP.replace("class MCPClient:", "class DeepSeekMCPAgent:"), "DeepSeekMCPAgent")
    assert evidence["classification"] == "source_supported_agent_construct"


def test_passive_mcp_forwarder_not_promoted_to_agent() -> None:
    passive = '''
class MCPClient:
    async def call_tool(self, name, args):
        return await self.session.call_tool(name, args)
'''
    assert loop_evidence(passive, "MCPClient")["classification"] == (
        "not_proven_by_iterative_model_tool_loop_rule"
    )


def test_single_model_call_even_with_tools_not_agent_loop() -> None:
    one_shot = '''
class MCPClient:
    async def ask(self, messages):
        return self.client.chat.completions.create(
            model="qwen", messages=messages, tools=self.tools,
        )
'''
    assert loop_evidence(one_shot, "MCPClient")["classification"] == (
        "not_proven_by_iterative_model_tool_loop_rule"
    )


def test_tool_call_loop_without_model_result_feedback_is_not_proven() -> None:
    missing_feedback = MODEL_LOOP.replace(
        'self.messages.append({"role": "tool", "content": value})',
        'print(value)',
    )
    assert loop_evidence(missing_feedback, "MCPClient")["classification"] == (
        "not_proven_by_iterative_model_tool_loop_rule"
    )


def test_model_and_tool_in_disjoint_functions_not_proven() -> None:
    split = '''
class MCPClient:
    async def chat(self):
        while True:
            result = self.client.chat.completions.create(
                model="qwen", tools=self.tools,
            )
            if result.choices[0].message.tool_calls:
                self.messages.append({"role": "tool", "content": "dummy"})

    async def run(self):
        while True:
            await self.session.call_tool("name", {})
'''
    assert loop_evidence(split, "MCPClient")["classification"] == (
        "not_proven_by_iterative_model_tool_loop_rule"
    )


def test_exact_source_provenance_and_posthoc_label_disclosure() -> None:
    doc = json.loads(
        (BASE / "research" / "real-world-agent-security-2026"
         / "custom-agent-loop-ontology-v1.json").read_text(encoding="utf-8")
    )
    assert doc["original_frozen_source_truth_preserved"] is True
    assert doc["adjudication_method"] == "posthoc_static_source_not_blinded"
    assert doc["production_precision_certified"] is False
    cases = {item["case_id"]: item for item in doc["cases"]}
    assert set(cases) == {"rw-089", "rw-103"}
    for case in cases.values():
        assert len(case["source_sha"]) == 40
        assert case["source_ontology"] == "source_supported_agent_construct"
        assert case["runtime_deployment"] == "unresolved"
        assert case["per_tool_effective_authority"] == "unresolved"
        assert all(case["source_evidence"].get(key) for key in (
            "model_with_tools", "model_selected_tool_call",
            "actual_tool_dispatch", "result_feedback_and_repeat",
        ))


def test_missing_or_duplicate_class_fails() -> None:
    with pytest.raises(ValueError, match="one exact"):
        loop_evidence(MODEL_LOOP, "NotPresent")
    with pytest.raises(ValueError, match="one exact"):
        loop_evidence(MODEL_LOOP + "\n" + MODEL_LOOP, "MCPClient")
