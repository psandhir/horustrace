"""Offline contract tests for the Sign in with ChatGPT inference transport.

These tests deliberately do not make live account requests or store credentials.
"""
from __future__ import annotations

import io
import json
from urllib import error

import pytest

from horustrace.chatgpt_plan import (
    ChatGPTPlanError,
    RESPONSES_URL,
    _terminal,
    _events,
    stream_responses,
)
from horustrace.llm_semantics import LLMSemanticConfig


def event(item: dict) -> bytes:
    return ("event: " + item["type"] + "\n"
            + "data: " + json.dumps(item) + "\n\n").encode()


def complete():
    return {
        "type": "response.completed",
        "response": {
            "id": "resp_test",
            "status": "completed",
            "output": [{
                "type": "message",
                "content": [{"type": "output_text", "text": '{"confidence":0.95}'}],
            }],
        },
    }


def test_chatgpt_plan_provider_is_valid():
    LLMSemanticConfig(provider="chatgpt_plan", model="account-selected-model").validate()


def test_stream_forces_privacy_flags_and_waits_for_completion():
    captured = {}

    def opener(req, *, timeout):
        assert timeout == 180
        captured["url"] = req.full_url
        captured["headers"] = dict(req.header_items())
        captured["body"] = json.loads(req.data)
        # Text fragments are not sufficient; only a completed terminal response succeeds.
        return io.BytesIO(event({"type": "response.output_text.delta", "delta": "partial"})
                          + event(complete()))

    output = stream_responses(
        {"model": "account-selected-model", "input": "test",
         "store": True, "stream": False},
        "user-authorized-oauth-token",
        opener=opener,
    )
    assert output["id"] == "resp_test"
    assert captured["url"] == RESPONSES_URL
    assert captured["body"]["store"] is False
    assert captured["body"]["stream"] is True
    assert captured["headers"]["Authorization"] == "Bearer user-authorized-oauth-token"


def test_plan_failure_discloses_only_code_not_sensitive_response():
    value = event({
        "type": "response.failed",
        "response": {
            "error": {
                "code": "subscription_sharing_usage_limit_exceeded",
                "message": "confidential provider detail",
            }
        },
    })
    with pytest.raises(ChatGPTPlanError, match="subscription_sharing_usage_limit_exceeded") as exc:
        _terminal(_events(iter(io.BytesIO(value))))
    assert "confidential provider detail" not in str(exc.value)


@pytest.mark.parametrize("raw,expected", [
    (event({"type": "response.output_text.delta", "delta": "partial"}),
     "without response.completed"),
    (event({"type": "response.incomplete"}), "incomplete"),
    (b"data: {not json}\n\n", "invalid ChatGPT plan event JSON"),
    (b"data: {\"type\":\"response.completed\"", "truncated ChatGPT plan event"),
    (event({"type": "response.completed", "response": {"status": "failed"}}),
     "invalid completed"),
])
def test_stream_fails_closed_on_noncompletion(raw, expected):
    with pytest.raises(ChatGPTPlanError, match=expected):
        _terminal(_events(iter(io.BytesIO(raw))))


def test_missing_token_never_calls_network():
    def prohibited(*args, **kwargs):
        raise AssertionError("network access must be gated by account authorization")

    with pytest.raises(ChatGPTPlanError, match="authorization"):
        stream_responses({"model": "test"}, "", opener=prohibited)


def test_http_error_does_not_echo_provider_body_or_oauth_token():
    def forbidden(req, timeout):
        raise error.HTTPError(
            req.full_url, 403, "secret-reason", {}, io.BytesIO(b"secret-body")
        )

    with pytest.raises(ChatGPTPlanError, match="HTTP 403") as exc:
        stream_responses({"model": "test"}, "secret-token", opener=forbidden)
    assert "secret-token" not in str(exc.value)
    assert "secret-body" not in str(exc.value)
