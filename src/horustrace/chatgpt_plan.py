"""Streaming Responses API transport for *authorized* ChatGPT plan usage.

An access token must be obtained by the end user through the documented
Sign in with ChatGPT OAuth flow on a runtime they control. This module does not
perform sign-in, collect session cookies, or persist bearer credentials.

OpenAI requires store=False, stream=True and a terminal completed event.
"""
from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from typing import Any
from urllib import error, request

RESPONSES_URL = "https://api.openai.com/v1/responses"
MAX_EVENT_BYTES = 4_000_000
MAX_STREAM_BYTES = 8_000_000


class ChatGPTPlanError(ValueError):
    """A consented ChatGPT-plan inference request did not complete."""


def _events(lines: Iterator[bytes]) -> Iterator[dict[str, Any]]:
    """Read SSE data frames without buffering arbitrary multi-megabyte streams."""
    data: list[bytes] = []
    event_size = 0
    total = 0
    for line in lines:
        total += len(line)
        if total > MAX_STREAM_BYTES:
            raise ChatGPTPlanError("ChatGPT plan stream exceeds maximum size")
        item = line.rstrip(b"\r\n")
        if not item:
            if data:
                try:
                    payload = json.loads(b"\n".join(data))
                except (ValueError, UnicodeDecodeError) as exc:
                    raise ChatGPTPlanError("invalid ChatGPT plan event JSON") from exc
                if not isinstance(payload, dict):
                    raise ChatGPTPlanError("invalid ChatGPT plan event object")
                yield payload
            data = []
            event_size = 0
        elif item.startswith(b"data:"):
            fragment = item[5:].lstrip(b" ")
            event_size += len(fragment)
            if event_size > MAX_EVENT_BYTES:
                raise ChatGPTPlanError("ChatGPT plan event exceeds maximum size")
            if fragment != b"[DONE]":
                data.append(fragment)
    if data:
        raise ChatGPTPlanError("truncated ChatGPT plan event")


def _terminal(events: Iterator[dict[str, Any]]) -> dict[str, Any]:
    """Only return a completed response. Never treat partial text as success."""
    for event in events:
        kind = event.get("type")
        if kind == "response.completed":
            response = event.get("response")
            if not isinstance(response, dict) or response.get("status") != "completed":
                raise ChatGPTPlanError("invalid completed ChatGPT plan response")
            return response
        if kind == "response.failed":
            response = event.get("response") or {}
            detail = response.get("error") if isinstance(response, dict) else {}
            code = detail.get("code") if isinstance(detail, dict) else None
            safe_code = str(code)[:100] if code else "unknown_error"
            raise ChatGPTPlanError(f"ChatGPT plan request failed: {safe_code}")
        if kind == "response.incomplete":
            raise ChatGPTPlanError("ChatGPT plan request was incomplete")
        if kind == "error":
            detail = event.get("error") or {}
            code = detail.get("code") if isinstance(detail, dict) else None
            safe_code = str(code)[:100] if code else "stream_error"
            raise ChatGPTPlanError(f"ChatGPT plan stream error: {safe_code}")
    raise ChatGPTPlanError("ChatGPT plan stream ended without response.completed")


def stream_responses(
    payload: dict[str, Any],
    access_token: str,
    *,
    opener: Callable[..., Any] = request.urlopen,
    timeout: int = 180,
) -> dict[str, Any]:
    """Call OpenAI's public Responses API with OAuth plan authorization.

    The caller must provide a freshly authorized OAuth token with scopes
    `resource.invoke` and `chatgpt.tokens.use.direct`. This transport does
    not store tokens and deliberately never returns/logs authorization headers.
    """
    if not access_token or not access_token.strip():
        raise ChatGPTPlanError("Sign in with ChatGPT authorization is required")
    if not isinstance(payload.get("model"), str) or not payload["model"].strip():
        raise ChatGPTPlanError("a model selected from the signed-in account is required")
    encoded = json.dumps({**payload, "store": False, "stream": True}).encode("utf-8")
    req = request.Request(
        RESPONSES_URL,
        data=encoded,
        method="POST",
        headers={
            "Authorization": "Bearer " + access_token.strip(),
            "Content-Type": "application/json",
            "Accept": "text/event-stream",
        },
    )
    try:
        with opener(req, timeout=timeout) as response:
            return _terminal(_events(iter(response)))
    except error.HTTPError as exc:
        # Avoid dumping response bodies or headers: they may include identifiers.
        raise ChatGPTPlanError(f"ChatGPT plan API HTTP {exc.code}") from exc
    except (error.URLError, TimeoutError) as exc:
        raise ChatGPTPlanError(
            f"ChatGPT plan API connection failed ({type(exc).__name__})"
        ) from exc
