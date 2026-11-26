"""Any OpenAI-compatible Chat Completions endpoint (OpenAI, Groq, Together, vLLM, LM Studio...).

The API key is read from an environment variable (default ``OPENAI_API_KEY``) and is never
written to results or logs.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any

import httpx

from redteam.models import Message, TargetResponse, ToolCall, ToolSpec
from redteam.targets.base import CaseContext, Target, TargetError
from redteam.targets.ollama import to_tool_payload


def to_openai_messages(messages: list[Message]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for m in messages:
        item: dict[str, Any] = {"role": m.role, "content": m.content}
        if m.tool_calls:
            item["tool_calls"] = [
                {
                    "id": c.id or f"call_{i}",
                    "type": "function",
                    "function": {"name": c.name, "arguments": json.dumps(c.arguments)},
                }
                for i, c in enumerate(m.tool_calls)
            ]
            item["content"] = m.content or None
        if m.role == "tool":
            item["tool_call_id"] = m.tool_call_id or "call_0"
        out.append(item)
    return out


def _parse_args(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    try:
        parsed = json.loads(raw or "{}")
        return parsed if isinstance(parsed, dict) else {"_raw": parsed}
    except json.JSONDecodeError:
        return {"_raw": raw}


class OpenAICompatTarget(Target):
    kind = "openai"
    capabilities = frozenset({"chat", "rag", "agent"})

    def __init__(
        self,
        model: str,
        temperature: float = 0.7,
        timeout: float = 120.0,
        base_url: str | None = None,
        api_key_env: str = "OPENAI_API_KEY",
        max_tokens: int = 512,
        client: httpx.Client | None = None,
    ) -> None:
        super().__init__(model, temperature, timeout)
        self.base_url = (
            base_url or os.environ.get("OPENAI_BASE_URL") or "https://api.openai.com/v1"
        ).rstrip("/")
        api_key = os.environ.get(api_key_env, "")
        if not api_key and client is None:
            raise TargetError(f"environment variable {api_key_env} is not set")
        self.max_tokens = max_tokens
        self._client = client or httpx.Client(
            timeout=timeout, headers={"Authorization": f"Bearer {api_key}"}
        )

    def send(
        self,
        messages: list[Message],
        tools: list[ToolSpec] | None = None,
        ctx: CaseContext | None = None,
    ) -> TargetResponse:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": to_openai_messages(messages),
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }
        if tools:
            payload["tools"] = to_tool_payload(tools)
        start = time.perf_counter()
        try:
            resp = self._client.post(f"{self.base_url}/chat/completions", json=payload)
        except httpx.HTTPError as exc:
            raise TargetError(f"cannot reach {self.base_url}: {exc}") from exc
        if resp.status_code >= 400:
            raise TargetError(f"HTTP {resp.status_code}: {resp.text[:300]}")
        data = resp.json()
        try:
            msg = data["choices"][0]["message"]
        except (KeyError, IndexError) as exc:
            raise TargetError(f"unexpected response shape: {str(data)[:300]}") from exc
        calls = [
            ToolCall(
                id=c.get("id"),
                name=c.get("function", {}).get("name", ""),
                arguments=_parse_args(c.get("function", {}).get("arguments")),
            )
            for c in msg.get("tool_calls") or []
        ]
        return TargetResponse(
            text=msg.get("content") or "",
            tool_calls=calls,
            latency_ms=(time.perf_counter() - start) * 1000,
            raw={"model": data.get("model"), "usage": data.get("usage")},
        )

    def close(self) -> None:
        self._client.close()
