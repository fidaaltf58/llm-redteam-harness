"""Local Ollama target (default ``llama3.1:8b``). Free, offline, no API key."""

from __future__ import annotations

import os
import time
from typing import Any

import httpx

from redteam.models import Message, TargetResponse, ToolCall, ToolSpec
from redteam.targets.base import CaseContext, Target, TargetError


def to_ollama_messages(messages: list[Message]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for m in messages:
        item: dict[str, Any] = {"role": m.role, "content": m.content}
        if m.tool_calls:
            item["tool_calls"] = [
                {"function": {"name": c.name, "arguments": c.arguments}} for c in m.tool_calls
            ]
        out.append(item)
    return out


def to_tool_payload(tools: list[ToolSpec]) -> list[dict[str, Any]]:
    return [
        {
            "type": "function",
            "function": {"name": t.name, "description": t.description, "parameters": t.parameters},
        }
        for t in tools
    ]


class OllamaTarget(Target):
    kind = "ollama"
    capabilities = frozenset({"chat", "rag", "agent"})

    def __init__(
        self,
        model: str = "llama3.1:8b",
        temperature: float = 0.7,
        timeout: float = 180.0,
        host: str | None = None,
        max_tokens: int = 512,
        client: httpx.Client | None = None,
    ) -> None:
        super().__init__(model, temperature, timeout)
        self.host = (host or os.environ.get("OLLAMA_HOST") or "http://localhost:11434").rstrip("/")
        if not self.host.startswith("http"):
            self.host = f"http://{self.host}"
        self.max_tokens = max_tokens
        self._client = client or httpx.Client(timeout=timeout)

    def send(
        self,
        messages: list[Message],
        tools: list[ToolSpec] | None = None,
        ctx: CaseContext | None = None,
    ) -> TargetResponse:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": to_ollama_messages(messages),
            "stream": False,
            "options": {"temperature": self.temperature, "num_predict": self.max_tokens},
        }
        if tools:
            payload["tools"] = to_tool_payload(tools)
        start = time.perf_counter()
        try:
            resp = self._client.post(f"{self.host}/api/chat", json=payload)
        except httpx.HTTPError as exc:
            raise TargetError(
                f"cannot reach Ollama at {self.host} ({exc}). Is `ollama serve` running?"
            ) from exc
        if resp.status_code == 404:
            raise TargetError(f"model {self.model!r} not found. Run: ollama pull {self.model}")
        if resp.status_code >= 400:
            raise TargetError(f"Ollama returned HTTP {resp.status_code}: {resp.text[:300]}")
        data = resp.json()
        msg = data.get("message", {})
        calls = [
            ToolCall(
                name=c.get("function", {}).get("name", ""),
                arguments=c.get("function", {}).get("arguments") or {},
            )
            for c in msg.get("tool_calls") or []
        ]
        return TargetResponse(
            text=msg.get("content", "") or "",
            tool_calls=calls,
            latency_ms=(time.perf_counter() - start) * 1000,
            raw={k: data.get(k) for k in ("model", "eval_count", "prompt_eval_count")},
        )

    def close(self) -> None:
        self._client.close()
