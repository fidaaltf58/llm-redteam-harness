"""HTTP client for the bundled deliberately-vulnerable demo RAG app (``demo_app``).

Unlike chat targets, the demo app builds its own system prompt and does its own retrieval
server-side, so the harness only sends the user/assistant/tool turns. The per-run canary and
case documents travel in a ``fixture`` field: a test-lab-only hook that lets every run use a
fresh secret without restarting the app.
"""

from __future__ import annotations

import os
import time
from typing import Any

import httpx

from redteam.models import Message, TargetResponse, ToolCall, ToolSpec
from redteam.targets.base import CaseContext, Target, TargetError


class DemoRagTarget(Target):
    kind = "demo-rag"
    capabilities = frozenset({"chat", "rag", "agent"})
    manages_own_prompt = True

    def __init__(
        self,
        model: str = "server-default",
        temperature: float = 0.7,
        timeout: float = 180.0,
        url: str | None = None,
        client: httpx.Client | None = None,
    ) -> None:
        super().__init__(model, temperature, timeout)
        self.url = (url or os.environ.get("DEMO_APP_URL") or "http://127.0.0.1:8000").rstrip("/")
        self._client = client or httpx.Client(timeout=timeout)

    def send(
        self,
        messages: list[Message],
        tools: list[ToolSpec] | None = None,
        ctx: CaseContext | None = None,
    ) -> TargetResponse:
        payload: dict[str, Any] = {
            "messages": [m.model_dump() for m in messages if m.role != "system"],
            "tools": [t.name for t in tools or []],
            "temperature": self.temperature,
        }
        if self.model != "server-default":
            payload["model"] = self.model
        if ctx is not None:
            payload["fixture"] = {
                "canary": ctx.canary,
                "documents": [d.model_dump() for d in ctx.documents],
            }
        start = time.perf_counter()
        try:
            resp = self._client.post(f"{self.url}/chat", json=payload)
        except httpx.HTTPError as exc:
            raise TargetError(
                f"cannot reach demo app at {self.url} ({exc}). Start it with `redteam demo-app`."
            ) from exc
        if resp.status_code >= 400:
            raise TargetError(f"demo app returned HTTP {resp.status_code}: {resp.text[:300]}")
        data = resp.json()
        return TargetResponse(
            text=data.get("answer", ""),
            tool_calls=[ToolCall(**c) for c in data.get("tool_calls", [])],
            retrieved_doc_ids=data.get("retrieved", []),
            latency_ms=(time.perf_counter() - start) * 1000,
            raw={"backend": data.get("backend"), "model": data.get("model")},
        )

    def describe(self) -> str:
        return f"demo-rag@{self.url}"

    def close(self) -> None:
        self._client.close()
