"""The pluggable target interface.

A target is anything that takes a conversation (and optionally tool definitions) and returns
text and/or tool calls. Adding a new provider means implementing one method: ``send``.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from redteam.models import Document, Message, TargetResponse, ToolSpec


class TargetError(RuntimeError):
    """Raised when the endpoint cannot be reached or returns an unusable response."""


@dataclass
class CaseContext:
    """Per-run fixture data. Only targets that build their own prompt (the demo app) need it;
    for plain chat targets the harness already put everything into ``messages``."""

    canary: str
    documents: list[Document] = field(default_factory=list)


class Target(ABC):
    #: short identifier used on the CLI (``--target``)
    kind: str = "abstract"
    #: what this target can be tested for: plain chat, retrieval (RAG), tool calling (agent)
    capabilities: frozenset[str] = frozenset({"chat"})
    #: True when the endpoint adds its own system prompt and retrieval server-side
    manages_own_prompt: bool = False

    def __init__(self, model: str, temperature: float = 0.7, timeout: float = 120.0) -> None:
        self.model = model
        self.temperature = temperature
        self.timeout = timeout

    @abstractmethod
    def send(
        self,
        messages: list[Message],
        tools: list[ToolSpec] | None = None,
        ctx: CaseContext | None = None,
    ) -> TargetResponse:
        """Send the full conversation so far and return the model's next message."""

    def describe(self) -> str:
        return f"{self.kind}:{self.model}"

    def close(self) -> None:  # noqa: B027 - optional hook
        """Release network resources."""
