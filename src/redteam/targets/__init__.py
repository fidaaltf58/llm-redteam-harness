"""Target adapters and the registry that maps ``--target`` names to them."""

from __future__ import annotations

import inspect
from typing import Any

from redteam.targets.base import CaseContext, Target, TargetError
from redteam.targets.demo_rag import DemoRagTarget
from redteam.targets.mock import MockTarget
from redteam.targets.ollama import OllamaTarget
from redteam.targets.openai_compat import OpenAICompatTarget

REGISTRY: dict[str, type[Target]] = {
    "ollama": OllamaTarget,
    "openai": OpenAICompatTarget,
    "demo-rag": DemoRagTarget,
    "mock": MockTarget,
}


def create_target(kind: str, **kwargs: Any) -> Target:
    try:
        cls = REGISTRY[kind]
    except KeyError as exc:
        raise TargetError(f"unknown target {kind!r}; choose from {sorted(REGISTRY)}") from exc
    accepted = inspect.signature(cls.__init__).parameters
    return cls(**{k: v for k, v in kwargs.items() if v is not None and k in accepted})


__all__ = [
    "REGISTRY",
    "CaseContext",
    "DemoRagTarget",
    "MockTarget",
    "OllamaTarget",
    "OpenAICompatTarget",
    "Target",
    "TargetError",
    "create_target",
]
