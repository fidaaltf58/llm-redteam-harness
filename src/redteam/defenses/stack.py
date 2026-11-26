"""Combine the enabled defenses into one object the runner calls at fixed points."""

from __future__ import annotations

from dataclasses import dataclass, field

from redteam.defenses.input_filter import InputFilter
from redteam.defenses.output_scanner import OutputScanner
from redteam.defenses.tool_allowlist import Confirmer, ToolAllowlist, simulated_user
from redteam.models import ToolCall

ALL_DEFENSES = ("input_filter", "output_scanner", "tool_allowlist")


@dataclass(frozen=True)
class DefenseConfig:
    enabled: tuple[str, ...] = ()

    @classmethod
    def parse(cls, value: str) -> DefenseConfig:
        """``none`` | ``all`` | comma list, e.g. ``input_filter,tool_allowlist``."""
        value = value.strip().lower()
        if value in ("", "none"):
            return cls(())
        if value == "all":
            return cls(ALL_DEFENSES)
        names = tuple(v.strip() for v in value.split(",") if v.strip())
        unknown = [n for n in names if n not in ALL_DEFENSES]
        if unknown:
            raise ValueError(f"unknown defense(s) {unknown}; choose from {ALL_DEFENSES}")
        return cls(tuple(n for n in ALL_DEFENSES if n in names))

    @property
    def label(self) -> str:
        return (
            "none"
            if not self.enabled
            else ("all" if self.enabled == ALL_DEFENSES else ",".join(self.enabled))
        )


@dataclass
class DefenseStack:
    config: DefenseConfig
    confirmer: Confirmer = simulated_user
    input_filter: InputFilter | None = field(init=False, default=None)
    output_scanner: OutputScanner | None = field(init=False, default=None)
    tool_allowlist: ToolAllowlist | None = field(init=False, default=None)

    def __post_init__(self) -> None:
        if "input_filter" in self.config.enabled:
            self.input_filter = InputFilter()
        if "output_scanner" in self.config.enabled:
            self.output_scanner = OutputScanner()
        if "tool_allowlist" in self.config.enabled:
            self.tool_allowlist = ToolAllowlist(confirmer=self.confirmer)

    def authorize_tool(self, call: ToolCall, canary: str) -> tuple[bool, str]:
        """Gate between a *proposed* tool call and its execution."""
        if self.output_scanner:
            findings = self.output_scanner.check_tool_call(call, canary)
            if findings:
                return False, f"output_scanner blocked {call.name}: {', '.join(findings)}"
        if self.tool_allowlist:
            ok, reason = self.tool_allowlist.authorize(call)
            return ok, f"tool_allowlist: {reason}"
        return True, "no tool defense enabled"
