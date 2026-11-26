"""Typed data models.

Two families live here:

* **Library models** (``AttackCase`` and friends) define the YAML schema of the attack
  library. They are strict (``extra="forbid"``) so that a typo in a YAML file fails loudly
  at load time instead of silently producing a test that never fires.
* **Runtime models** (``Message``, ``TargetResponse``, ``RunRecord`` ...) carry data between
  the runner, targets, scorers and reporters, and are serialised to the JSON results file.
"""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

OWASP_ID_RE = re.compile(r"^LLM(0[1-9]|10)$")
ATLAS_ID_RE = re.compile(r"^AML\.T\d{4}(\.\d{3})?$")
CASE_ID_RE = re.compile(r"^[A-Z]{2,4}-\d{3}$")

# --------------------------------------------------------------------------------------
# Runtime: conversation primitives
# --------------------------------------------------------------------------------------

Role = Literal["system", "user", "assistant", "tool"]


class ToolCall(BaseModel):
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    id: str | None = None


class Message(BaseModel):
    role: Role
    content: str = ""
    tool_calls: list[ToolCall] = Field(default_factory=list)
    tool_call_id: str | None = None
    name: str | None = None


class ToolSpec(BaseModel):
    """A function the model may call (OpenAI/Ollama 'tools' format)."""

    name: str
    description: str
    parameters: dict[str, Any]


class TargetResponse(BaseModel):
    text: str = ""
    tool_calls: list[ToolCall] = Field(default_factory=list)
    retrieved_doc_ids: list[str] = Field(default_factory=list)
    latency_ms: float = 0.0
    raw: dict[str, Any] = Field(default_factory=dict)


# --------------------------------------------------------------------------------------
# Library: YAML schema
# --------------------------------------------------------------------------------------

Transform = Literal["none", "base64", "rot13", "hex", "reverse", "split"]
Category = Literal[
    "direct_prompt_injection",
    "indirect_prompt_injection",
    "system_prompt_leakage",
    "jailbreak",
    "sensitive_data_disclosure",
    "improper_output_handling",
    "excessive_agency",
]
Capability = Literal["chat", "rag", "agent"]
Severity = Literal["low", "medium", "high", "critical"]
DetectorType = Literal["canary", "regex", "tool_called", "markup", "not_refused"]
MarkupKind = Literal[
    "script_tag",
    "event_handler",
    "javascript_url",
    "iframe",
    "markdown_image_exfil",
    "sql_destructive",
]
Stage = Literal["proposed", "executed"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Turn(_Strict):
    """One user message. ``payload`` + ``transform`` let you keep the attack readable in YAML
    while the loader produces the encoded/split variant that is actually sent."""

    role: Literal["user"] = "user"
    content: str
    payload: str | None = None
    transform: Transform = "none"

    @model_validator(mode="after")
    def _payload_placeholder(self) -> Turn:
        if self.payload is not None and "{{PAYLOAD}}" not in self.content:
            raise ValueError("a turn with 'payload' must reference {{PAYLOAD}} in 'content'")
        return self


class Document(_Strict):
    id: str
    content: str
    title: str | None = None


class Setup(_Strict):
    documents: list[Document] = Field(default_factory=list)
    tools: list[str] = Field(default_factory=list)
    tool_outputs: dict[str, str] = Field(
        default_factory=dict,
        description="Override the mock result of a tool (used for tool-output injection).",
    )


class DetectorSpec(_Strict):
    type: DetectorType
    # canary
    value: str = "{{CANARY}}"
    min_fragment: int | None = Field(
        default=None, ge=4, description="Also match any N consecutive chars of the secret part."
    )
    # regex
    pattern: str | None = None
    ignore_case: bool = True
    # tool_called
    tool: str | None = None
    args_match: dict[str, str] = Field(default_factory=dict)
    stage: Stage = "executed"
    # markup
    kinds: list[MarkupKind] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check_fields(self) -> DetectorSpec:
        if self.type == "regex":
            if not self.pattern:
                raise ValueError("regex detector requires 'pattern'")
            re.compile(self.pattern)
        if self.type == "tool_called" and not self.tool:
            raise ValueError("tool_called detector requires 'tool'")
        if self.type == "markup" and not self.kinds:
            raise ValueError("markup detector requires 'kinds'")
        for pat in self.args_match.values():
            re.compile(pat)
        return self


class SuccessCriteria(_Strict):
    """When does the *attack* count as successful for one run?"""

    match: Literal["any", "all"] = "any"
    detectors: list[DetectorSpec] = Field(min_length=1)


class JudgeSpec(_Strict):
    rubric: str


class AttackCase(_Strict):
    id: str
    title: str
    owasp_llm: str
    owasp_secondary: list[str] = Field(default_factory=list)
    atlas: list[str] = Field(min_length=1)
    category: Category
    technique: str
    severity: Severity
    description: str
    target_types: list[Capability] = Field(
        default_factory=lambda: ["chat"],
        description="Capabilities the target must ALL support for this case to run.",
    )
    setup: Setup = Field(default_factory=Setup)
    prompt: str | None = None
    turns: list[Turn] = Field(default_factory=list)
    success_criteria: SuccessCriteria
    judge: JudgeSpec | None = None

    @field_validator("id")
    @classmethod
    def _id_format(cls, v: str) -> str:
        if not CASE_ID_RE.match(v):
            raise ValueError(f"case id {v!r} must look like 'DPI-001'")
        return v

    @field_validator("owasp_llm")
    @classmethod
    def _owasp(cls, v: str) -> str:
        if not OWASP_ID_RE.match(v):
            raise ValueError(f"owasp_llm {v!r} must be LLM01..LLM10")
        return v

    @field_validator("owasp_secondary")
    @classmethod
    def _owasp_secondary(cls, v: list[str]) -> list[str]:
        for item in v:
            if not OWASP_ID_RE.match(item):
                raise ValueError(f"owasp_secondary entry {item!r} must be LLM01..LLM10")
        return v

    @field_validator("atlas")
    @classmethod
    def _atlas(cls, v: list[str]) -> list[str]:
        for item in v:
            if not ATLAS_ID_RE.match(item):
                raise ValueError(f"atlas id {item!r} must look like AML.T0051 or AML.T0051.001")
        return v

    @model_validator(mode="after")
    def _prompt_or_turns(self) -> AttackCase:
        if bool(self.prompt) == bool(self.turns):
            raise ValueError(f"{self.id}: define exactly one of 'prompt' or 'turns'")
        if self.prompt:
            self.turns = [Turn(content=self.prompt)]
            self.prompt = None
        if self.setup.tools and "agent" not in self.target_types:
            raise ValueError(f"{self.id}: cases with tools must list 'agent' in target_types")
        return self


class Suite(_Strict):
    suite: str
    schema_version: Literal[1] = 1
    cases: list[AttackCase]


# --------------------------------------------------------------------------------------
# Runtime: results
# --------------------------------------------------------------------------------------


class DetectorHit(BaseModel):
    type: DetectorType
    matched: bool
    detail: str = ""


class JudgeVerdict(BaseModel):
    succeeded: bool | None
    confidence: float | None = None
    reason: str = ""
    raw: str = ""


class RunRecord(BaseModel):
    index: int
    success: bool
    rule_success: bool
    judge: JudgeVerdict | None = None
    attempted: bool | None = Field(
        default=None, description="For tool cases: did the model PROPOSE the forbidden call?"
    )
    hits: list[DetectorHit] = Field(default_factory=list)
    transcript: list[Message] = Field(default_factory=list)
    proposed_tool_calls: list[ToolCall] = Field(default_factory=list)
    executed_tool_calls: list[ToolCall] = Field(default_factory=list)
    blocked_tool_calls: list[ToolCall] = Field(default_factory=list)
    defense_events: list[str] = Field(default_factory=list)
    retrieved_doc_ids: list[str] = Field(default_factory=list)
    canary: str = ""
    error: str | None = None
    latency_ms: float = 0.0


class CaseResult(BaseModel):
    case_id: str
    title: str
    category: Category
    technique: str
    severity: Severity
    owasp_llm: str
    owasp_secondary: list[str] = Field(default_factory=list)
    atlas: list[str]
    skipped: str | None = None
    runs: list[RunRecord] = Field(default_factory=list)
    successes: int = 0
    trials: int = 0
    errors: int = 0
    attempts: int | None = None
    rate: float | None = None
    ci_low: float | None = None
    ci_high: float | None = None


class RunMeta(BaseModel):
    run_id: str
    tool_version: str
    started_at: str
    finished_at: str = ""
    target: str
    model: str
    suite: str
    runs_per_case: int
    temperature: float
    defenses: list[str]
    score_mode: Literal["rules", "judge", "any"] = "rules"
    judge_model: str | None = None
    owasp_version: str = "OWASP Top 10 for LLM Applications 2025"
    atlas_version: str = ""
    python: str = ""
    platform: str = ""


class RunReport(BaseModel):
    meta: RunMeta
    cases: list[CaseResult]
