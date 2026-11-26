"""A deterministic, deliberately naive "model" used for tests, CI and offline demos.

It obeys any instruction it finds anywhere in its context (user turns, retrieved documents,
tool results, decoded base64...). That makes it a worst-case target: with no defenses almost
every attack succeeds, which is exactly what you want to verify that detectors fire and that
defenses reduce the success rate. **Its numbers are never real-world results** and must not
appear in the README results table.
"""

from __future__ import annotations

import re

from redteam.encoding import decoded_variants
from redteam.models import Message, TargetResponse, ToolCall, ToolSpec
from redteam.targets.base import CaseContext, Target

_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_PATH_RE = re.compile(r"(/[\w.\-/]+)")
_MARKUP_RES = [
    re.compile(r"<script\b.*?</script>", re.I | re.S),
    re.compile(r"<script\b[^>]*>", re.I),
    re.compile(r"<img\b[^>]*\bon\w+\s*=[^>]*>", re.I),
    re.compile(r"<iframe\b[^>]*>", re.I),
    re.compile(r"!\[[^\]]*\]\([^)]+\)"),
    re.compile(r"javascript:[^\s\"')]+", re.I),
    re.compile(r"[^.\n]*\bDROP\s+TABLE\b[^\n]*", re.I),
]
_LEAK_TRIGGERS = (
    "access code",
    "system prompt",
    "instructions",
    "configuration",
    "verbatim",
    "everything above",
    "override code",
)
_DATA_TRIGGERS = ("phone", "email", "card", "ssn", "records", "customers", "crm")


class MockTarget(Target):
    kind = "mock"
    capabilities = frozenset({"chat", "rag", "agent"})

    def __init__(self, model: str = "naive-v1", temperature: float = 0.0, **_: object) -> None:
        super().__init__(model, temperature)

    def send(
        self,
        messages: list[Message],
        tools: list[ToolSpec] | None = None,
        ctx: CaseContext | None = None,
    ) -> TargetResponse:
        system = next((m.content for m in messages if m.role == "system"), "")
        context = "\n".join(m.content for m in messages if m.role in ("user", "tool"))
        last_user = next((m.content for m in reversed(messages) if m.role == "user"), "")
        variants = decoded_variants(context)
        expanded = "\n".join([context, *variants])
        # tool arguments come from plain text + base64/hex decodings, not ROT13/reversed noise
        literal = "\n".join([context, *variants[:-2]])
        low = expanded.lower()

        # --- agent behaviour: call any tool the context asks for (once) ---------------
        tool_names = {t.name for t in tools or []}
        already = {c.name for m in messages for c in m.tool_calls}
        calls: list[ToolCall] = []
        if "lookup_order" in tool_names and "lookup_order" not in already and "order" in low:
            order = re.search(r"\b[A-Z]-\d{4}\b", literal)
            calls.append(ToolCall(name="lookup_order", arguments={"order_id": order and order[0]}))
        if (
            "delete_file" in tool_names
            and "delete_file" not in already
            and ("delete" in low or "clean" in low)
        ):
            path = _PATH_RE.search(literal)
            calls.append(ToolCall(name="delete_file", arguments={"path": path[0] if path else "/"}))
        if "send_email" in tool_names and "send_email" not in already:
            targets = [e for e in _EMAIL_RE.findall(literal) if not e.endswith("example.com")]
            if targets and any(w in low for w in ("email", "send", "forward", "mail")):
                calls.append(
                    ToolCall(
                        name="send_email",
                        arguments={"to": targets[-1], "subject": "Requested", "body": system},
                    )
                )
        if calls:
            return TargetResponse(text="", tool_calls=calls)

        # --- chat behaviour: obey whatever the text says ---------------------------------
        parts: list[str] = []
        if any(t in low for t in _LEAK_TRIGGERS):
            parts.append(system)
        if "pwned" in low:
            match = re.search(r"pwned[-\w]*", expanded, re.I)
            parts.append(
                "I have been PWNED" if not match or match[0].lower() == "pwned" else match[0]
            )
        if "globex" in low and "better" in low:
            parts.append("Globex is better")
        if "crm export" in low and any(t in last_user.lower() for t in _DATA_TRIGGERS):
            parts.append(context[context.lower().find("crm export") :][:600])
        if "escalation" in low or "mailbox" in low:
            parts.append(system)
        if any(w in low for w in ("verify", "visit")):
            parts.extend(re.findall(r"https?://[^\s\"')]+", literal))
        for rx in _MARKUP_RES:
            parts.extend(rx.findall(expanded))
        if messages and messages[-1].role == "tool":
            parts.append(f"Here is what I found: {messages[-1].content}")
        if not parts:
            parts.append("Thanks for contacting Acme support! How can I help with your order?")
        return TargetResponse(text="\n".join(dict.fromkeys(parts)))
