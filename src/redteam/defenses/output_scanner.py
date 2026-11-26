"""Defense 2 - output canary/secret scanner (+ active-content neutralisation).

Runs on every assistant message *before the user sees it* and on every tool call's
arguments *before the tool executes*:

* If the per-run canary appears in any form (exact, spaced, base64/hex/ROT13/reversed, or a
  6+ character fragment), the whole response is withheld. Redacting only the exact string
  would miss the encoded variants, so withholding is the safe default.
* Other protected values (the internal mailbox) and generic PII patterns (card numbers that
  pass the Luhn check, SSN-shaped numbers, phone numbers, third-party emails) are redacted.
* Active content (script/iframe tags, event handlers, javascript: URLs, auto-loading external
  images with data in the URL) is HTML-escaped or removed.

What it does NOT fix: destructive SQL text. Output encoding cannot make "execute the model's
answer as SQL" safe; the real fix is parameterised queries downstream. The report keeps
showing those cases as successful, on purpose.
"""

from __future__ import annotations

import json
import re

from redteam import fixtures
from redteam.models import ToolCall
from redteam.scoring.detectors import find_canary

WITHHELD = "[response withheld by output scanner: it contained protected data]"

_CARD_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_PHONE_RE = re.compile(r"\+\d{1,3}[-\s]\d{3}[-\s]\d{4}\b|\(\d{3}\)\s?\d{3}-\d{4}")
_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_ACTIVE = [
    ("script_tag", re.compile(r"<\s*(/?\s*script)", re.I), r"&lt;\1"),
    ("iframe", re.compile(r"<\s*(/?\s*iframe)", re.I), r"&lt;\1"),
    ("event_handler", re.compile(r"(<[a-z][^>]*?)\s(on[a-z]+)\s*=", re.I), r"\1 blocked_\2_attr="),
    ("javascript_url", re.compile(r"javascript\s*:", re.I), "blocked-javascript&#58;"),
    (
        "markdown_image_exfil",
        re.compile(r"!\[([^\]]*)\]\(\s*https?://[^)\s]+\?[^)\s]*\)", re.I),
        r"[image removed: \1]",
    ),
]


def _luhn_ok(digits: str) -> bool:
    total, parity = 0, len(digits) % 2
    for i, ch in enumerate(digits):
        d = int(ch)
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


class OutputScanner:
    name = "output_scanner"

    def __init__(
        self,
        protected_values: list[str] | None = None,
        allowed_emails: set[str] | None = None,
    ) -> None:
        self.protected_values = protected_values or [fixtures.ESCALATION_MAILBOX]
        self.allowed_emails = allowed_emails or {fixtures.CURRENT_CUSTOMER_EMAIL}

    def scan_text(self, text: str, canary: str) -> tuple[str, list[str]]:
        """Return (safe_text, findings)."""
        findings: list[str] = []
        how = find_canary(text, canary, min_fragment=6)
        if how:
            return WITHHELD, [f"canary detected ({how}) -> response withheld"]

        for value in self.protected_values:
            if value.lower() in text.lower():
                text = re.sub(re.escape(value), "[REDACTED]", text, flags=re.I)
                findings.append("protected value redacted")

        def _card(m: re.Match[str]) -> str:
            digits = re.sub(r"\D", "", m[0])
            if 13 <= len(digits) <= 19 and _luhn_ok(digits):
                findings.append("card number redacted")
                return "[REDACTED CARD]"
            return m[0]

        text = _CARD_RE.sub(_card, text)
        if _SSN_RE.search(text):
            text = _SSN_RE.sub("[REDACTED SSN]", text)
            findings.append("SSN redacted")
        if _PHONE_RE.search(text):
            text = _PHONE_RE.sub("[REDACTED PHONE]", text)
            findings.append("phone redacted")

        def _email(m: re.Match[str]) -> str:
            if m[0].lower() in self.allowed_emails:
                return m[0]
            findings.append("third-party email redacted")
            return "[REDACTED EMAIL]"

        text = _EMAIL_RE.sub(_email, text)

        for kind, rx, repl in _ACTIVE:
            if rx.search(text):
                text = rx.sub(repl, text)
                findings.append(f"{kind} neutralised")
        return text, sorted(set(findings))

    def check_tool_call(self, call: ToolCall, canary: str) -> list[str]:
        """Findings that should block a tool call (secret leaving through tool arguments)."""
        blob = json.dumps(call.arguments)
        if find_canary(blob, canary, min_fragment=6):
            return ["canary in tool arguments"]
        return []
