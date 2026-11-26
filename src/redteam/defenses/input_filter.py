"""Defense 1 - heuristic input filter.

Applied in two places:

* **User turns**: a turn matching a known injection pattern is blocked before it reaches the
  model (the user gets a refusal, the model never sees the text).
* **Documents at ingestion**: case documents are sanitised before they enter the vector
  store - HTML comments are stripped and sentences matching a pattern are dropped. Filtering
  at ingestion, not only at query time, is what stops indirect injection.

It also decodes base64/hex chunks and rescans them, so trivial obfuscation does not bypass it.

This is deliberately a *signature* defense: cheap and explainable, but bypassable by
paraphrase and multi-turn escalation. The before/after report shows exactly where it fails,
which is the point. Production systems would add a trained classifier (e.g. a prompt-injection
detection model) on top.
"""

from __future__ import annotations

import re

from redteam.encoding import decoded_variants
from redteam.models import Document

_F = re.I | re.M
PATTERNS: dict[str, re.Pattern[str]] = {
    "instruction_override": re.compile(
        r"\b(ignore|disregard|forget|override|bypass|suspend(?:ed)?)\b[^.\n]{0,60}"
        r"\b(previous|prior|above|earlier|all|your|these|the)\b[^.\n]{0,40}"
        r"\b(instructions?|rules?|prompts?|directives?|guidelines?|polic(?:y|ies))\b",
        _F,
    ),
    "prompt_extraction": re.compile(
        r"\b(reveal|repeat|print|show|output|display|tell|give|share|state|leak|dump|"
        r"translate|encode|spell|confirm|resend|send|convert|fill)\b[^\n]{0,80}"
        r"\b(system prompt|initial instructions|(?:your|the) (?:full )?instructions|"
        r"configuration|access code|override code|secret|password|escalation mailbox)\b",
        _F,
    ),
    "role_hijack": re.compile(
        r"\b(you are now|from now on,? you|pretend (?:to be|you are)|act as my|"
        r"no (?:rules|restrictions|filters)|never refuses|developer mode|jailbreak)\b",
        _F,
    ),
    "delimiter_injection": re.compile(
        r"(<\|[a-z_]+\|>|\[/?INST\]|^\s*#{2,}\s*(?:system|instruction|admin)\b|"
        r"\[(?:system|assistant)[- ](?:update|only|note)|^\s*system\s*:)",
        _F,
    ),
    "obfuscation_request": re.compile(
        r"(\b(?:decode|decipher|convert|read)\b[^\n]{0,40}\b(?:base64|rot13|hex|backwards|reversed?)\b"
        r"|\b(?:base64|rot13|hex)\b[^\n]{0,60}\b(?:follow|do|execute|obey)\b)",
        _F,
    ),
    "payload_splitting": re.compile(
        r"(\b[a-z]\s*=\s*['\"][^'\"]*['\"]\s*[;,.]\s*(?:let\s+)?[a-z]\s*=\s*['\"]"
        r"|\b[a-z]\s*\+\s*[a-z]\b)",
        _F,
    ),
    "assistant_directed": re.compile(
        r"(\b(?:note|instruction|message|policy update|system note)s?\s+(?:to|for)\s+"
        r"(?:the\s+)?(?:ai|assistants?|model|llm)\b|\b(?:assistants?|ai)\s+(?:must|should)\b)",
        _F,
    ),
    "tool_invocation": re.compile(r"\b(call|use|invoke)\s+(send_email|delete_file)\b", _F),
    "active_markup": re.compile(
        r"(<\s*(?:script|iframe)\b|\bon(?:error|load)\s*=|javascript\s*:)", _F
    ),
}

_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.S)
_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+|\n+")


class InputFilter:
    name = "input_filter"

    def __init__(self, patterns: dict[str, re.Pattern[str]] | None = None) -> None:
        self.patterns = patterns or PATTERNS

    def check(self, text: str) -> list[str]:
        """Names of the patterns that match ``text`` or any decoded variant of it."""
        reasons = {name for name, rx in self.patterns.items() if rx.search(text)}
        for variant in decoded_variants(text)[:-2]:  # base64/hex decodings only
            reasons |= {
                f"{name} (decoded)" for name, rx in self.patterns.items() if rx.search(variant)
            }
        return sorted(reasons)

    def sanitize_document(self, doc: Document) -> tuple[Document, list[str]]:
        """Strip HTML comments and drop sentences that look like instructions."""
        removed: list[str] = []
        text = doc.content
        if _HTML_COMMENT_RE.search(text):
            removed.append("html_comment")
            text = _HTML_COMMENT_RE.sub(" ", text)
        kept: list[str] = []
        for sentence in _SENTENCE_SPLIT_RE.split(text):
            hits = self.check(sentence)
            if hits:
                removed.extend(hits)
            elif sentence.strip():
                kept.append(sentence.strip())
        return doc.model_copy(update={"content": " ".join(kept)}), sorted(set(removed))
