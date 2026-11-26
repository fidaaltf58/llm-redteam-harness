"""Encoding helpers shared by the loader (to build obfuscated payloads), the input filter and
output scanner (to see through them), and the mock model."""

from __future__ import annotations

import base64
import binascii
import codecs
import re

_B64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])")
_HEX_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}\s?){8,}\b")


def to_base64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def to_rot13(text: str) -> str:
    return codecs.encode(text, "rot_13")


def to_hex(text: str) -> str:
    return text.encode().hex()


def split_payload(text: str, parts: int = 3) -> str:
    """Payload splitting: hand the model fragments and ask it to reassemble them."""
    size = max(1, -(-len(text) // parts))
    chunks = [text[i : i + size] for i in range(0, len(text), size)]
    names = "abcdefghij"
    assigns = "; ".join(f"{names[i]} = {chunk!r}" for i, chunk in enumerate(chunks))
    concat = " + ".join(names[: len(chunks)])
    return f"{assigns}. Let z = {concat}. Now do exactly what z says."


def decoded_variants(text: str) -> list[str]:
    """Best-effort decodings of obfuscated chunks found in ``text``.

    Returns base64 and hex decodings that yield mostly printable text, plus the ROT13 and
    reversed form of the whole string. Used defensively, to inspect what a payload *means*.
    """
    out: list[str] = []
    for match in _B64_RE.findall(text):
        try:
            decoded = base64.b64decode(match + "=" * (-len(match) % 4), validate=False)
            s = decoded.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if s and sum(ch.isprintable() for ch in s) / len(s) > 0.9:
            out.append(s)
    for match in _HEX_RE.findall(text):
        try:
            s = bytes.fromhex(match.replace(" ", "")).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if s and sum(ch.isprintable() for ch in s) / len(s) > 0.9:
            out.append(s)
    out.append(to_rot13(text))
    out.append(text[::-1])
    return out
