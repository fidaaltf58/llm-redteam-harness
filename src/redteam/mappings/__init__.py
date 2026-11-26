"""Load the OWASP LLM Top 10 (2025) and MITRE ATLAS reference tables."""

from __future__ import annotations

from functools import cache
from pathlib import Path
from typing import Any

import yaml

_DIR = Path(__file__).parent


@cache
def owasp() -> dict[str, Any]:
    with open(_DIR / "owasp_llm_2025.yaml", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


@cache
def atlas() -> dict[str, Any]:
    with open(_DIR / "mitre_atlas.yaml", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def owasp_name(owasp_id: str) -> str:
    return owasp()["entries"].get(owasp_id, {}).get("name", "Unknown")


def atlas_name(technique_id: str) -> str:
    return atlas()["techniques"].get(technique_id, {}).get("name", "Unknown")


def atlas_url(technique_id: str) -> str:
    return f"https://atlas.mitre.org/techniques/{technique_id}"
