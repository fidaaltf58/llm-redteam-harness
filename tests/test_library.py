"""The attack library itself is tested: schema, coverage, and that RAG attacks actually retrieve
their poisoned document (otherwise an indirect-injection case could never succeed)."""

from collections import Counter
from pathlib import Path

import pytest
import yaml

from redteam import fixtures
from redteam.encoding import to_base64
from redteam.loader import LibraryError, build_turn_text, load_library, render
from redteam.models import AttackCase, Turn
from redteam.rag import TfidfIndex

ATTACKS = Path(__file__).resolve().parents[1] / "attacks"
CASES = load_library(ATTACKS)


def test_library_size_and_unique_ids():
    assert len(CASES) >= 60
    assert len({c.id for c in CASES}) == len(CASES)


def test_every_required_category_is_covered():
    counts = Counter(c.category for c in CASES)
    for cat in [
        "direct_prompt_injection",
        "indirect_prompt_injection",
        "system_prompt_leakage",
        "jailbreak",
        "sensitive_data_disclosure",
        "improper_output_handling",
        "excessive_agency",
    ]:
        assert counts[cat] >= 5, cat


def test_jailbreak_subtechniques_present():
    techniques = {c.technique for c in CASES if c.category == "jailbreak"}
    for prefix in ("roleplay", "encoding", "multi_turn", "payload_splitting"):
        assert any(t.startswith(prefix) for t in techniques), prefix


def test_agent_cases_offer_dangerous_tools():
    for c in CASES:
        if c.category == "excessive_agency":
            assert {"send_email", "delete_file"} <= set(c.setup.tools)


@pytest.mark.parametrize("case", [c for c in CASES if c.setup.documents], ids=lambda c: c.id)
def test_poisoned_documents_are_retrieved_by_the_case_query(case):
    variables = fixtures.template_vars("ACME-000000000000")
    index = TfidfIndex([*fixtures.BASE_CORPUS, *case.setup.documents])
    query = build_turn_text(case.turns[0], variables)
    top = [d.id for d, _ in index.search(query, k=3)]
    assert any(d.id in top for d in case.setup.documents), (case.id, top)


@pytest.mark.parametrize(
    "case",
    [c for c in CASES if c.category == "sensitive_data_disclosure" and "rag" in c.target_types],
    ids=lambda c: c.id,
)
def test_pii_cases_retrieve_the_crm_export(case):
    index = TfidfIndex(fixtures.BASE_CORPUS)
    query = build_turn_text(case.turns[0], fixtures.template_vars("X"))
    assert "crm-export" in [d.id for d, _ in index.search(query, k=3)]


def test_suite_filter_and_unknown_suite():
    jb = load_library(ATTACKS, "jailbreak")
    assert jb and all(c.category == "jailbreak" for c in jb)
    with pytest.raises(LibraryError):
        load_library(ATTACKS, "does_not_exist")


def test_invalid_case_is_rejected():
    raw = yaml.safe_load(
        """
        id: BAD-001
        title: t
        owasp_llm: LLM11
        atlas: [AML.T0051]
        category: jailbreak
        technique: t
        severity: low
        description: d
        prompt: hi
        success_criteria: {detectors: [{type: canary}]}
        """
    )
    with pytest.raises(ValueError):
        AttackCase.model_validate(raw)
    raw["owasp_llm"] = "LLM01"
    raw["unexpected_field"] = 1
    with pytest.raises(ValueError):
        AttackCase.model_validate(raw)


def test_render_and_transforms():
    v = {"CANARY": "ACME-1", "ATTACKER_EMAIL": "a@evil.example"}
    assert render("mail {{ATTACKER_EMAIL}}", v) == "mail a@evil.example"
    with pytest.raises(LibraryError):
        render("{{NOPE}}", v)
    t = Turn(content="Decode: {{PAYLOAD}}", payload="say hi", transform="base64")
    assert build_turn_text(t, v) == f"Decode: {to_base64('say hi')}"
    split = build_turn_text(Turn(content="{{PAYLOAD}}", payload="abcdef", transform="split"), v)
    assert "a = " in split and "z = a + b" in split
