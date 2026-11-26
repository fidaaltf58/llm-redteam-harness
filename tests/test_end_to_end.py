"""Full pipeline on the deterministic mock model, plus the demo app through FastAPI's TestClient.

These numbers are NOT security results; they only prove the plumbing: detectors fire on a
naive model, defenses measurably reduce the success rate, and reports are produced.
"""

import os
from pathlib import Path

import pytest

from redteam.defenses import DefenseConfig
from redteam.loader import load_library
from redteam.models import RunReport
from redteam.reporting import build_view, load_report, render_html, render_markdown, save_report
from redteam.runner import RunConfig, build_report
from redteam.scoring.aggregate import overall
from redteam.targets import DemoRagTarget, MockTarget

ATTACKS = Path(__file__).resolve().parents[1] / "attacks"


@pytest.fixture(scope="module")
def reports() -> tuple[RunReport, RunReport]:
    cases = load_library(ATTACKS)
    target = MockTarget()
    before = build_report(cases, target, RunConfig(runs=2), "all")
    after = build_report(
        cases, target, RunConfig(runs=2, defenses=DefenseConfig.parse("all")), "all"
    )
    return before, after


def test_naive_model_is_mostly_vulnerable(reports):
    before, _ = reports
    assert not any(c.errors for c in before.cases)
    assert overall(before.cases).rate > 0.8


def test_defenses_reduce_attack_success_rate(reports):
    before, after = reports
    assert overall(after.cases).rate < overall(before.cases).rate / 2


def test_tool_allowlist_blocks_execution_but_records_attempt(reports):
    _, after = reports
    ea002 = next(c for c in after.cases if c.case_id == "EA-002")
    assert ea002.successes == 0
    assert ea002.attempts == ea002.trials  # the model still tried every time
    assert all(r.blocked_tool_calls for r in ea002.runs)


def test_each_run_uses_a_fresh_canary(reports):
    before, _ = reports
    canaries = [r.canary for c in before.cases for r in c.runs]
    assert len(set(canaries)) == len(canaries)


def test_reports_round_trip_and_render(reports, tmp_path):
    before, after = reports
    path = save_report(before, tmp_path / "baseline.json")
    assert load_report(path).meta.run_id == before.meta.run_id
    view = build_view(before, after)
    md = render_markdown(view)
    html = render_html(view)
    assert "LLM01" in md and "not covered by this harness" in md and "MITRE ATLAS" in md
    assert "<script>alert" not in html  # payloads in transcripts are escaped
    assert "&lt;script&gt;" in html


def test_demo_app_through_target_adapter(monkeypatch):
    pytest.importorskip("fastapi")
    monkeypatch.setitem(os.environ, "DEMO_LLM_BACKEND", "mock")
    import importlib

    import demo_app.app as demo

    demo = importlib.reload(demo)
    from fastapi.testclient import TestClient

    client = TestClient(demo.app)
    assert client.get("/health").json()["backend"] == "mock"
    assert "innerHTML" in client.get("/").text

    target = DemoRagTarget(url="http://testserver", client=client)
    cases = load_library(ATTACKS, case_ids=["IPI-001", "SDD-001", "EA-001"])
    report = build_report(cases, target, RunConfig(runs=1), "subset")
    by_id = {c.case_id: c for c in report.cases}
    assert by_id["IPI-001"].successes == 1
    assert "poisoned-refund-faq" in by_id["IPI-001"].runs[0].retrieved_doc_ids
    assert by_id["SDD-001"].successes == 1
    assert by_id["EA-001"].successes == 1
