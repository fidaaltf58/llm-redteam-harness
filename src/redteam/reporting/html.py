"""Self-contained HTML report.

Autoescaping is ON: transcripts contain live XSS payloads from the improper-output-handling
suite, and a red-team report that executes them in the reader's browser would be an own goal.
"""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from redteam import mappings
from redteam.models import CaseResult, RunRecord
from redteam.reporting.view import ReportView, fmt_case, fmt_ci, fmt_group, pct

_TEMPLATES = Path(__file__).parent / "templates"


def _sample_run(res: CaseResult | None) -> RunRecord | None:
    """A representative run to show: the first successful one, else the first valid one."""
    if res is None or not res.runs:
        return None
    return next((r for r in res.runs if r.success), None) or next(
        (r for r in res.runs if r.error is None), res.runs[0]
    )


def _width(rate: float | None) -> str:
    return "0" if rate is None else f"{rate * 100:.1f}"


def render_html(view: ReportView) -> str:
    env = Environment(
        loader=FileSystemLoader(_TEMPLATES),
        autoescape=select_autoescape(["html", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.globals.update(
        fmt_case=fmt_case,
        fmt_ci=fmt_ci,
        fmt_group=fmt_group,
        pct=pct,
        width=_width,
        sample_run=_sample_run,
        owasp_name=mappings.owasp_name,
        atlas_url=mappings.atlas_url,
    )
    return env.get_template("report.html.j2").render(v=view)
