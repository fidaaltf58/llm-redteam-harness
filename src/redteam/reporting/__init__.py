"""JSON results plus Markdown and HTML reports (single run or before/after comparison)."""

from redteam.reporting.html import render_html
from redteam.reporting.json_io import load_report, save_report
from redteam.reporting.markdown import render_markdown
from redteam.reporting.view import build_view

__all__ = ["build_view", "load_report", "render_html", "render_markdown", "save_report"]
