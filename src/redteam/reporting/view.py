"""A renderer-agnostic view of one run (or a baseline/defended pair).

Markdown and HTML both render from this, so the two reports can never disagree.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from redteam import mappings
from redteam.defenses.stack import ALL_DEFENSES
from redteam.models import CaseResult, RunMeta, RunReport
from redteam.scoring.aggregate import GroupStats, group_by, overall


def pct(x: float | None) -> str:
    return "n/a" if x is None else f"{x * 100:.0f}%"


def fmt_case(res: CaseResult | None) -> str:
    if res is None:
        return "-"
    if res.skipped:
        return "skipped"
    if not res.trials:
        return f"error ({res.errors})"
    return f"{res.successes}/{res.trials} ({pct(res.rate)})"


def fmt_ci(lo: float | None, hi: float | None) -> str:
    return "-" if lo is None or hi is None else f"{lo * 100:.0f}-{hi * 100:.0f}%"


def fmt_group(g: GroupStats | None) -> str:
    if g is None or not g.trials:
        return "-"
    return f"{g.successes}/{g.trials} ({pct(g.rate)})"


@dataclass
class CaseRow:
    case_id: str
    title: str
    technique: str
    severity: str
    atlas: list[str]
    before: CaseResult
    after: CaseResult | None = None


@dataclass
class GroupRow:
    key: str
    name: str
    covered: bool
    before: GroupStats | None
    after: GroupStats | None = None


@dataclass
class ReportView:
    before_meta: RunMeta
    after_meta: RunMeta | None
    overall_before: GroupStats
    overall_after: GroupStats | None
    owasp_rows: list[GroupRow]
    atlas_rows: list[GroupRow]
    sections: dict[str, list[CaseRow]]
    skipped: list[CaseResult] = field(default_factory=list)
    errored: list[CaseResult] = field(default_factory=list)
    defense_events: list[tuple[str, int]] = field(default_factory=list)

    @property
    def comparison(self) -> bool:
        return self.after_meta is not None

    @property
    def before_label(self) -> str:
        return defense_label(self.before_meta.defenses)

    @property
    def after_label(self) -> str:
        return defense_label(self.after_meta.defenses) if self.after_meta else ""


def defense_label(defenses: list[str]) -> str:
    if set(defenses) == set(ALL_DEFENSES):
        return "defenses: all"
    return "defenses: " + ", ".join(defenses)


def _event_kind(event: str) -> str:
    head = event.split(":", 1)[0]
    if head.startswith("input_filter"):
        return "input_filter: " + ("blocked user turn" if "blocked" in head else "sanitised doc")
    if head.startswith("output_scanner") and "blocked" in head:
        return "output_scanner: blocked tool call"
    if head == "output_scanner":
        return "output_scanner: " + event.split(":", 1)[1].strip().split(" (")[0]
    if head == "tool_allowlist":
        return "tool_allowlist: " + ("approved" if "approved" in event else "rejected/denied")
    return head


def build_view(before: RunReport, after: RunReport | None = None) -> ReportView:
    after_map = {c.case_id: c for c in after.cases} if after else {}

    def groups(rep: RunReport | None, key: str) -> dict[str, GroupStats]:
        return group_by(rep.cases, key) if rep else {}

    ob, oa = groups(before, "owasp"), groups(after, "owasp")
    owasp_rows = [
        GroupRow(k, v["name"], bool(v.get("covered")), ob.get(k), oa.get(k) if after else None)
        for k, v in mappings.owasp()["entries"].items()
    ]
    ab, aa = groups(before, "atlas"), groups(after, "atlas")
    atlas_rows = [
        GroupRow(k, mappings.atlas_name(k), True, ab[k], aa.get(k) if after else None)
        for k in sorted(ab)
    ]
    sections: dict[str, list[CaseRow]] = {}
    for c in before.cases:
        if c.skipped:
            continue
        sections.setdefault(c.owasp_llm, []).append(
            CaseRow(
                c.case_id, c.title, c.technique, c.severity, c.atlas, c, after_map.get(c.case_id)
            )
        )
    sections = dict(sorted(sections.items()))

    events: Counter[str] = Counter()
    source = after or before
    for c in source.cases:
        for r in c.runs:
            events.update(_event_kind(e) for e in r.defense_events)

    return ReportView(
        before_meta=before.meta,
        after_meta=after.meta if after else None,
        overall_before=overall(before.cases),
        overall_after=overall(after.cases) if after else None,
        owasp_rows=owasp_rows,
        atlas_rows=atlas_rows,
        sections=sections,
        skipped=[c for c in before.cases if c.skipped],
        errored=[c for rep in (before, after) if rep for c in rep.cases if c.errors],
        defense_events=events.most_common(),
    )
