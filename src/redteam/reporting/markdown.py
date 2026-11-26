"""Markdown report (GitHub-friendly tables)."""

from __future__ import annotations

from redteam import mappings
from redteam.reporting.view import (
    GroupRow,
    ReportView,
    fmt_case,
    fmt_ci,
    fmt_group,
    pct,
)


def _esc(s: str) -> str:
    return s.replace("|", "\\|")


def _delta(before: float | None, after: float | None) -> str:
    if before is None or after is None:
        return "-"
    d = (after - before) * 100
    return f"{d:+.0f} pp"


def _cases(row: GroupRow) -> int:
    return row.before.cases if row.before else 0


def render_markdown(view: ReportView) -> str:
    m, a = view.before_meta, view.after_meta
    out: list[str] = ["# LLM Red-Team Report", ""]
    out += [
        "| | |",
        "|---|---|",
        f"| Target | `{m.target}` |",
        f"| Model | `{m.model}` |",
        f"| Date tested (UTC) | {m.started_at} |",
        f"| Runs per case | {m.runs_per_case} |",
        f"| Temperature | {m.temperature} |",
        f"| Defenses | {', '.join(m.defenses)}"
        + (f" **vs** {', '.join(a.defenses)}" if a else "")
        + " |",
        f"| Scoring | {m.score_mode}"
        + (f" (judge: `{m.judge_model}`)" if m.judge_model else "")
        + " |",
        f"| Frameworks | {m.owasp_version}; {m.atlas_version} |",
        f"| Harness | llm-redteam-harness {m.tool_version}, run `{m.run_id}` |",
        "",
        "**ASR** = attack success rate = successful runs / valid runs. Lower is better for the "
        "defender. 95% CI = Wilson score interval.",
        "",
    ]

    ob, oa = view.overall_before, view.overall_after
    out += ["## Overall", ""]
    if view.comparison and oa:
        out += [
            f"| | Cases | Cases with >=1 success | ASR ({view.before_label}) | 95% CI "
            f"| ASR ({view.after_label}) | 95% CI | Change |",
            "|---|---|---|---|---|---|---|---|",
            f"| All | {ob.cases} | {ob.cases_with_success} -> {oa.cases_with_success} | "
            f"{fmt_group(ob)} | {fmt_ci(*ob.ci)} | {fmt_group(oa)} | {fmt_ci(*oa.ci)} | "
            f"{_delta(ob.rate, oa.rate)} |",
        ]
    else:
        out += [
            "| | Cases | Cases with >=1 success | ASR | 95% CI |",
            "|---|---|---|---|---|",
            f"| All | {ob.cases} | {ob.cases_with_success} | {fmt_group(ob)} | {fmt_ci(*ob.ci)} |",
        ]
    out.append("")

    out += ["## Results by OWASP LLM Top 10 (2025)", ""]
    if view.comparison:
        out += [
            f"| ID | Category | Cases | ASR ({view.before_label}) | ASR ({view.after_label}) "
            "| Change |",
            "|---|---|---|---|---|---|",
        ]
    else:
        out += ["| ID | Category | Cases | ASR | 95% CI |", "|---|---|---|---|---|"]
    for row in view.owasp_rows:
        if not row.covered or row.before is None:
            note = "not covered by this harness" if not row.covered else "no cases run"
            cols = 3 if view.comparison else 2
            out.append(
                f"| {row.key} | {row.name} | - | {' | '.join([note] + ['-'] * (cols - 1))} |"
            )
            continue
        b = row.before
        if view.comparison:
            out.append(
                f"| {row.key} | {row.name} | {b.cases} | {fmt_group(b)} | {fmt_group(row.after)} "
                f"| {_delta(b.rate, row.after.rate if row.after else None)} |"
            )
        else:
            out.append(f"| {row.key} | {row.name} | {b.cases} | {fmt_group(b)} | {fmt_ci(*b.ci)} |")
    out.append("")
    out.append(
        "A case counts under its primary and secondary OWASP IDs, so rows overlap; the "
        "per-case tables below group each case once, by its primary ID."
    )
    out.append("")

    out += ["## Per-case results", ""]
    for owasp_id, rows in view.sections.items():
        out += [f"### {owasp_id} - {mappings.owasp_name(owasp_id)}", ""]
        has_tools = any(r.before.attempts is not None for r in rows)
        if view.comparison:
            head = "| ID | Title | ATLAS | Baseline | 95% CI | Defended | 95% CI |"
            sep = "|---|---|---|---|---|---|---|"
            if has_tools:
                head += " Tool call proposed (defended) |"
                sep += "---|"
        else:
            head = "| ID | Title | ATLAS | Successes | 95% CI |"
            sep = "|---|---|---|---|---|"
            if has_tools:
                head += " Tool call proposed |"
                sep += "---|"
        out += [head, sep]
        for r in rows:
            atlas = ", ".join(r.atlas)
            line = (
                f"| {r.case_id} | {_esc(r.title)} | {atlas} | {fmt_case(r.before)} | "
                f"{fmt_ci(r.before.ci_low, r.before.ci_high)} |"
            )
            if view.comparison:
                aft = r.after
                line += f" {fmt_case(aft)} | {fmt_ci(aft.ci_low, aft.ci_high) if aft else '-'} |"
            if has_tools:
                src = r.after if view.comparison else r.before
                if src is not None and src.attempts is not None:
                    line += f" {src.attempts}/{src.trials} |"
                else:
                    line += " - |"
            out.append(line)
        out.append("")

    out += ["## Results by MITRE ATLAS technique", ""]
    if view.comparison:
        out += [
            "| Technique | Name | Cases | Baseline ASR | Defended ASR |",
            "|---|---|---|---|---|",
        ]
        out += [
            f"| [{r.key}]({mappings.atlas_url(r.key)}) | {r.name} | {_cases(r)}"
            f" | {fmt_group(r.before)} | {fmt_group(r.after)} |"
            for r in view.atlas_rows
        ]
    else:
        out += ["| Technique | Name | Cases | ASR |", "|---|---|---|---|"]
        out += [
            f"| [{r.key}]({mappings.atlas_url(r.key)}) | {r.name} | {_cases(r)}"
            f" | {fmt_group(r.before)} |"
            for r in view.atlas_rows
        ]
    out += ["", "A case mapped to several techniques counts once under each.", ""]

    if view.defense_events:
        out += ["## Defense activity", "", "| Event | Count |", "|---|---|"]
        out += [f"| {_esc(k)} | {v} |" for k, v in view.defense_events]
        out.append("")

    if view.skipped or view.errored:
        out += ["## Skipped and errored cases", ""]
        out += [f"- `{c.case_id}` skipped: {c.skipped}" for c in view.skipped]
        for c in view.errored:
            first = next((r.error for r in c.runs if r.error), "")
            out.append(f"- `{c.case_id}`: {c.errors} run(s) errored (excluded from rates): {first}")
        out.append("")

    out += [
        "## How to read this",
        "",
        "- Each case ran several times at non-zero temperature because LLM output is "
        "stochastic; a 1/5 is a real (intermittent) vulnerability, not noise to ignore.",
        "- With few runs per case the confidence intervals are wide; compare categories, not "
        "single cases, and increase `--runs` before drawing fine-grained conclusions.",
        "- Rule-based detectors can miss paraphrased leaks (false negatives) and can flag a "
        "refusal that quotes the payload (false positives). Use `--judge` to cross-check.",
        f"- Overall baseline ASR: {pct(ob.rate)}"
        + (f"; with defenses: {pct(oa.rate)}." if oa else "."),
        "",
    ]
    return "\n".join(out)
