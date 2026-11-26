"""Command-line interface: ``redteam run | list | validate | report | demo-app``."""

from __future__ import annotations

import os
from collections import Counter
from pathlib import Path

import typer

from redteam.defenses import DefenseConfig
from redteam.defenses.tool_allowlist import interactive_user, simulated_user
from redteam.loader import LibraryError, load_library
from redteam.models import CaseResult, Message, RunReport
from redteam.reporting import build_view, load_report, render_html, render_markdown, save_report
from redteam.reporting.view import fmt_case, fmt_group, pct
from redteam.runner import RunConfig, build_report, is_compatible
from redteam.scoring.judge import Judge
from redteam.targets import Target, TargetError, create_target

app = typer.Typer(
    help="LLM red-teaming harness. Only test systems you own or are authorised to test.",
    no_args_is_help=True,
    add_completion=False,
)

DEFAULT_MODELS = {"ollama": "llama3.1:8b", "mock": "naive-v1", "demo-rag": "server-default"}
BANNER = "Responsible use: only test systems you own or have written permission to test."


def _make_target(
    kind: str,
    model: str | None,
    temperature: float,
    base_url: str | None,
    api_key_env: str,
    demo_url: str | None,
    ollama_host: str | None,
) -> Target:
    model = model or DEFAULT_MODELS.get(kind)
    if model is None:
        raise typer.BadParameter(f"--model is required for target {kind!r}")
    return create_target(
        kind,
        model=model,
        temperature=temperature,
        base_url=base_url,
        api_key_env=api_key_env,
        url=demo_url,
        host=ollama_host,
    )


def _preflight(target: Target) -> None:
    """One cheap request so a missing server fails in 1 second, not after 300 errors."""
    if target.kind == "mock":
        return
    try:
        target.send([Message(role="user", content="Reply with the word OK.")])
    except TargetError as exc:
        typer.secho(f"Target check failed: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from exc


def _write_reports(out_dir: Path, before: RunReport, after: RunReport | None) -> list[Path]:
    view = build_view(before, after)
    md = out_dir / "report.md"
    html = out_dir / "report.html"
    md.write_text(render_markdown(view), encoding="utf-8")
    html.write_text(render_html(view), encoding="utf-8")
    return [md, html]


def _progress_printer(total: int):
    done = 0

    def show(res: CaseResult) -> None:
        nonlocal done
        done += 1
        status = fmt_case(res)
        color = (
            typer.colors.BRIGHT_BLACK
            if res.skipped
            else typer.colors.RED
            if res.successes
            else typer.colors.GREEN
        )
        typer.echo(f"  [{done:>3}/{total}] {res.case_id:<8} ", nl=False)
        typer.secho(f"{status:<14}", fg=color, nl=False)
        typer.echo(f" {res.title}")

    return show


@app.command()
def run(
    target: str = typer.Option(
        "ollama", "--target", "-t", help="ollama | openai | demo-rag | mock"
    ),
    model: str | None = typer.Option(
        None, "--model", "-m", help="Model name (default per target)."
    ),
    suite: str = typer.Option("all", help="'all' or comma-separated suite names."),
    runs: int = typer.Option(5, min=1, help="Repetitions per case."),
    defenses: str = typer.Option(
        "none", help="none | all | comma list of input_filter,output_scanner,tool_allowlist"
    ),
    compare: bool = typer.Option(
        False, help="Run twice (no defenses, then --defenses or 'all') and report before/after."
    ),
    case: list[str] | None = typer.Option(None, "--case", help="Run only these case ids."),
    temperature: float = typer.Option(0.7, help="Sampling temperature for the target."),
    judge: bool = typer.Option(False, help="Also score every run with an LLM judge."),
    judge_target: str | None = typer.Option(None, help="Judge target kind (default: --target)."),
    judge_model: str | None = typer.Option(None, help="Judge model (default: --model)."),
    score_mode: str = typer.Option("rules", help="rules | judge | any (what counts as success)."),
    out: Path = typer.Option(Path("results"), help="Output directory."),
    attacks_dir: Path | None = typer.Option(None, help="Directory with the YAML suites."),
    base_url: str | None = typer.Option(None, help="OpenAI-compatible base URL."),
    api_key_env: str = typer.Option("OPENAI_API_KEY", help="Env var holding the API key."),
    demo_url: str | None = typer.Option(None, help="Demo app URL (default http://127.0.0.1:8000)."),
    ollama_host: str | None = typer.Option(
        None, help="Ollama URL (default http://localhost:11434)."
    ),
    concurrency: int = typer.Option(1, min=1, help="Parallel requests."),
    interactive: bool = typer.Option(
        False, help="Ask YOU to approve each sensitive tool call (tool_allowlist)."
    ),
) -> None:
    """Run the attack library against a target and write JSON + Markdown + HTML reports."""
    typer.secho(BANNER, fg=typer.colors.YELLOW)
    if score_mode not in ("rules", "judge", "any"):
        raise typer.BadParameter("--score-mode must be rules, judge or any")
    if score_mode != "rules" and not judge:
        raise typer.BadParameter("--score-mode judge/any requires --judge")
    if interactive and concurrency > 1:
        raise typer.BadParameter("--interactive requires --concurrency 1")
    try:
        cases = load_library(attacks_dir, suite, case)
        defense_cfg = DefenseConfig.parse(defenses)
        tgt = _make_target(target, model, temperature, base_url, api_key_env, demo_url, ollama_host)
    except (LibraryError, ValueError, TargetError) as exc:
        typer.secho(f"Error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from exc
    _preflight(tgt)

    judge_obj = None
    if judge:
        jt = _make_target(
            judge_target or target,
            judge_model or model,
            0.0,
            base_url,
            api_key_env,
            demo_url,
            ollama_host,
        )
        if jt.manages_own_prompt:
            raise typer.BadParameter("the demo app cannot be a judge; pass --judge-target ollama")
        judge_obj = Judge(jt)

    configs = [defense_cfg]
    if compare:
        configs = [
            DefenseConfig(),
            defense_cfg if defense_cfg.enabled else DefenseConfig.parse("all"),
        ]

    runnable = sum(is_compatible(c, tgt) for c in cases)
    typer.echo(
        f"Target {tgt.describe()} | {len(cases)} cases ({runnable} compatible) x {runs} runs | "
        f"defenses: {' -> '.join(c.label for c in configs)}"
    )
    reports: list[RunReport] = []
    for cfg_def in configs:
        typer.secho(f"\n== defenses: {cfg_def.label} ==", bold=True)
        cfg = RunConfig(
            runs=runs,
            defenses=cfg_def,
            judge=judge_obj,
            score_mode=score_mode,
            concurrency=concurrency,
            confirmer=interactive_user if interactive else simulated_user,
        )
        reports.append(build_report(cases, tgt, cfg, suite, _progress_printer(len(cases))))
    tgt.close()

    out_dir = out / reports[0].meta.run_id
    if len(reports) == 2:
        files = [
            save_report(reports[0], out_dir / "baseline.json"),
            save_report(reports[1], out_dir / "defended.json"),
        ]
        files += _write_reports(out_dir, reports[0], reports[1])
    else:
        files = [save_report(reports[0], out_dir / "results.json")]
        files += _write_reports(out_dir, reports[0], None)

    view = build_view(reports[0], reports[1] if len(reports) == 2 else None)
    typer.secho("\nSummary (attack success rate, lower is better)", bold=True)
    for row in view.owasp_rows:
        if row.before is None:
            continue
        line = f"  {row.key} {row.name:<34} {fmt_group(row.before):>16}"
        if row.after is not None:
            line += f"  ->  {fmt_group(row.after):>16}"
        typer.echo(line)
    ob, oa = view.overall_before, view.overall_after
    typer.echo(
        f"  {'Overall':<40} {pct(ob.rate):>16}" + (f"  ->  {pct(oa.rate):>16}" if oa else "")
    )
    typer.echo("\nWrote:")
    for f in files:
        typer.echo(f"  {f}")


@app.command("list")
def list_cases(
    suite: str = typer.Option("all"),
    attacks_dir: Path | None = typer.Option(None),
) -> None:
    """List the attack cases."""
    try:
        cases = load_library(attacks_dir, suite)
    except LibraryError as exc:
        typer.secho(str(exc), fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from exc
    for c in cases:
        typer.echo(
            f"{c.id:<8} {c.owasp_llm:<6} {','.join(c.atlas):<34} "
            f"{'+'.join(c.target_types):<10} {c.title}"
        )
    typer.echo(f"\n{len(cases)} cases")


@app.command()
def validate(attacks_dir: Path | None = typer.Option(None)) -> None:
    """Validate the YAML library against the schema and the OWASP/ATLAS mappings."""
    try:
        cases = load_library(attacks_dir)
    except LibraryError as exc:
        typer.secho(f"INVALID: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1) from exc
    typer.secho(f"OK: {len(cases)} valid cases", fg=typer.colors.GREEN)
    for label, counter in (
        ("category", Counter(c.category for c in cases)),
        ("OWASP", Counter(c.owasp_llm for c in cases)),
        ("ATLAS", Counter(t for c in cases for t in c.atlas)),
    ):
        typer.echo(f"\nBy {label}:")
        for k, n in sorted(counter.items()):
            typer.echo(f"  {k:<28} {n}")


@app.command()
def report(
    baseline: Path = typer.Argument(..., exists=True, help="results/baseline JSON"),
    defended: Path | None = typer.Argument(None, help="Optional defended-run JSON to compare."),
    out: Path | None = typer.Option(None, help="Output directory (default: next to baseline)."),
) -> None:
    """Re-render Markdown/HTML from saved JSON (one run, or two runs as before/after)."""
    before = load_report(baseline)
    after = load_report(defended) if defended else None
    files = _write_reports(out or baseline.parent, before, after)
    for f in files:
        typer.echo(f"Wrote {f}")


@app.command("demo-app")
def demo_app(
    backend: str = typer.Option("ollama", help="ollama | mock"),
    model: str = typer.Option("llama3.1:8b", help="Ollama model used by the demo app."),
    host: str = typer.Option("127.0.0.1", help="Bind address. Keep it on localhost."),
    port: int = typer.Option(8000),
) -> None:
    """Start the deliberately vulnerable demo RAG app (requires the 'demo' extra)."""
    try:
        import uvicorn
    except ImportError as exc:
        typer.secho("Install the demo extra first: pip install -e '.[demo]'", fg="red", err=True)
        raise typer.Exit(2) from exc
    if host not in ("127.0.0.1", "localhost"):
        typer.secho(
            "WARNING: this app is deliberately vulnerable. Do not expose it on a network.",
            fg=typer.colors.RED,
        )
    os.environ["DEMO_LLM_BACKEND"] = backend
    os.environ["DEMO_OLLAMA_MODEL"] = model
    uvicorn.run("demo_app.app:app", host=host, port=port)


if __name__ == "__main__":  # pragma: no cover
    app()
