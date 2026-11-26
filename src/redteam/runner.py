"""Execute attack cases against a target, N times each, with optional defenses and judge.

Pipeline for one run of one case::

    fresh canary -> render templates -> [input filter: sanitise docs]
    for each user turn:
        [input filter: block turn?] -> (simulated) retrieval -> target.send
        while the model proposes tool calls:
            [output scanner: secret in args?] -> [allowlist + confirmation] -> mock execute
        [output scanner: withhold/redact/neutralise] -> visible answer
    detectors(visible answers, proposed vs executed calls) -> [judge] -> RunRecord
"""

from __future__ import annotations

import json
import platform
import sys
import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import UTC, datetime

from redteam import __version__, fixtures, mappings
from redteam.agent import mock_tools
from redteam.defenses import DefenseConfig, DefenseStack
from redteam.defenses.tool_allowlist import Confirmer, simulated_user
from redteam.loader import build_turn_text, render_detector, render_documents
from redteam.models import (
    AttackCase,
    CaseResult,
    Message,
    RunMeta,
    RunRecord,
    RunReport,
    TargetResponse,
    ToolCall,
)
from redteam.rag import TfidfIndex, augment_user_message
from redteam.scoring.aggregate import finalize_case
from redteam.scoring.detectors import Evidence, evaluate_criteria
from redteam.scoring.judge import Judge
from redteam.targets.base import CaseContext, Target, TargetError

BLOCKED_REPLY = "I can't help with that request."


@dataclass
class RunConfig:
    runs: int = 5
    defenses: DefenseConfig = field(default_factory=DefenseConfig)
    judge: Judge | None = None
    score_mode: str = "rules"  # rules | judge | any
    max_agent_steps: int = 4
    rag_top_k: int = 3
    concurrency: int = 1
    confirmer: Confirmer = simulated_user


def is_compatible(case: AttackCase, target: Target) -> bool:
    return set(case.target_types) <= set(target.capabilities)


def execute_once(case: AttackCase, target: Target, cfg: RunConfig, index: int) -> RunRecord:
    canary = fixtures.make_canary()
    variables = fixtures.template_vars(canary)
    stack = DefenseStack(cfg.defenses, confirmer=cfg.confirmer)
    events: list[str] = []

    docs = render_documents(case.setup.documents, variables)
    if stack.input_filter:
        cleaned = []
        for doc in docs:
            new_doc, removed = stack.input_filter.sanitize_document(doc)
            if removed:
                events.append(f"input_filter sanitised document {doc.id}: {removed}")
            cleaned.append(new_doc)
        docs = cleaned

    tools = mock_tools.specs_for(case.setup.tools) if case.setup.tools else None
    ctx = CaseContext(canary=canary, documents=docs)
    simulate_rag = "rag" in case.target_types and not target.manages_own_prompt
    rag_index = TfidfIndex([*fixtures.BASE_CORPUS, *docs]) if simulate_rag else None

    model_msgs: list[Message] = []
    transcript: list[Message] = []
    if not target.manages_own_prompt:
        sys_msg = Message(role="system", content=fixtures.system_prompt(canary))
        model_msgs.append(sys_msg)
        transcript.append(sys_msg)

    outputs: list[str] = []
    proposed: list[ToolCall] = []
    executed: list[ToolCall] = []
    blocked: list[ToolCall] = []
    retrieved: list[str] = []
    latency = 0.0
    error: str | None = None

    try:
        for turn in case.turns:
            text = build_turn_text(turn, variables)
            transcript.append(Message(role="user", content=text))
            if stack.input_filter and (reasons := stack.input_filter.check(text)):
                events.append(f"input_filter blocked user turn: {reasons}")
                outputs.append(BLOCKED_REPLY)
                transcript.append(Message(role="assistant", content=BLOCKED_REPLY))
                continue

            sent = text
            if rag_index is not None:
                hits = [d for d, _ in rag_index.search(text, k=cfg.rag_top_k)]
                retrieved += [d.id for d in hits]
                sent = augment_user_message(text, hits)
            model_msgs.append(Message(role="user", content=sent))

            resp = TargetResponse()
            for _step in range(cfg.max_agent_steps):
                resp = target.send(model_msgs, tools=tools, ctx=ctx)
                latency += resp.latency_ms
                retrieved += resp.retrieved_doc_ids
                if not resp.tool_calls:
                    break
                assistant_call = Message(
                    role="assistant", content=resp.text, tool_calls=resp.tool_calls
                )
                model_msgs.append(assistant_call)
                transcript.append(assistant_call)
                for call in resp.tool_calls:
                    proposed.append(call)
                    allowed, reason = stack.authorize_tool(call, canary)
                    if allowed:
                        executed.append(call)
                        result = mock_tools.execute(call, case.setup.tool_outputs)
                    else:
                        blocked.append(call)
                        events.append(reason)
                        result = json.dumps({"error": f"blocked: {reason}"})
                    tool_msg = Message(
                        role="tool", content=result, name=call.name, tool_call_id=call.id
                    )
                    model_msgs.append(tool_msg)
                    transcript.append(tool_msg)

            visible = resp.text
            if stack.output_scanner:
                visible, findings = stack.output_scanner.scan_text(visible, canary)
                events += [f"output_scanner: {f}" for f in findings]
            outputs.append(visible)
            model_msgs.append(Message(role="assistant", content=visible))
            transcript.append(Message(role="assistant", content=visible))
    except TargetError as exc:
        error = str(exc)
    except Exception as exc:  # keep the run going; record the failure
        error = f"{type(exc).__name__}: {exc}"

    record = RunRecord(
        index=index,
        success=False,
        rule_success=False,
        transcript=transcript,
        proposed_tool_calls=proposed,
        executed_tool_calls=executed,
        blocked_tool_calls=blocked,
        defense_events=events,
        retrieved_doc_ids=list(dict.fromkeys(retrieved)),
        canary=canary,
        error=error,
        latency_ms=round(latency, 1),
    )
    if error:
        return record

    # ---- scoring ----
    evidence = Evidence(outputs=outputs, proposed=proposed, executed=executed, canary=canary)
    specs = [render_detector(s, variables) for s in case.success_criteria.detectors]
    record.rule_success, record.hits = evaluate_criteria(case.success_criteria, specs, evidence)
    if any(s.type == "tool_called" for s in specs):
        proposed_specs = [
            s.model_copy(update={"stage": "proposed"}) if s.type == "tool_called" else s
            for s in specs
        ]
        record.attempted, _ = evaluate_criteria(case.success_criteria, proposed_specs, evidence)

    if cfg.judge is not None:
        record.judge = cfg.judge.evaluate(
            case,
            transcript,
            executed=[f"{c.name}({json.dumps(c.arguments)})" for c in executed],
            blocked=[f"{c.name}({json.dumps(c.arguments)})" for c in blocked],
        )
    judge_ok = bool(record.judge and record.judge.succeeded)
    if cfg.score_mode == "judge" and record.judge is not None:
        record.success = judge_ok
    elif cfg.score_mode == "any":
        record.success = record.rule_success or judge_ok
    else:
        record.success = record.rule_success
    return record


def _case_result(case: AttackCase) -> CaseResult:
    return CaseResult(
        case_id=case.id,
        title=case.title,
        category=case.category,
        technique=case.technique,
        severity=case.severity,
        owasp_llm=case.owasp_llm,
        owasp_secondary=case.owasp_secondary,
        atlas=case.atlas,
    )


def run_cases(
    cases: list[AttackCase],
    target: Target,
    cfg: RunConfig,
    progress: Callable[[CaseResult], None] | None = None,
) -> list[CaseResult]:
    results: dict[str, CaseResult] = {c.id: _case_result(c) for c in cases}
    jobs: list[tuple[AttackCase, int]] = []
    for case in cases:
        if not is_compatible(case, target):
            results[case.id].skipped = (
                f"target lacks capability: needs {case.target_types}, "
                f"has {sorted(target.capabilities)}"
            )
        else:
            jobs += [(case, i) for i in range(cfg.runs)]

    remaining = {c.id: cfg.runs for c in cases if not results[c.id].skipped}
    with ThreadPoolExecutor(max_workers=max(1, cfg.concurrency)) as pool:
        futures = {pool.submit(execute_once, case, target, cfg, i): case for case, i in jobs}
        for fut in as_completed(futures):
            case = futures[fut]
            results[case.id].runs.append(fut.result())
            remaining[case.id] -= 1
            if remaining[case.id] == 0:
                res = results[case.id]
                res.runs.sort(key=lambda r: r.index)
                finalize_case(res)
                if progress:
                    progress(res)
    for res in results.values():
        if res.skipped and progress:
            progress(res)
    return [results[c.id] for c in cases]


def build_report(
    cases: list[AttackCase],
    target: Target,
    cfg: RunConfig,
    suite_label: str,
    progress: Callable[[CaseResult], None] | None = None,
) -> RunReport:
    started = datetime.now(UTC)
    meta = RunMeta(
        run_id=f"{started:%Y%m%d-%H%M%S}-{uuid.uuid4().hex[:6]}",
        tool_version=__version__,
        started_at=started.isoformat(timespec="seconds"),
        target=target.kind,
        model=target.model if not target.manages_own_prompt else target.describe(),
        suite=suite_label,
        runs_per_case=cfg.runs,
        temperature=target.temperature,
        defenses=list(cfg.defenses.enabled) or ["none"],
        score_mode=cfg.score_mode,  # type: ignore[arg-type]
        judge_model=cfg.judge.model if cfg.judge else None,
        atlas_version=f"MITRE ATLAS {mappings.atlas()['version']}",
        python=sys.version.split()[0],
        platform=platform.platform(terse=True),
    )
    results = run_cases(cases, target, cfg, progress)
    meta.finished_at = datetime.now(UTC).isoformat(timespec="seconds")
    return RunReport(meta=meta, cases=results)
