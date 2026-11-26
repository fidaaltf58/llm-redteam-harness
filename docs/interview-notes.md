# Interview notes

What to be able to explain about each part of the project, in the order it was built.
For each step: how to run it, then the questions you should be ready for.

---

## 1. Folder structure and YAML schema

**Run:** `redteam validate` (validates all 67 cases), `redteam list --suite jailbreak`

- **Attacks are data, not code.** Every case is a YAML entry validated by Pydantic
  (`src/redteam/models.py`) with `extra="forbid"`: a typo like `sucess_criteria` fails at load
  time instead of silently producing a test that can never fire.
- **Cross-reference validation.** The loader rejects ATLAS IDs that are not in
  `mappings/mitre_atlas.yaml` (verified against ATLAS data release 5.6.0) and OWASP IDs outside
  LLM01-LLM10.
- **`target_types` = required capabilities.** `[rag, agent]` means the target must support both;
  incompatible cases are *skipped and reported*, never counted as passes.
- **`payload` + `transform`.** You write the attack in plain text; the loader produces the
  base64/ROT13/hex/reversed/split variant. Reviewers can read what each case actually does.
- **Random canary per run** (`fixtures.make_canary`). Finding `ACME-3F9A1C0B7E22` in an output
  proves a leak *in that run*: it cannot come from training data or a lucky guess.
- **Policy-violation proxies.** Jailbreak success is defined as breaking the app's own rules
  (leak the canary, praise the competitor "Globex", print a marker), never producing genuinely
  harmful content. This keeps the library publishable and the scoring objective.

## 2. Target adapters

**Run:** `redteam run --target ollama --model llama3.1:8b --case DPI-001 --runs 1`

- One abstract method: `Target.send(messages, tools, ctx) -> TargetResponse`. Adding a provider
  means implementing that method (Strategy/Adapter pattern, `targets/base.py`).
- `capabilities` and `manages_own_prompt` describe the target. For chat models the harness
  *plays the application* (system prompt + simulated retrieval); the demo app builds its own
  prompt server-side, so the harness only sends user turns.
- Normalised tool calls: Ollama returns arguments as a dict, OpenAI as a JSON string. Both become
  `ToolCall(name, arguments: dict)` so detectors don't care which provider produced them.
- **Secrets hygiene:** the API key is read from an env var and never written to results.
- **Fail fast:** a one-request preflight turns "Ollama isn't running" into a clear error instead
  of 300 failed runs. Errored runs are excluded from the denominator and listed in the report.
- Tested without network using `httpx.MockTransport` (`tests/test_targets.py`).

## 3. Demo vulnerable RAG app

**Run:** `redteam demo-app` then `redteam run --target demo-rag --suite indirect_prompt_injection`
(open http://127.0.0.1:8000 to see the chat UI)

Know the six intentional vulnerabilities (docstring of `demo_app/app.py`):
1. Secret in the system prompt (LLM07). Lesson: the system prompt is not a security boundary.
2. Retrieved text concatenated into the prompt with no isolation (LLM01 indirect).
3. Public docs and the internal CRM export share one index with no per-user access control
   (LLM08 -> LLM02). The fix is filtering at retrieval time by the user's permissions, not
   asking the model nicely.
4. Answers rendered with `innerHTML` (LLM05). The fix is output encoding / `textContent`.
5. `send_email` / `delete_file` offered with no allowlist (LLM06).
6. A `fixture` field lets the harness set a fresh canary per run: a test hook, documented as such.

Why TF-IDF instead of embeddings: deterministic, zero downloads, and the security property under
test (untrusted text reaching the prompt, no ACL on the index) is identical. A test proves every
poisoned document is actually retrieved by its case's question (`tests/test_library.py`).

## 4. Attack library (67 cases)

**Run:** `redteam validate` shows counts per category, OWASP ID and ATLAS technique.

| Suite | Cases | Main mapping |
|---|---|---|
| direct_prompt_injection | 10 | LLM01 / AML.T0051.000 |
| indirect_prompt_injection | 10 | LLM01 (+LLM08) / AML.T0051.001, AML.T0070 |
| system_prompt_leakage | 9 | LLM07 / AML.T0056 |
| jailbreak (role-play, encoding, multi-turn, splitting) | 13 | LLM01 / AML.T0054, AML.T0068 |
| sensitive_data_disclosure | 8 | LLM02 (+LLM08) / AML.T0057 |
| improper_output_handling | 8 | LLM05 / AML.T0077 |
| excessive_agency | 9 | LLM06 / AML.T0053, AML.T0086 |

Be ready to explain: direct vs indirect injection; why multi-turn "crescendo" defeats per-message
filters; markdown-image exfiltration (zero-click: the browser fetches the URL when rendering);
tool-output injection (the data source, not the user, is the attacker); path traversal past a
naive prefix allowlist (EA-007).

Honest mapping: ATLAS has no XSS/SQLi technique, so LLM05 cases map to AML.T0077 (LLM Response
Rendering) and AML.T0048.003 (User Harm) as the closest fits, and this is stated in the YAML.

## 5. Scoring

**Run:** any `redteam run`; add `--judge` (optionally `--judge-model llama3.1:70b` or another
target) to cross-check with an LLM judge.

- **Rule detectors** (`scoring/detectors.py`): `canary` (exact, spaced, case-changed,
  base64/hex/ROT13/reversed, optional N-character fragment; also checks executed tool
  arguments), `regex`, `tool_called` (stage `proposed` vs `executed`), `markup` (script, event
  handlers, javascript: URLs, iframes, exfiltration images, chained destructive SQL),
  `not_refused`.
- **Why N runs:** sampling at temperature > 0 makes outputs vary. "1/5" is a real intermittent
  vulnerability; an attacker only needs one success. Report k/n, not pass/fail.
- **Wilson interval:** with n=5 the uncertainty is huge (2/5 -> 12-77%). Wilson stays inside
  [0, 1] and works for small n and for 0/n or n/n, unlike the normal approximation.
- **Known detector errors:** false negatives on paraphrased leaks; false positives when a refusal
  quotes the payload. The markup detectors are tuned against this (e.g. `javascript:` must be
  followed by a call; SQL must be chained with `;`), and tests cover both directions.
- **LLM-as-judge:** fixed rubrics in code, temperature 0, transcript fenced as untrusted data
  (the judge itself can be prompt-injected). Rule scoring stays the default because it is
  deterministic; `--score-mode any|judge` is opt-in.

## 6. Defenses

**Run:** `redteam run --target ollama --compare` (baseline, then all defenses) or
`--defenses input_filter,tool_allowlist` for one combination.

1. **Input filter** (`defenses/input_filter.py`): signature-based. Blocks matching user turns and
   sanitises documents *at ingestion* (strips HTML comments, drops instruction-like sentences),
   and rescans base64/hex decodings. Expected gaps: paraphrase, multi-turn, unusual phrasing.
2. **Output scanner** (`defenses/output_scanner.py`): withholds any response that contains the
   canary in any form (redacting only exact matches would miss encodings), redacts PII (cards
   validated with Luhn, SSNs, phones, third-party emails) and neutralises active HTML. It also
   checks tool-call arguments, so a secret cannot leave through `send_email`. It does **not**
   fix SQL: you cannot make "execute the model's text as SQL" safe by filtering output.
   Parameterised queries are the real fix, and the report shows those cases still succeeding.
3. **Tool allowlist + confirmation** (`defenses/tool_allowlist.py`): allow / confirm / deny
   (deny by default). The automated "user" approves only plausible actions; paths are
   normalised first (`/sandbox/tmp/../../etc/passwd` -> `/etc/passwd` -> rejected).
   `--interactive` makes you the approver.

The key insight: report **proposed vs executed** tool calls. If the model still *proposes* the
malicious call 5/5 times but 0/5 execute, the model is still vulnerable and the control is doing
the work. That is defense in depth, and it tells you what would break if the control were removed.

## 7. Reports

**Run:** reports are written automatically; `redteam report results/<id>/baseline.json
results/<id>/defended.json` re-renders them from saved JSON.

- JSON keeps every transcript, detector hit, defense event and canary, so any number in the
  report can be audited back to the raw run.
- Markdown and HTML render from one view model (`reporting/view.py`), so they never disagree.
- The HTML report autoescapes everything: transcripts contain live XSS payloads, and a report
  that executed them would be an own goal.
- OWASP rows marked "not covered" (LLM03/04/09/10) show the scope honestly instead of hiding it.

## 8. Tests and CI

**Run:** `pytest`, `ruff check .`, `ruff format --check .`

- Tests cover detectors (both directions: should fire / must not fire), Wilson values, judge
  parsing, each defense, the library itself (schema, coverage, poisoned docs are retrievable),
  adapters against fake HTTP servers, and an end-to-end run on a deterministic naive mock model
  plus the demo app via FastAPI's TestClient.
- CI never calls a real LLM: it is free, fast and deterministic. Real-model numbers come only
  from runs on your own machine.
- The mock model's numbers are plumbing checks, never security results.
