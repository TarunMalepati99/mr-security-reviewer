# mr-security-reviewer

An agentic security reviewer for GitLab merge requests. A seven-node
[LangGraph](https://langchain-ai.github.io/langgraph/) pipeline checks every changed file against
PCI-DSS, SOC 2 and OWASP Top 10 rules using Google Gemini, throws away any finding whose quoted
code isn't really in the diff, and runs a second exploitability check that traces attacker input
to the flagged line, so reviewers only see issues that are real.

## Results

Measured on 136 **held-out** cases from the [OWASP Benchmark for Python](https://github.com/OWASP-Benchmark/BenchmarkPython)
(real vulnerabilities and safe look-alikes across 14 types), none of which were inspected while
designing the prompt or the exploitability check. Model: `gemini-3.5-flash-lite`.

| Setup | Benchmark score (95% CI) | Recall | False-positive rate | Precision | F1 |
|---|---|---|---|---|---|
| Bandit (static analyzer baseline) | +0.14 (+0.04 to +0.25) | 45% | 32% | 58% | 0.50 |
| Original prompt | +0.34 (+0.23 to +0.45) | 75% | 39% | 65% | 0.69 |
| Improved prompt | +0.50 (+0.39 to +0.61) | 96% | 45% | 67% | 0.79 |
| **Improved prompt + exploitability check** | **+0.68 (+0.57 to +0.80)** | **91%** | **23%** | **79%** | **0.85** |

- The exploitability check removed 15 false alarms and lost 3 real catches, roughly halving the
  false-positive rate.
- The hallucination check found **0 fabricated findings** across 170 benchmark files.
- On a separate 32-MR compliance suite (secrets, card data in logs, plaintext transport, access
  control, JS/Java), it reached **100% precision and 73% recall**, with no flags on any of 12 clean
  MRs.
- The full 136-case evaluation took **29 API requests** for 231 file reviews, using batching and
  caching on a free-tier key.

Benchmark score is OWASP's metric: true-positive rate minus false-positive rate, averaged over
categories. Flagging everything scores 0. Full per-category numbers are in
[`benchmark/RESULTS.md`](benchmark/RESULTS.md), the method is in
[`benchmark/README.md`](benchmark/README.md), and `python benchmark/rescore.py` regenerates the table.

**Limitations:**
- Cross-site scripting recall is still low (2 of 5).
- Path traversal and XPath false-positive rates are 60%.
- Each category has only 5 real and 5 safe test cases.
- Results are for one lightweight model.

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m mr_security_reviewer.cli --demo              # zero-credential demo on a bundled MR
```

Set `GEMINI_API_KEY` (and optionally `GITLAB_TOKEN`) to review real merge requests. See
[Demo mode vs. live mode](#demo-mode-vs-live-mode).

## Why this exists

Compliance-heavy codebases (payments, healthcare, anything PCI/SOC2-scoped) generate more
review surface area than humans can keep up with on every merge request. This agent is a
first-pass gate: it reads the diff, checks it against the actual text of the relevant
compliance rules (not just the model's memory of them), and only surfaces a finding once
it has verified the evidence it's citing actually exists in the code. It's meant to catch
the "hardcoded secret," "SQL built with string concatenation," "card number logged in
plaintext" class of issues automatically, so human reviewers spend their attention on
judgment calls instead of pattern matching.

## The graph

```
ingest → context → analyze → verify → exploit_check → aggregate → report
```

| # | Node | What it does |
|---|------|---------------|
| 1 | **ingest** | Pulls the MR title, author, and per-file diffs from the GitLab API (`/merge_requests/:iid/changes`). |
| 2 | **context** | Attaches the full PCI-DSS / SOC 2 / OWASP Top 10 rule set (with CWE ids) to each changed file, keyword-relevant rules first, plus any related repository files the change imports. This keeps the LLM grounded in the actual rule text and in what helper functions really do. |
| 3 | **analyze** | Sends each file's line-numbered diff, rules and related files to Gemini (or the deterministic stub analyzer in demo mode), which returns JSON findings tagged with a CWE and quoting the exact evidence line. API errors are recorded, never silently treated as "no issues". |
| 4 | **verify** | **Hallucination detection.** Grounds every finding's quoted evidence against the code that will exist after the merge (exact → substring → fuzzy match via `difflib`). Anything that doesn't appear there, including quotes of lines the MR deletes, is dropped, not surfaced. |
| 5 | **exploit_check** | **False-alarm filter.** A second Gemini pass traces each grounded finding from the attacker-controlled source to the flagged line (evaluating constant branches, list/dict reads and helper return values) and rejects findings whose input never actually reaches it. Fails open: if the check can't run, findings are kept and the gap is reported. Off in demo mode or with `REVIEW_CRITIC=off`. |
| 6 | **aggregate** | Deduplicates findings that multiple frameworks flag for the same line (e.g. a hardcoded secret trips both PCI-DSS and SOC 2), scores overall risk 0-100, and decides the gate outcome (`pass` / `warn` / `block`). |
| 7 | **report** | Renders a Markdown summary and posts it as an MR comment (real mode) or hands it back to the CLI (demo mode). |

Each node is a plain function operating on a shared `ReviewState` TypedDict
(`mr_security_reviewer/state.py`) — see that file for the full schema.

## Tools used

- **LangGraph** — the seven nodes above, wired as a `StateGraph` (`graph.py`).
- **Google Gemini** (`google-genai` SDK, model set by `GEMINI_MODEL`, default `gemini-3.6-flash`)
  — the analysis LLM. A Flash model is used for cost/latency: this is meant to run on every MR,
  not just nightly. Calls use temperature 0 and JSON output mode, with retry/backoff on rate limits.
- **GitLab REST API v4** — fetching MR diffs and posting the review comment.
- **Arize Phoenix** + **OpenInference** — optional OpenTelemetry-based tracing of every node's
  inputs/outputs/latency, viewable in Phoenix's local UI.
- Everything else is stdlib (`difflib` for fuzzy grounding, `argparse` for the CLI, `json`
  for the rule/fixture data).

## Demo mode vs. live mode

Nothing needs to be flipped in code. Each integration client checks for its own credential
and falls back to a mock automatically:

| | Demo (default / `--demo`) | Live |
|---|---|---|
| GitLab | Reads `mr_security_reviewer/fixtures/sample_mr_diff.json` | Set `GITLAB_TOKEN` (and optionally `GITLAB_URL`), pass `--project` / `--mr-id` |
| Gemini | Deterministic pattern-matching stub (`integrations/llm_client.py::_analyze_with_stub`) | Set `GEMINI_API_KEY` (optionally `GEMINI_MODEL`) |

Copy `.env.example` to `.env` and fill in what you have (the CLI reads `.env` automatically);
`--demo` always forces both mocks regardless of what's set, which is useful for CI smoke tests.

## Running it

```bash
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\Activate.ps1
pip install -r requirements.txt

# zero-setup demo run against the bundled fixture MR
python -m mr_security_reviewer.cli --demo

# live run once GITLAB_TOKEN / GEMINI_API_KEY are set
python -m mr_security_reviewer.cli --project mygroup/myrepo --mr-id 42

# write the report to a file instead of just stdout
python -m mr_security_reviewer.cli --demo --out review.md

# full state as JSON (useful for wiring into another system)
python -m mr_security_reviewer.cli --demo --json
```

The CLI exits non-zero when the gate decision is `block`, so it can be dropped straight into
a GitLab CI job as a required check.

Run the tests with:

```bash
pytest
```

`tests/test_graph_end_to_end.py` runs the full graph in demo mode and asserts findings show
up for all three frameworks, every surfaced finding is grounded in the diff, and the
hallucination-verification node actually drops fabricated evidence (it constructs a finding
that quotes a line never present in the diff and asserts it gets filtered out).
`tests/test_pipeline_fixes.py` exercises the live-Gemini path with the API call faked (messy
model output, a fabricated quote, rate-limit errors), and the removed-line and context rules.

## Benchmark

`benchmark/` measures detection quality against labeled data and compares with Bandit:
the public **OWASP Benchmark for Python** (1,230 labeled real-vs-safe cases, 14 vulnerability
types) and a hand-labeled 32-MR compliance suite. See `benchmark/README.md`.

```bash
python benchmark/run_benchmark.py --suite owasp --analyzer gemini --budget 10
python benchmark/run_benchmark.py --suite owasp --analyzer bandit     # baseline
```

## Observability

`--trace` turns on Arize Phoenix instrumentation. Its packages are optional and live in
`requirements-trace.txt` (`pip install -r requirements-trace.txt`), because current
`arize-phoenix` releases pull in a dependency that has to be compiled from source on some
Windows/Python combinations:

```bash
python -m mr_security_reviewer.cli --demo --trace
# Phoenix UI: http://localhost:6006
```

This is intentionally best-effort: `observability/tracing.py` lazy-imports `phoenix` and
`openinference-instrumentation-langchain`, and if either is missing *or fails to import*,
it prints a one-line warning and the review still runs untraced rather than crashing.

**Known packaging issue:** `arize-phoenix` ships very frequently, and a couple of releases
have had import-time bugs on Python 3.11 (a `dataclasses` mutable-default error in
`phoenix.trace.dsl.filter`, and a version split where `phoenix.evals` moved into the separate
`arize-phoenix-evals` package). If `--trace` prints an import error, or `pytest` itself starts
failing after you `pip install arize-phoenix` (it registers a pytest plugin via entry points,
so a broken install can break plain `pytest` runs too, not just `--trace`), try:

```bash
pip uninstall -y arize-phoenix arize-phoenix-evals
pip install arize-phoenix arize-phoenix-evals   # or pin a specific known-good pair
```

or run tests with `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 pytest` to sidestep plugin autoloading
entirely. None of this affects demo-mode correctness — it's isolated to the optional tracing
path.

## Project layout

```
mr_security_reviewer/
  state.py                 # shared graph state schema
  graph.py                 # StateGraph wiring
  nodes/
    ingest.py               # 1
    context.py               # 2
    analyze.py               # 3
    verify.py                # 4 -- hallucination detection
    exploit_check.py          # 5 -- exploitability check (false-alarm filter)
    aggregate.py              # 6
    report.py                 # 7
  integrations/
    gitlab_client.py         # real GitLab API + mock fixture fallback
    llm_client.py             # real Gemini + deterministic stub fallback
  observability/
    tracing.py                # optional Arize Phoenix wiring
  rules/                       # PCI-DSS / SOC2 / OWASP Top 10 rule excerpts with CWE ids
  fixtures/
    sample_mr_diff.json         # demo-mode MR with planted vulnerabilities
  cli.py
tests/
  test_graph_end_to_end.py
  test_pipeline_fixes.py
benchmark/
  run_benchmark.py             # scorer: --suite owasp|compliance, --analyzer gemini|stub|bandit
  owasp_python/                # OWASP Benchmark for Python, converted (+ prepare.py)
  cases/                       # compliance suite: 32 hand-labeled MRs
  results/                     # saved runs
```

## Extending it

- **Real retrieval**: `nodes/context.py` currently sends the whole (small) bundled rule set,
  keyword-matched rules first. Swap `_rules_for_text` for an embedding-based retriever over a larger compliance
  corpus without touching any other node — the contract is just `file path -> {framework: [rules]}`.
  - **Conditional routing**: the graph is linear on purpose, but LangGraph conditional edges
  would fit naturally here, e.g. skip `analyze` for files with no matched rules, or loop
  `verify` back into `analyze` with a re-prompt when grounding fails instead of just dropping.
- **Inline comments**: `report.py` currently posts one summary comment; GitLab's discussions
  API also supports line-anchored comments if you want findings attached to the exact diff line.

## License

MIT for the code (see `LICENSE`). The OWASP Benchmark test cases in `benchmark/owasp_python/`
are GPL-3.0, as noted in that folder. The API keys in `benchmark/cases/` and the demo fixture
are fake values planted on purpose for the reviewer to catch.
