# Benchmark

Two labeled test suites for measuring how well the reviewer finds real security issues
without raising false alarms, plus two baselines to compare against.

## Suites

### `owasp`: OWASP Benchmark for Python v0.1 (public, third-party)

[OWASP Benchmark for Python](https://github.com/OWASP-Benchmark/BenchmarkPython) is OWASP's
test suite for scoring security tools. It has 1,230 small Flask handlers, each labeled as either a
**real, exploitable vulnerability** or a **safe look-alike** (for example, a SQL query that
looks dangerous but uses a parameter, or user input that is overwritten with a constant before
use). There are 14 vulnerability types: path traversal, command/code/SQL/LDAP/XPath injection,
XSS, XXE, insecure deserialization, weak hashing, weak randomness, open redirect, insecure
cookies and trust-boundary violations.

- `owasp_python/cases.jsonl` holds all 1,230 cases, converted by `owasp_python/prepare.py`
  from upstream commit `f1291485` (May 2026).
- Each test file names its category in its URL path (`/benchmark/sqli-00/...`). The converter
  rewrites those names to neutral ones so the answer isn't given away. The code is otherwise
  unchanged.
- `owasp_python/helpers.json` contains the benchmark's shared helper modules. The reviewer gets them
  as "related repository files", so it can see, for example, that `get_safe_value()` returns a
  constant.
- Scoring follows OWASP's method: a case counts as flagged when the reviewer reports a finding
  with the right CWE. The **Benchmark score** is the true-positive rate minus the false-positive
  rate, averaged over categories. A tool that flags everything scores 0, and so does one that
  flags nothing.
- By default a fixed, stratified sample of 140 cases is used (5 real + 5 safe per type,
  seed 7), which fits a free Gemini quota. Use `--per-class all` for the full 1,230.
- License: GPL-3.0 (see `owasp_python/LICENSE-OWASP-Benchmark`).

### `compliance`: 32 hand-labeled merge requests (written for this project)

This suite covers what OWASP Benchmark doesn't: hardcoded secrets, card data in logs, plaintext
transport, missing authorization/IDOR, JavaScript and Java files, and a "fix" MR that deletes
vulnerable code. It contains 20 vulnerable MRs with 26 labeled issues and 12 safe MRs. Findings
are matched by file, line range and category. Describe it as a "hand-labeled synthetic suite".

## Analyzers

| `--analyzer` | What runs |
|---|---|
| `gemini` | The full seven-node LangGraph pipeline with Gemini (needs `GEMINI_API_KEY`) |
| `stub` | The same pipeline with the built-in pattern-matching stub |
| `bandit` | [Bandit](https://github.com/PyCQA/bandit), the standard open-source Python security linter |

## Running

From the project folder, with the virtual environment active:

```powershell
pip install -r requirements.txt
$env:GEMINI_API_KEY = "your-key"

# OWASP: grows the test set each run, spending at most 10 API requests on new cases
python benchmark/run_benchmark.py --suite owasp --analyzer gemini --budget 10

# compliance suite (32 MRs, about 5 requests)
python benchmark/run_benchmark.py --suite compliance --analyzer gemini
```

### Improving the reviewer without fooling yourself: dev/test split

`owasp_python/split.json` fixes two disjoint sets:

- **dev**: the 96 cases whose results were inspected while designing prompt v2 and the
  exploitability check. Tune here.
- **test**: 136 cases (up to 5 per category and real/safe), never inspected. Report final
  numbers here only, so the improvement isn't fitted to the cases it's measured on.

Compare the three setups on the same cases:

```powershell
python benchmark/run_benchmark.py --suite owasp --split test --analyzer gemini --prompt v1 --critic off
python benchmark/run_benchmark.py --suite owasp --split test --analyzer gemini --prompt v2 --critic off
python benchmark/run_benchmark.py --suite owasp --split test --analyzer gemini --prompt v2 --critic on
```

- `--prompt v1` is the original prompt. `v2` adds a checklist of what counts as each issue type
  (including XSS and weak randomness) and requires tracing the value that reaches each dangerous
  operation.
- `--critic on` runs the exploitability-check node, which costs one extra request per 8 files
  that have findings. The report shows how many false alarms it removed and how many real
  catches it lost.

### Keeping API usage low (built for free-tier keys)

- **Batching.** Each request reviews 8 files at once (`--batch 8`). The rules and shared helper
  files are sent once per request, not once per file, so 140 cases take about 18 requests
  instead of 140. Use `--batch 1` for one file per request, which is the most faithful to how
  the reviewer runs on a real MR.
- **Answer cache.** Every file review is saved in `benchmark/.cache/` and is never paid for twice.
  If a request fails, or the model skips a file in a batch, only the missing files are asked again
  next run.
- **Adaptive test set (`--budget N`).** Each run spends at most N requests on new OWASP cases,
  then scores everything fetched so far. New cases go to the (category, real/safe) groups whose
  result is least certain right now: groups with few samples, or where the model is
  inconsistent, get them first. Running the same command each day keeps growing the set and
  narrowing the confidence interval.
- **Clean quota stops.** On a 429 the run stops, says whether it was the per-minute or the daily
  limit, and scores what it has.
- **Same-case Bandit comparison.** Bandit is free and local, so every Gemini OWASP run also
  scores Bandit on exactly the same cases.

Tested and rejected: a similarity ("semantic") cache that reuses answers for near-identical
files. In this dataset only 18 of 1,230 files have a near-duplicate, and 9 of those pairs have
opposite labels (one real, one safe). Reusing answers there would save almost nothing and copy
wrong verdicts.

### Other options

- The model defaults to `gemini-3.6-flash`. To use another, set `$env:GEMINI_MODEL = "..."`.
  Each model has its own cache.
- `--per-class 5` (without `--budget`) evaluates a fixed stratified sample of 140 cases instead.
  Add `--limit 10` for a quick check.
- `--sleep` sets the pause between requests (default 4 seconds). `--no-compare` skips the
  Bandit comparison.
- Results are saved in `results/` as a readable `.md` and a full `.json`. The 95% interval on the
  benchmark score is centered on the score, with each rate's uncertainty from the Agresti-Coull
  adjustment, so groups with only a few cases show wide uncertainty.

## Baseline results (already in `results/`)

| Suite | Analyzer | Result |
|---|---|---|
| OWASP, all 1,230 | Bandit | Benchmark score **+0.17** (TPR 48%, FPR 31%), F1 0.57 |
| OWASP, 140 sample | Bandit | Benchmark score +0.20, F1 0.56 |
| OWASP, 140 sample | stub | Benchmark score +0.04, F1 0.08 |
| Compliance, 32 MRs | Bandit | Recall 46%, precision 63%, F1 0.53 |
| Compliance, 32 MRs | stub | Recall 27%, precision 88%, F1 0.41 |

Bandit catches weak hashing and weak randomness well. In 4 categories (command, code and SQL
injection, and XXE) it flags every case, safe or not, so its false-positive rate there is 100%,
and it finds nothing in 8 categories. Those gaps are where an LLM reviewer that follows the data
flow should do better.
