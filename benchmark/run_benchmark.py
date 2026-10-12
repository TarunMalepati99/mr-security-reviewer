"""Score mr-security-reviewer on labeled test suites. Run from the project folder.

Suites
  owasp       OWASP Benchmark for Python v0.1: 1,230 small Flask apps, each labeled as a real
              vulnerability or a safe look-alike, across 14 vulnerability types. A stratified
              sample is used by default (--per-class N real + N safe per type).
  compliance  32 hand-labeled merge requests covering what OWASP Benchmark doesn't:
              hardcoded secrets, card data in logs, plaintext transport, access control,
              plus JavaScript/Java and a "fix" MR.

Analyzers
  gemini      the full LangGraph pipeline with Gemini (needs GEMINI_API_KEY)
  stub        the full pipeline with the built-in pattern-matching stub
  bandit      Bandit, the standard open-source Python security linter (baseline)

Examples
  python benchmark/run_benchmark.py --suite owasp --analyzer gemini --budget 10
  python benchmark/run_benchmark.py --suite compliance --analyzer gemini
  python benchmark/run_benchmark.py --suite owasp --analyzer bandit --per-class all

API usage is kept low for free-tier keys: 8 files per request (--batch), every answer cached
in benchmark/.cache and never paid for twice, and --budget N grows the OWASP test set by at
most N requests per run, spending them on the groups whose score is least certain.
Results are written to benchmark/results/.
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import os
import random
import re
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from mr_security_reviewer.integrations import gitlab_client, llm_client  # noqa: E402
from mr_security_reviewer.nodes.context import _related_files, _rules_for_text  # noqa: E402
from mr_security_reviewer.nodes.verify import _ground  # noqa: E402

BENCH = ROOT / "benchmark"
RESULTS_DIR = BENCH / "results"
CACHE_DIR = BENCH / ".cache"

# ---------------------------------------------------------------------- label vocab

# OWASP Benchmark category -> CWE ids that count as "reported this vulnerability".
OWASP_ACCEPT = {
    "pathtraver": {22, 23, 36, 73},
    "cmdi": {77, 78},
    "codeinj": {94, 95},
    "deserialization": {502},
    "hash": {327, 328, 916},
    "ldapi": {90},
    "redirect": {601},
    "securecookie": {614, 1004},
    "sqli": {89},
    "trustbound": {501},
    "weakrand": {330, 338},
    "xpathi": {643},
    "xss": {79, 80},
    "xxe": {611, 776},
}
OWASP_NAMES = {
    "pathtraver": "Path traversal", "cmdi": "Command injection", "codeinj": "Code injection",
    "deserialization": "Insecure deserialization", "hash": "Weak hashing", "ldapi": "LDAP injection",
    "redirect": "Open redirect", "securecookie": "Insecure cookie", "sqli": "SQL injection",
    "trustbound": "Trust boundary", "weakrand": "Weak randomness", "xpathi": "XPath injection",
    "xss": "Cross-site scripting", "xxe": "XML external entities",
}

# Compliance-suite category -> rule ids and CWE ids that count as the right kind of issue.
COMPLIANCE_RULES = {
    "injection": {"OWASP-A03", "PCI-DSS-6.5"},
    "hardcoded_secret": {"PCI-DSS-3.4", "SOC2-CC6.7", "OWASP-A07"},
    "sensitive_logging": {"PCI-DSS-3.3", "OWASP-A09", "SOC2-CC7.2"},
    "weak_crypto": {"OWASP-A02"},
    "insecure_transport": {"PCI-DSS-4.1", "SOC2-CC6.6", "OWASP-A02"},
    "broken_access_control": {"OWASP-A01", "SOC2-CC6.1", "OWASP-A04"},
}
COMPLIANCE_CWES = {
    "injection": {77, 78, 79, 89, 90, 94, 95, 643, 917},
    "hardcoded_secret": {259, 321, 547, 798},
    "sensitive_logging": {117, 200, 312, 359, 532},
    "weak_crypto": {326, 327, 328, 330, 338, 916},
    "insecure_transport": {295, 297, 319, 523, 757},
    "broken_access_control": {22, 284, 285, 290, 602, 639, 807, 862, 863},
}
RULE_ID_RE = re.compile(r"(OWASP-A\d+|PCI-DSS-[\d.]+|SOC2-CC[\d.]+)")


def finding_cwes(f: dict) -> set[int]:
    out = {c for c in (f.get("cwes") or []) if isinstance(c, int)}
    if isinstance(f.get("cwe"), int):
        out.add(f["cwe"])
    return out


def finding_rule_ids(f: dict) -> set[str]:
    return set(RULE_ID_RE.findall(str(f.get("rule_id", "")))) | set(RULE_ID_RE.findall(str(f.get("rule_title", ""))))


# ---------------------------------------------------------------------- loading suites

def as_added_diff(code: str) -> str:
    return "\n".join("+" + line for line in code.splitlines()) + "\n"


def load_owasp(per_class: str, seed: int, split: str | None = None) -> list[dict]:
    rows = [json.loads(l) for l in open(BENCH / "owasp_python" / "cases.jsonl", encoding="utf-8")]
    helpers = json.loads((BENCH / "owasp_python" / "helpers.json").read_text(encoding="utf-8"))
    if split:
        ids = set(json.loads((BENCH / "owasp_python" / "split.json").read_text(encoding="utf-8"))[split])
        rows = [r for r in rows if r["id"] in ids]
    elif per_class != "all":
        n = int(per_class)
        groups = defaultdict(list)
        for r in rows:
            groups[(r["category"], r["real_vulnerability"])].append(r)
        rng = random.Random(seed)
        rows = []
        for key in sorted(groups):
            g = sorted(groups[key], key=lambda r: r["id"])
            rows += rng.sample(g, min(n, len(g)))
        rows.sort(key=lambda r: r["id"])
    cases = []
    for r in rows:
        cases.append({
            "id": r["id"],
            "title": r["source_test"],
            "author": "owasp-benchmark",
            "changed_files": [{"path": r["path"], "diff": as_added_diff(r["code"])}],
            "context_files": helpers,
            "owasp": {"category": r["category"], "real": r["real_vulnerability"], "cwe": r["cwe"]},
        })
    return cases


def load_compliance() -> list[dict]:
    cases = []
    for p in sorted((BENCH / "cases").glob("*.json")):
        c = json.loads(p.read_text(encoding="utf-8"))
        c.setdefault("context_files", {})
        cases.append(c)
    return cases


# ---------------------------------------------------------------------- analyzers

class QuotaExhausted(RuntimeError):
    pass


def _cache_dir() -> Path:
    d = CACHE_DIR / re.sub(r"[^\w.-]", "_", llm_client.gemini_model())
    d.mkdir(parents=True, exist_ok=True)
    return d


def cache_key(path: str, diff: str, rules, context_files) -> str:
    return hashlib.sha256(json.dumps(
        [llm_client.gemini_model(), llm_client.system_prompt(), path, diff, rules, context_files or {}],
        sort_keys=True,
    ).encode()).hexdigest()[:32]


def cache_get(key: str):
    f = _cache_dir() / f"{key}.json"
    if not f.exists():
        return None
    data = json.loads(f.read_text(encoding="utf-8"))
    return data["findings"] if isinstance(data, dict) else data


def cache_put(key: str, findings: list, mode: str) -> None:
    (_cache_dir() / f"{key}.json").write_text(json.dumps({"mode": mode, "findings": findings}), encoding="utf-8")


def critic_key(path: str, diff: str, findings: list, context_files) -> str:
    return "critic-" + hashlib.sha256(json.dumps(
        [llm_client.gemini_model(), llm_client.CRITIC_PROMPT, path, diff,
         llm_client.critic_view(findings), context_files or {}],
        sort_keys=True, default=str,
    ).encode()).hexdigest()[:32]


def grounded_only(findings: list, diff: str) -> list:
    """What the verify node will pass on to the exploitability check, in the same order."""
    lines = diff.splitlines()
    return [f for f in findings if _ground(f.get("evidence", ""), lines)[0]]


def file_inputs(case: dict, cf: dict):
    """Exactly what the pipeline's context node will hand the analyzer for this file."""
    return _rules_for_text(cf["diff"]), _related_files(cf["diff"], case.get("context_files") or {})


def case_is_cached(case: dict) -> bool:
    return all(cache_get(cache_key(cf["path"], cf["diff"], *file_inputs(case, cf))) is not None
               for cf in case["changed_files"])


def install_gemini_cache(sleep_s: float, stats: dict, allow_calls: bool) -> None:
    """Serve the pipeline's analyze step from the on-disk cache. With allow_calls=False
    (batch mode) every file must already have been fetched by prefetch_batches."""
    original = llm_client.analyze_file

    def cached(path, diff, rules, use_mock, context_files=None):
        key = cache_key(path, diff, rules, context_files)
        hit = cache_get(key)
        if hit is not None:
            stats["cached"] += 1
            return hit
        if not allow_calls:
            raise llm_client.LLMError("not fetched in batch mode (the batch request failed or skipped it)")
        try:
            out = original(path, diff, rules, use_mock, context_files)
        except llm_client.LLMError as exc:
            if "429" in str(exc) or "quota" in str(exc).lower():
                raise QuotaExhausted(str(exc)) from exc
            raise
        cache_put(key, out, "single")
        stats["calls"] += 1
        if sleep_s:
            time.sleep(sleep_s)
        return out

    llm_client.analyze_file = cached

    original_critic = llm_client.critique_file

    def cached_critic(path, diff, findings, context_files, use_mock):
        if not findings or use_mock or not llm_client.critic_enabled():
            return original_critic(path, diff, findings, context_files, use_mock)
        key = critic_key(path, diff, findings, context_files)
        hit = cache_get(key)
        if hit is not None:
            stats["cached"] += 1
            return hit
        if not allow_calls:
            raise llm_client.LLMError("not fetched in batch mode (the batch request failed or skipped it)")
        try:
            out = original_critic(path, diff, findings, context_files, use_mock)
        except llm_client.LLMError as exc:
            if "429" in str(exc) or "quota" in str(exc).lower():
                raise QuotaExhausted(str(exc)) from exc
            raise
        cache_put(key, out, "single")
        stats["critic_calls"] += 1
        stats["calls"] += 1
        if sleep_s:
            time.sleep(sleep_s)
        return out

    llm_client.critique_file = cached_critic


def _make_batches(pending: list[dict], batch_size: int) -> list[list[dict]]:
    batches, cur = [], []
    for it in pending:  # one entry per distinct path per request (paths are the answer keys)
        if len(cur) >= batch_size or any(x["path"] == it["path"] for x in cur):
            batches.append(cur)
            cur = []
        cur.append(it)
    if cur:
        batches.append(cur)
    return batches


def _run_batches(label: str, batches: list[list[dict]], call, store, sleep_s: float, stats: dict,
                 max_requests: int) -> str | None:
    """Send batches until done / out of request budget / out of quota. Returns quota msg or None."""
    for n, batch in enumerate(batches, 1):
        if max_requests and stats["calls"] >= max_requests:
            print(f"  request budget reached; {len(batches) - n + 1} {label} request(s) left for next run", flush=True)
            return None
        try:
            answers = call(batch)
        except llm_client.LLMError as exc:
            msg = str(exc)
            if "429" in msg or "quota" in msg.lower():
                return msg
            if "rejected the API key" in msg or "was not found for this API key" in msg:
                print(f"  !! {msg}\n     Stopping: every request would fail the same way.", flush=True)
                stats["batch_errors"] += 1
                return None
            print(f"  !! {label} request {n}/{len(batches)} failed: {msg[:160]}", flush=True)
            stats["batch_errors"] += 1
            continue
        stats["calls"] += 1
        got = 0
        for it in batch:
            if it["path"] in answers:
                store(it, answers[it["path"]], len(batch))
                got += 1
            else:
                stats["skipped_by_model"] += 1
        print(f"  {label} request {n}/{len(batches)}: got answers for {got}/{len(batch)} files", flush=True)
        if sleep_s and n < len(batches):
            time.sleep(sleep_s)
    return None


def prefetch_batches(cases: list[dict], batch_size: int, sleep_s: float, stats: dict,
                     max_requests: int = 0) -> str | None:
    """Fetch every uncached answer with as few API requests as possible: first the reviews
    (batch_size files per request), then the exploitability checks for files that have
    grounded findings. Returns the quota error message if the quota ran out, else None."""
    pending = []
    for c in cases:
        for cf in c["changed_files"]:
            rules, ctx = file_inputs(c, cf)
            key = cache_key(cf["path"], cf["diff"], rules, ctx)
            if cache_get(key) is None:
                pending.append({"path": cf["path"], "diff": cf["diff"], "context_files": ctx, "key": key})
    if pending:
        batches = _make_batches(pending, batch_size)
        print(f"Reviewing {len(pending)} files in {len(batches)} request(s) ({batch_size} files per request)...",
              flush=True)
        all_rules = _rules_for_text("")

        def store(it, findings, n):
            cache_put(it["key"], findings, f"batch{n}")
            stats["fetched"] += 1

        quota = _run_batches("review", batches, lambda b: llm_client.analyze_batch(b, all_rules), store,
                             sleep_s, stats, max_requests)
        if quota:
            return quota

    if not llm_client.critic_enabled():
        return None
    pending = []
    for c in cases:
        for cf in c["changed_files"]:
            rules, ctx = file_inputs(c, cf)
            findings = cache_get(cache_key(cf["path"], cf["diff"], rules, ctx))
            if not findings:
                continue
            grounded = grounded_only(findings, cf["diff"])
            if not grounded:
                continue
            key = critic_key(cf["path"], cf["diff"], grounded, ctx)
            if cache_get(key) is None:
                pending.append({"path": cf["path"], "diff": cf["diff"], "findings": grounded,
                                "context_files": ctx, "key": key})
    if not pending:
        return None
    batches = _make_batches(pending, batch_size)
    print(f"Double-checking findings in {len(pending)} files in {len(batches)} request(s)...", flush=True)

    def store_critic(it, verdicts, n):
        cache_put(it["key"], verdicts, f"batch{n}")
        stats["critic_fetched"] += 1

    return _run_batches("check", batches, llm_client.critique_batch, store_critic, sleep_s, stats, max_requests)


# ---------------------------------------------------------------------- adaptive sampling

def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return 0.0, 1.0
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / d
    return max(0.0, c - h), min(1.0, c + h)


def select_adaptive(pool: list[dict], done_outcomes: dict[str, bool], n_new: int, seed: int) -> list[dict]:
    """Pick n_new more OWASP cases, one at a time, from whichever (category, real/safe) group
    currently has the widest 95% confidence interval on its rate (TPR for real cases,
    FPR for safe ones). Groups the model handles inconsistently, or that have few samples,
    get the next requests. done_outcomes: case id -> flagged? for already-scored cases."""
    rng = random.Random(seed)
    strata = defaultdict(list)
    for c in pool:
        strata[(c["owasp"]["category"], c["owasp"]["real"])].append(c)
    for k in strata:
        strata[k].sort(key=lambda c: c["id"])
        rng.shuffle(strata[k])  # fixed order per group, so runs are reproducible
    stat = {k: [0, 0] for k in strata}  # flagged, evaluated
    for k, cs in strata.items():
        for c in cs:
            if c["id"] in done_outcomes:
                stat[k][0] += done_outcomes[c["id"]]
                stat[k][1] += 1
    queues = {k: [c for c in cs if c["id"] not in done_outcomes] for k, cs in strata.items()}
    chosen = []
    for _ in range(n_new):
        open_groups = [k for k in queues if queues[k]]
        if not open_groups:
            break

        def width(k):
            f, n = stat[k]
            p = f / n if n else 0.5
            lo, hi = wilson(round(p * (n + 1)), n + 1)  # width after one more sample
            cur_lo, cur_hi = wilson(f, n)
            return (cur_hi - cur_lo) - (hi - lo), -n  # biggest expected shrink first

        k = max(open_groups, key=width)
        chosen.append(queues[k].pop(0))
        f, n = stat[k]
        stat[k] = [f + (f / n if n else 0.5), n + 1]  # expected outcome until we know
    return chosen


def bootstrap_score(results: list[dict], iters: int = 0, seed: int = 0) -> tuple[float, float]:
    """95% confidence interval for the benchmark score (mean over categories of TPR - FPR).

    Centered on the observed score, with each rate's variance from the Agresti-Coull
    adjustment p~ = (k+2)/(n+4), var = p~(1-p~)/(n+4). That keeps groups with only a few
    cases (or a perfect 5/5) honestly uncertain without pulling the interval off the score --
    plain bootstrap gives zero width for 5/5 groups, and Beta-posterior draws shift a
    perfect 5/5 toward 50% so far that the interval can miss the score entirely.
    (iters/seed kept for backwards compatibility; unused.)"""
    counts = defaultdict(lambda: [0, 0])  # (cat, real) -> [flagged, total]
    for r in results:
        c = counts[(r["category"], r["real"])]
        c[0] += r["flagged"]
        c[1] += 1
    cats = sorted({c for c, _ in counts})
    if not cats:
        return 0.0, 0.0
    score, var = 0.0, 0.0
    for cat in cats:
        for real in (True, False):
            k, n = counts.get((cat, real), [0, 0])
            p = k / n if n else 0.0
            score += p if real else -p
            pa = (k + 2) / (n + 4)
            var += pa * (1 - pa) / (n + 4)
    score /= len(cats)
    half = 1.96 * (var ** 0.5) / len(cats)
    return max(-1.0, score - half), min(1.0, score + half)


def run_pipeline(case: dict, use_mock: bool) -> dict:
    from mr_security_reviewer.graph import build_graph

    gitlab_client._load_fixture = lambda: case  # the ingest node reads the MR from here
    app = build_graph()
    return app.invoke({"project": "benchmark", "mr_id": case["id"], "use_mock": use_mock, "errors": []})


# Bandit tags some checks with a generic CWE (e.g. CWE-20 for every XML parser check).
# Map those to the specific CWE the check is actually about, so Bandit gets full credit.
BANDIT_CWE = {
    **{f"B{n}": 611 for n in (313, 314, 315, 316, 317, 318, 319, 320, 405, 406, 407, 408, 409, 410)},
    "B301": 502, "B302": 502, "B403": 502, "B506": 502,
    "B307": 95, "B102": 94,
    "B303": 328, "B324": 328, "B311": 330,
    "B608": 89, "B602": 78, "B603": 78, "B604": 78, "B605": 78, "B606": 78, "B607": 78, "B609": 78,
    "B704": 79, "B703": 79, "B701": 79,
}


def run_bandit(cases: list[dict]) -> dict[str, dict]:
    """Run Bandit once over every case's code and map its results back to findings."""
    states: dict[str, dict] = {c["id"]: {"final_findings": [], "raw_findings": [], "dropped_findings": []} for c in cases}
    sev = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
    with tempfile.TemporaryDirectory() as tmp:
        index = {}
        for c in cases:
            for i, cf in enumerate(c["changed_files"]):
                if not cf["path"].endswith(".py"):
                    continue
                kept, line_map = [], []
                for n, line in enumerate(cf["diff"].splitlines(), 1):
                    if line.startswith("-") or line.startswith("@@"):
                        continue
                    kept.append(line[1:] if line[:1] in "+ " else line)
                    line_map.append(n)
                p = Path(tmp) / c["id"] / f"f{i}" / Path(cf["path"]).name
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text("\n".join(kept) + "\n", encoding="utf-8")
                index[str(p.resolve())] = (c["id"], cf, line_map)
        # run Bandit in chunks so a big run shows progress and one slow chunk can't hang everything
        case_dirs = sorted({str(Path(k).parent.parent) for k in index})
        chunk = 100
        all_results = []
        for start in range(0, len(case_dirs), chunk):
            part = case_dirs[start:start + chunk]
            if len(case_dirs) > chunk:
                print(f"  bandit: files {start + 1}-{start + len(part)} of {len(case_dirs)}", flush=True)
            try:
                proc = subprocess.run(
                    [sys.executable, "-m", "bandit", "-r", *part, "-f", "json", "-q"],
                    capture_output=True, text=True, timeout=300,
                )
            except subprocess.TimeoutExpired:
                raise SystemExit("Bandit took over 5 minutes on one chunk of 100 files. Antivirus scanning of "
                                 "temporary files can do this on Windows; try a smaller sample (--per-class 5).")
            try:
                all_results += json.loads(proc.stdout).get("results", [])
            except json.JSONDecodeError:
                raise SystemExit(f"Bandit failed. Is it installed? (pip install bandit)\n{proc.stderr[:500]}")
        for r in all_results:
            key = str(Path(r["filename"]).resolve())
            if key not in index:
                continue
            cid, cf, line_map = index[key]
            ln = r["line_number"]
            diff_line = line_map[ln - 1] if 0 < ln <= len(line_map) else None
            evidence = cf["diff"].splitlines()[diff_line - 1][1:].strip() if diff_line else ""
            f = {
                "id": f"{r['test_id']}-{ln}",
                "framework": "OWASP",
                "rule_id": f"BANDIT-{r['test_id']}",
                "rule_title": r["test_name"],
                "cwe": BANDIT_CWE.get(r["test_id"], (r.get("issue_cwe") or {}).get("id")),
                "file": cf["path"],
                "line_hint": diff_line,
                "evidence": evidence,
                "severity": sev.get(r["issue_severity"], "low"),
            }
            states[cid]["final_findings"].append(f)
            states[cid]["raw_findings"].append(f)
    for s in states.values():
        sevs = {f["severity"] for f in s["final_findings"]}
        s["gate_decision"] = "block" if "high" in sevs else ("warn" if "medium" in sevs else "pass")
    return states


# ---------------------------------------------------------------------- scoring: OWASP

def score_owasp_case(case: dict, state: dict) -> dict:
    lab = case["owasp"]
    accept = OWASP_ACCEPT[lab["category"]]
    findings = state.get("final_findings", [])
    flagged = any(finding_cwes(f) & accept for f in findings)
    rejected_relevant = any(finding_cwes(f) & accept for f in state.get("rejected_findings", []))
    return {
        "id": case["id"], "test": case["title"], "category": lab["category"], "real": lab["real"],
        "flagged": flagged,
        "outcome": ("TP" if flagged else "FN") if lab["real"] else ("FP" if flagged else "TN"),
        "other_findings": sum(1 for f in findings if not (finding_cwes(f) & accept)),
        "findings": [{"rule_id": f.get("rule_id"), "cwe": f.get("cwe"), "severity": f.get("severity"),
                      "evidence": f.get("evidence")} for f in findings],
        "raw_findings": len(state.get("raw_findings", [])),
        "dropped_as_hallucination": len(state.get("dropped_findings", [])),
        "rejected_by_check": len(state.get("rejected_findings", [])),
        # the check removed the in-category finding: good on safe code, a lost catch on real code
        "check_removed_alarm": rejected_relevant and not flagged,
    }


def summarize_owasp(results: list[dict]) -> dict:
    per = {}
    for cat in OWASP_ACCEPT:
        rs = [r for r in results if r["category"] == cat]
        if not rs:
            continue
        c = {k: sum(r["outcome"] == k for r in rs) for k in ("TP", "FP", "TN", "FN")}
        tpr = c["TP"] / (c["TP"] + c["FN"]) if c["TP"] + c["FN"] else 0.0
        fpr = c["FP"] / (c["FP"] + c["TN"]) if c["FP"] + c["TN"] else 0.0
        per[cat] = c | {"tpr": round(tpr, 3), "fpr": round(fpr, 3), "score": round(tpr - fpr, 3),
                        "tpr_ci": [round(x, 3) for x in wilson(c["TP"], c["TP"] + c["FN"])],
                        "fpr_ci": [round(x, 3) for x in wilson(c["FP"], c["FP"] + c["TN"])]}
    tot = {k: sum(p[k] for p in per.values()) for k in ("TP", "FP", "TN", "FN")}
    precision = tot["TP"] / (tot["TP"] + tot["FP"]) if tot["TP"] + tot["FP"] else 0.0
    recall = tot["TP"] / (tot["TP"] + tot["FN"]) if tot["TP"] + tot["FN"] else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    n = len(per)
    raw = sum(r["raw_findings"] for r in results)
    dropped = sum(r["dropped_as_hallucination"] for r in results)
    return {
        "cases": len(results),
        "real_vulnerable": tot["TP"] + tot["FN"],
        "safe_lookalikes": tot["FP"] + tot["TN"],
        **tot,
        "benchmark_score": round(sum(p["score"] for p in per.values()) / n, 3) if n else 0.0,
        "benchmark_score_ci95": [round(x, 3) for x in bootstrap_score(results)] if results else [0.0, 0.0],
        "avg_tpr": round(sum(p["tpr"] for p in per.values()) / n, 3) if n else 0.0,
        "avg_fpr": round(sum(p["fpr"] for p in per.values()) / n, 3) if n else 0.0,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
        "accuracy": round((tot["TP"] + tot["TN"]) / len(results), 3) if results else 0.0,
        "raw_candidate_findings": raw,
        "dropped_as_hallucination": dropped,
        "rejected_by_check": sum(r.get("rejected_by_check", 0) for r in results),
        "check_fixed_false_alarms": sum(1 for r in results if r.get("check_removed_alarm") and not r["real"]),
        "check_lost_real_catches": sum(1 for r in results if r.get("check_removed_alarm") and r["real"]),
        "per_category": per,
    }


def render_owasp(s: dict) -> str:
    lines = [
        f"Suite: OWASP Benchmark for Python v0.1 -- {s['cases']} cases "
        f"({s['real_vulnerable']} real vulnerabilities, {s['safe_lookalikes']} safe look-alikes)",
        f"Analyzer: {s['analyzer']} ({s['model']})",
        f"Benchmark score (avg TPR - FPR): {s['benchmark_score']:+.2f}  "
        f"(95% CI {s['benchmark_score_ci95'][0]:+.2f} to {s['benchmark_score_ci95'][1]:+.2f})   "
        f"[avg true-positive rate {s['avg_tpr']:.0%}, avg false-positive rate {s['avg_fpr']:.0%}]",
        f"Precision {s['precision']:.0%}   Recall {s['recall']:.0%}   F1 {s['f1']:.2f}   Accuracy {s['accuracy']:.0%}",
        f"Confusion: TP {s['TP']}  FP {s['FP']}  TN {s['TN']}  FN {s['FN']}",
    ]
    if s["analyzer"] != "bandit":
        lines.append(f"Hallucination check: dropped {s['dropped_as_hallucination']} of "
                     f"{s['raw_candidate_findings']} candidate findings")
        if s.get("rejected_by_check"):
            lines.append(f"Exploitability check: rejected {s['rejected_by_check']} findings -- turned "
                         f"{s['check_fixed_false_alarms']} false alarms into correct passes, lost "
                         f"{s['check_lost_real_catches']} real catches")
    lines.append("")
    lines.append(f"{'Category':<26}{'TP':>4}{'FN':>4}{'FP':>4}{'TN':>4}{'TPR':>7}{'FPR':>7}{'Score':>8}")
    for cat, p in s["per_category"].items():
        lines.append(f"{OWASP_NAMES[cat]:<26}{p['TP']:>4}{p['FN']:>4}{p['FP']:>4}{p['TN']:>4}"
                     f"{p['tpr']:>7.0%}{p['fpr']:>7.0%}{p['score']:>+8.2f}")
    return "\n".join(lines)


# ---------------------------------------------------------------------- scoring: compliance

def _norm(line: str) -> str:
    line = re.sub(r"^[+\-]\s*", "", line.strip())
    return re.sub(r"\s+", " ", line).strip().lower()


def locate(evidence: str, diff: str, line_hint) -> set[int]:
    """1-based diff line numbers that a finding's evidence points at."""
    diff_lines = [_norm(l) for l in diff.splitlines()]
    found: set[int] = set()
    for ev in (evidence or "").splitlines():
        ev = _norm(ev)
        if len(ev) < 4:
            continue
        hit = False
        for i, dl in enumerate(diff_lines):
            if dl and (ev == dl or (len(ev) >= 8 and ev in dl) or (len(dl) >= 8 and dl in ev)):
                found.add(i + 1)
                hit = True
        if not hit:
            best, best_i = 0.0, None
            for i, dl in enumerate(diff_lines):
                r = difflib.SequenceMatcher(None, ev, dl).ratio()
                if r > best:
                    best, best_i = r, i
            if best >= 0.85 and best_i is not None:
                found.add(best_i + 1)
    if not found and isinstance(line_hint, int):
        found.add(line_hint)
    return found


def _right_kind(f: dict, category: str) -> bool:
    return bool(finding_rule_ids(f) & COMPLIANCE_RULES[category]) or bool(finding_cwes(f) & COMPLIANCE_CWES[category])


def score_compliance_case(case: dict, state: dict) -> dict:
    diffs = {cf["path"]: cf["diff"] for cf in case["changed_files"]}
    labels = [dict(l, matched_by=None) for l in case["labels"]]
    out = []
    for idx, f in enumerate(state.get("final_findings", [])):
        diff = diffs.get(f.get("file", ""), "")
        where = locate(f.get("evidence", ""), diff, f.get("line_hint"))
        cands = [l for l in labels
                 if l["file"] == f.get("file") and any(l["span"][0] <= w <= l["span"][1] for w in where)]
        cands.sort(key=lambda l: (l["matched_by"] is not None, not _right_kind(f, l["category"]), l["optional"]))
        verdict, label = "FP", None
        if cands:
            label = cands[0]
            if label["matched_by"] is not None:
                verdict = "DUP"
            else:
                label["matched_by"] = idx
                verdict = "OPTIONAL" if label["optional"] else "TP"
        removed = bool(where) and all(diff.splitlines()[w - 1].startswith("-") for w in where
                                      if 0 < w <= len(diff.splitlines()))
        out.append({
            "file": f.get("file"), "lines": sorted(where), "rule_id": f.get("rule_id"), "cwe": f.get("cwe"),
            "severity": f.get("severity"), "evidence": f.get("evidence"), "verdict": verdict,
            "on_removed_line": removed,
            "category_correct": bool(label) and _right_kind(f, label["category"]),
        })
    return {
        "id": case["id"], "title": case["title"], "expected_gate": case["expected_gate"],
        "gate": state.get("gate_decision"),
        "labels": [{k: l[k] for k in ("file", "line", "category", "optional", "code")}
                   | {"found": l["matched_by"] is not None} for l in labels],
        "findings": out,
        "raw_findings": len(state.get("raw_findings", [])),
        "dropped_as_hallucination": len(state.get("dropped_findings", [])),
    }


def summarize_compliance(results: list[dict]) -> dict:
    req = [l for r in results for l in r["labels"] if not l["optional"]]
    fnd = [f for r in results for f in r["findings"]]
    tp = sum(f["verdict"] == "TP" for f in fnd)
    fp = sum(f["verdict"] == "FP" for f in fnd)
    tp_cat = sum(f["verdict"] == "TP" and f["category_correct"] for f in fnd)
    recall = tp / len(req) if req else 0.0
    precision = tp / (tp + fp) if tp + fp else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    per = {}
    for cat in COMPLIANCE_RULES:
        cl = [l for l in req if l["category"] == cat]
        if cl:
            per[cat] = {"found": sum(l["found"] for l in cl), "total": len(cl)}
    vuln = [r for r in results if r["expected_gate"] != "pass"]
    clean = [r for r in results if r["expected_gate"] == "pass"]
    return {
        "cases": len(results), "vulnerable_cases": len(vuln), "clean_cases": len(clean),
        "labeled_issues": len(req), "true_positives": tp, "false_positives": fp,
        "precision": round(precision, 3), "recall": round(recall, 3), "f1": round(f1, 3),
        "right_rule_family_given_found": round(tp_cat / tp, 3) if tp else 0.0,
        "per_category": per,
        "vulnerable_mrs_flagged": sum(r["gate"] != "pass" for r in vuln),
        "clean_mrs_false_alarm": sum(r["gate"] != "pass" for r in clean),
        "findings_on_removed_lines": sum(f["on_removed_line"] for f in fnd),
        "raw_candidate_findings": sum(r["raw_findings"] for r in results),
        "dropped_as_hallucination": sum(r["dropped_as_hallucination"] for r in results),
    }


def render_compliance(s: dict) -> str:
    lines = [
        f"Suite: compliance -- {s['cases']} MRs ({s['vulnerable_cases']} vulnerable, {s['clean_cases']} clean), "
        f"{s['labeled_issues']} labeled issues",
        f"Analyzer: {s['analyzer']} ({s['model']})",
        f"Recall {s['recall']:.0%} ({s['true_positives']}/{s['labeled_issues']})   "
        f"Precision {s['precision']:.0%} ({s['false_positives']} false alarms)   F1 {s['f1']:.2f}",
        f"Right rule family when found: {s['right_rule_family_given_found']:.0%}",
        f"Vulnerable MRs flagged {s['vulnerable_mrs_flagged']}/{s['vulnerable_cases']}   "
        f"Clean MRs wrongly flagged {s['clean_mrs_false_alarm']}/{s['clean_cases']}   "
        f"Findings on deleted lines {s['findings_on_removed_lines']}",
    ]
    if s["analyzer"] != "bandit":
        lines.append(f"Hallucination check: dropped {s['dropped_as_hallucination']} of "
                     f"{s['raw_candidate_findings']} candidate findings")
    lines.append("Per category: " + ", ".join(f"{k} {v['found']}/{v['total']}" for k, v in s["per_category"].items()))
    return "\n".join(lines)


# ---------------------------------------------------------------------- main

def evaluate(cases, analyzer, scorer, suite):
    """Run every case through the pipeline (or Bandit) and score it."""
    results, errors, skipped, quota_msg = [], [], 0, None
    bandit_states = run_bandit(cases) if analyzer == "bandit" else None
    for i, case in enumerate(cases, 1):
        if bandit_states is not None:
            state = bandit_states[case["id"]]
        else:
            try:
                state = run_pipeline(case, use_mock=(analyzer == "stub"))
            except QuotaExhausted as exc:
                quota_msg = str(exc)
                break
            errs = state.get("errors", [])
            quota = [e for e in errs if "429" in e or "quota" in e.lower()]
            if quota:
                quota_msg = quota[0]
                break
            if any("not fetched in batch mode" in e for e in errs):
                skipped += 1
                continue
            if errs:
                errors.append({"case": case["id"], "errors": errs})
                print(f"  !! {case['id']}: {errs[0][:160]}", flush=True)
                continue  # an incomplete review would be scored unfairly; leave it out
        r = scorer(case, state)
        results.append(r)
        if analyzer == "bandit":
            continue
        if suite == "owasp":
            tag = {"TP": "caught", "TN": "correctly ignored", "FP": "FALSE ALARM", "FN": "MISSED"}[r["outcome"]]
            print(f"  [{i:>4}/{len(cases)}] {r['id']}  {OWASP_NAMES[r['category']]:<24} "
                  f"{'real' if r['real'] else 'safe'}  -> {tag}", flush=True)
        else:
            need = [l for l in r["labels"] if not l["optional"]]
            print(f"  [{i:>4}/{len(cases)}] {r['id']}  found {sum(l['found'] for l in need)}/{len(need)}  "
                  f"false alarms {sum(f['verdict'] == 'FP' for f in r['findings'])}  {r['title']}", flush=True)
    return results, errors, skipped, quota_msg


def quota_notice(msg: str) -> str:
    limit_ids = sorted(set(re.findall(r"quotaId'?:\s*'([^']+)'", msg)))
    caps = sorted(set(re.findall(r"limit:\s*(\d+)", msg)))
    if any("PerDay" in l for l in limit_ids) or "PerDay" in msg:
        kind = "the DAILY limit -- it resets at midnight Pacific time"
    elif any("PerMinute" in l for l in limit_ids) or "PerMinute" in msg:
        kind = "the per-minute limit -- wait a minute and run again"
    else:
        kind = ("a free-tier request limit (Google didn't say which); if it happens again on the very "
                "first request after waiting a minute, it is the daily limit")
    detail = ", ".join(limit_ids) + (f" (limit {', '.join(caps)} requests)" if caps else "")
    return (f"\n!! Gemini quota reached: {kind}." + (f"\n   Limit: {detail}" if detail.strip() else "") +
            "\n   Each Gemini model has its own free quota, so a different model (set GEMINI_MODEL) or turning on "
            "billing will work right away.\n   Everything fetched so far is saved; re-running continues from here.")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--suite", choices=["owasp", "compliance"], default="owasp")
    ap.add_argument("--analyzer", choices=["gemini", "stub", "bandit"], default="stub")
    ap.add_argument("--budget", type=int, default=0,
                    help="OWASP + gemini: spend at most this many API requests on NEW cases this run, chosen "
                         "adaptively, and score everything fetched so far (grows the test set each run)")
    ap.add_argument("--batch", type=int, default=8,
                    help="gemini: files reviewed per API request (default 8; 1 = one request per file)")
    ap.add_argument("--per-class", default="5",
                    help="OWASP fixed-sample mode: cases per (category, real/safe) pair, or 'all' (default 5 -> 140)")
    ap.add_argument("--seed", type=int, default=7, help="sampling seed (keep fixed so runs are comparable)")
    ap.add_argument("--sleep", type=float, default=4.0, help="seconds to pause between Gemini requests")
    ap.add_argument("--limit", type=int, default=0, help="only run the first N cases (quick check)")
    ap.add_argument("--no-compare", action="store_true", help="skip the automatic Bandit comparison")
    ap.add_argument("--split", choices=["dev", "test"], default=None,
                    help="OWASP: dev = the 96 cases used while designing prompt v2 / the check; "
                         "test = 136 never-inspected cases for final numbers (see owasp_python/split.json)")
    ap.add_argument("--prompt", choices=sorted(llm_client.PROMPTS), default=llm_client.DEFAULT_PROMPT,
                    help="gemini: review prompt version (v1 = original, v2 = checklist + value tracing)")
    ap.add_argument("--critic", choices=["on", "off"], default="on",
                    help="gemini: run the exploitability check node (default on)")
    args = ap.parse_args()
    os.environ["REVIEW_PROMPT"] = args.prompt
    os.environ["REVIEW_CRITIC"] = args.critic

    os.environ.pop("GITLAB_TOKEN", None)  # never touch a real GitLab project while benchmarking
    scorer = score_owasp_case if args.suite == "owasp" else score_compliance_case
    stats = {"calls": 0, "cached": 0, "fetched": 0, "skipped_by_model": 0, "batch_errors": 0,
             "critic_calls": 0, "critic_fetched": 0}
    model = {"stub": "stub", "bandit": "bandit"}.get(args.analyzer, "")
    adaptive = args.analyzer == "gemini" and args.suite == "owasp" and args.budget > 0 and not args.split
    quota_msg = None
    t0 = time.time()

    if args.analyzer == "gemini":
        if not os.environ.get("GEMINI_API_KEY"):
            print('GEMINI_API_KEY is not set. In PowerShell:  $env:GEMINI_API_KEY = "your-key"', file=sys.stderr)
            return 2
        try:
            import google.genai  # noqa: F401
        except ImportError:
            print("Missing package. Run:  pip install google-genai", file=sys.stderr)
            return 2
        model = f"{llm_client.gemini_model()}, prompt {args.prompt}, check {args.critic}"
        install_gemini_cache(args.sleep, stats, allow_calls=args.batch <= 1)

    if adaptive:
        pool = load_owasp("all", args.seed)
        done = [c for c in pool if case_is_cached(c)]
        outcomes = {}
        if done:
            for c in done:
                st = run_pipeline(c, use_mock=False)
                if not st.get("errors"):
                    outcomes[c["id"]] = score_owasp_case(c, st)["flagged"]
        new = select_adaptive(pool, outcomes, args.budget * max(1, args.batch), args.seed)
        print(f"Adaptive mode: {len(done)} cases already fetched; choosing {len(new)} more where the "
              f"score is least certain ({args.budget} request(s) x {args.batch} files).", flush=True)
        if args.batch > 1:
            quota_msg = prefetch_batches(new + done, args.batch, args.sleep, stats, args.budget)
        cases = sorted(done + new, key=lambda c: c["id"])
    else:
        cases = load_owasp(args.per_class, args.seed, args.split) if args.suite == "owasp" else load_compliance()
        if args.limit:
            cases = cases[: args.limit]
        if args.analyzer == "gemini" and args.batch > 1:
            quota_msg = prefetch_batches(cases, args.batch, args.sleep, stats, args.budget)

    if quota_msg:
        print(quota_notice(quota_msg), flush=True)
    stats["cached"] = 0
    print(f"\nScoring {len(cases)} {args.suite} cases with {args.analyzer} ({model})\n", flush=True)
    results, errors, skipped, loop_quota = evaluate(cases, args.analyzer, scorer, args.suite)
    if loop_quota:
        quota_msg = quota_msg or loop_quota
        print(quota_notice(loop_quota), flush=True)

    if not results:
        print("No cases were scored yet." + (" Run again once the quota resets." if quota_msg else ""),
              file=sys.stderr)
        return 1

    s = summarize_owasp(results) if args.suite == "owasp" else summarize_compliance(results)
    s.update(analyzer=args.analyzer, model=model, suite=args.suite, partial=bool(quota_msg or skipped),
             cases_with_errors=len(errors), cases_not_fetched_yet=skipped, seconds=round(time.time() - t0, 1),
             api_requests_this_run=stats["calls"], files_fetched_this_run=stats["fetched"],
             answers_from_cache=stats["cached"], batch_size=args.batch if args.analyzer == "gemini" else None,
             mode="adaptive" if adaptive else ("split-" + args.split if args.split else "fixed"), seed=args.seed,
             prompt=args.prompt if args.analyzer == "gemini" else None,
             exploit_check=args.critic if args.analyzer == "gemini" else None,
             critic_requests=stats["critic_calls"], critic_files_fetched=stats["critic_fetched"],
             per_class=None if adaptive or args.suite != "owasp" else args.per_class)
    text = render_owasp(s) if args.suite == "owasp" else render_compliance(s)
    if args.analyzer == "gemini":
        text += (f"\nAPI usage this run: {stats['calls']} request(s) -- {stats['fetched']} new file reviews, "
                 f"{stats['critic_fetched']} new exploitability checks; {stats['cached']} answers reused from cache")
    if skipped:
        text += f"\n{skipped} selected case(s) not fetched yet (quota/skip) -- they'll be picked up next run."
    if errors:
        text += f"\n{len(errors)} case(s) left out because the analyzer errored (see the .json file)."

    comparison = None
    if args.analyzer == "gemini" and args.suite == "owasp" and not args.no_compare:
        scored_ids = {r["id"] for r in results}
        same = [c for c in cases if c["id"] in scored_ids]
        try:
            b_results, _, _, _ = evaluate(same, "bandit", scorer, args.suite)
            b = summarize_owasp(b_results)
            comparison = {k: b[k] for k in ("benchmark_score", "benchmark_score_ci95", "precision", "recall",
                                            "f1", "avg_tpr", "avg_fpr")}
            text += ("\n\nSame cases, Bandit baseline: "
                     f"score {b['benchmark_score']:+.2f} (95% CI {b['benchmark_score_ci95'][0]:+.2f} to "
                     f"{b['benchmark_score_ci95'][1]:+.2f}), precision {b['precision']:.0%}, recall {b['recall']:.0%}, "
                     f"F1 {b['f1']:.2f}")
        except SystemExit as exc:  # bandit not installed
            text += f"\n\n(Bandit comparison skipped: {str(exc)[:80]})"

    RESULTS_DIR.mkdir(exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    tag = f"{args.suite}{'-' + args.split if args.split else ''}_{args.analyzer}"
    if args.analyzer == "gemini":
        tag += f"-{args.prompt}{'-check' if args.critic == 'on' else ''}"
    base = RESULTS_DIR / f"{tag}_{stamp}"
    base.with_suffix(".json").write_text(json.dumps(
        {"summary": s, "bandit_same_cases": comparison, "errors": errors, "cases": results}, indent=2),
        encoding="utf-8")
    md = [f"# {args.suite} benchmark: {args.analyzer} ({model})", "", "```", text, "```", ""]
    if args.suite == "owasp":
        for kind, title in (("FN", "Missed real vulnerabilities"), ("FP", "False alarms on safe code")):
            md += [f"## {title}", ""]
            md += [f"- {r['id']} ({r['test']}) {OWASP_NAMES[r['category']]}" for r in results if r["outcome"] == kind]
            md.append("")
    else:
        md += ["## Misses", ""]
        md += [f"- **{r['id']}** `{l['file']}:{l['line']}` ({l['category']}): `{l['code']}`"
               for r in results for l in r["labels"] if not l["found"] and not l["optional"]]
        md += ["", "## False alarms", ""]
        md += [f"- **{r['id']}** `{f['file']}` {f['rule_id']}: `{(f['evidence'] or '')[:120]}`"
               for r in results for f in r["findings"] if f["verdict"] == "FP"]
    base.with_suffix(".md").write_text("\n".join(md) + "\n", encoding="utf-8")

    print("\n" + text)
    print(f"\nSaved: {base.with_suffix('.md')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
