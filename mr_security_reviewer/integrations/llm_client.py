"""LLM access for the analysis node, backed by Google Gemini.

Uses the supported `google-genai` SDK (`pip install google-genai`). The older
`google-generativeai` package is deprecated and `gemini-2.0-flash` was shut down
on 2026-06-01, so the model is configurable:

    GEMINI_API_KEY   required for live analysis
    GEMINI_MODEL     optional, defaults to DEFAULT_MODEL below

In demo mode (no GEMINI_API_KEY, or use_mock=True) this falls back to a
deterministic, pattern-based stub analyzer so the graph runs end-to-end
without any credentials or network access. The stub always quotes evidence
verbatim from the diff, so the verify node has something real to ground against.
"""

from __future__ import annotations

import json
import os
import re
import time
from typing import Any

DEFAULT_MODEL = "gemini-3.6-flash"

PROMPT_V1 = """You are an application security reviewer checking one file from a \
GitLab merge request against PCI-DSS, SOC 2 and OWASP Top 10 requirements.

How to read the input:
- The diff uses unified-diff markers: lines starting with "+" are added, "-" are \
removed, and " " are unchanged context. Review the code as it will exist AFTER the \
merge (added and context lines). Never report code that appears only on removed lines.
- "Related repository files", when present, are other files the changed code imports. \
Use them to understand what helper functions really return; do not report issues in them.

What to report:
- Report a finding only when you can point to a specific line and explain concretely \
why it is exploitable or non-compliant: how untrusted input (request parameters, \
headers, cookies, form or JSON bodies) reaches a dangerous operation, or why a \
construct is insecure on its own (hardcoded secret, weak algorithm, sensitive data in \
logs, plaintext transport, missing access control).
- Follow the data flow. If the value reaching the dangerous operation is a constant, \
is replaced by a constant before use, comes from a helper that returns a fixed value, \
or is properly parameterized, escaped or validated, it is NOT a vulnerability.
- One finding per distinct issue. Do not report style problems or speculative risks.

Return ONLY a JSON array (no markdown, no prose). Each element is an object with \
exactly these fields:
  framework: "PCI-DSS" | "SOC2" | "OWASP"
  rule_id: one of the provided rule ids
  rule_title: that rule's title
  cwe: integer, the most specific CWE id for the issue (e.g. 89 for SQL injection)
  line_hint: integer line number within the diff, or null
  evidence: the single most relevant line, copied EXACTLY character-for-character \
from the diff without the leading +/space marker. Never paraphrase it; it is used to \
verify you are not hallucinating.
  explanation: 1-2 sentences on why this violates the rule
  severity: "critical" | "high" | "medium" | "low"
  confidence: number between 0 and 1

If there are no issues, return [].
"""

# v2: same output contract; adds (1) an explicit checklist of what counts as each issue type,
# written from general secure-coding knowledge, and (2) a required value trace before reporting.
PROMPT_V2 = """You are an application security reviewer checking one file from a \
GitLab merge request against PCI-DSS, SOC 2 and OWASP Top 10 requirements.

How to read the input:
- The diff uses unified-diff markers: lines starting with "+" are added, "-" are \
removed, and " " are unchanged context. Review the code as it will exist AFTER the \
merge (added and context lines). Never report code that appears only on removed lines.
- "Related repository files", when present, are other files the changed code imports. \
Use them to learn what helper functions really return; do not report issues in them.

Step 1 -- find candidate issues. Check every handler for each of these:
- Injection (CWE-89 SQL, 78 OS command, 94/95 code via eval/exec, 90 LDAP, 643 XPath): \
untrusted input reaches a query, shell command, interpreter or filter string by \
concatenation/formatting instead of parameters or argument lists.
- Cross-site scripting (CWE-79): untrusted input is placed into an HTTP response body \
(a returned string, make_response, render_template_string, Markup, f-strings building HTML) \
without HTML escaping. In Flask, returning a plain str from a view sends it as HTML, so \
returning request-derived text unescaped IS XSS. Values passed through a real HTML \
escaping function (html.escape, markupsafe.escape, a helper that escapes) are safe.
- Path traversal (CWE-22): untrusted input used in a file path (open, codecs.open, \
os.path.join, send_file, remove) without normalizing and confining it.
- Open redirect (CWE-601): redirect() to a URL taken from the request without an allow-list.
- Insecure deserialization (CWE-502): pickle/marshal/shelve/jsonpickle or yaml.load \
without SafeLoader applied to untrusted bytes.
- XML external entities (CWE-611): an XML parser configured to resolve entities or load \
external DTDs (e.g. lxml resolve_entities=True, no_network=False, xml.sax feature_external_ges) \
parsing untrusted XML. Default-safe parsers and defusedxml are fine.
- Weak hashing (CWE-328): MD5 or SHA-1 used for passwords or other security purposes.
- Weak randomness (CWE-330): the `random` module (random(), randint, choice, getrandbits, \
uniform...) generating values used as tokens, ids, cookie or session values, passwords or \
keys. `secrets`, os.urandom and random.SystemRandom are fine.
- Trust boundary violation (CWE-501): untrusted request data stored into a trusted store \
such as the server-side session.
- Insecure cookie (CWE-614): set_cookie for a sensitive value without secure=True \
(and httponly=True).
- Also: hardcoded secrets (798), sensitive data in logs (532), plaintext transport or \
disabled TLS verification (319/295), missing authentication/authorization or IDOR (862/639).

Step 2 -- before reporting any issue that depends on untrusted input, trace the exact value \
that reaches the dangerous operation. Walk through every assignment in order; evaluate \
conditions and arithmetic whose operands are constants; track which list/dict/config entry \
is actually read back; and check what helper functions return. If the value that finally \
reaches the operation is a constant or otherwise not attacker-controlled, or it is properly \
parameterized/escaped/validated, it is NOT a vulnerability -- do not report it. Issues that do \
not depend on input (weak algorithm, hardcoded secret, insecure flag) only need the construct \
to be present and used for a security-relevant purpose.

Report one finding per distinct issue. No style problems or speculative risks.

Return ONLY a JSON array (no markdown, no prose). Each element is an object with \
exactly these fields:
  framework: "PCI-DSS" | "SOC2" | "OWASP"
  rule_id: one of the provided rule ids
  rule_title: that rule's title
  cwe: integer, the most specific CWE id for the issue (e.g. 89 for SQL injection)
  line_hint: integer line number within the diff, or null
  evidence: the single most relevant line, copied EXACTLY character-for-character \
from the diff without the leading +/space marker. Never paraphrase it; it is used to \
verify you are not hallucinating.
  explanation: 1-2 sentences on why this violates the rule, including the source-to-sink path
  severity: "critical" | "high" | "medium" | "low"
  confidence: number between 0 and 1

If there are no issues, return [].
"""

PROMPTS = {"v1": PROMPT_V1, "v2": PROMPT_V2}
DEFAULT_PROMPT = "v2"


def prompt_version() -> str:
    v = os.environ.get("REVIEW_PROMPT", DEFAULT_PROMPT)
    if v not in PROMPTS:
        raise LLMError(f"Unknown REVIEW_PROMPT {v!r}; choose one of {sorted(PROMPTS)}")
    return v


def system_prompt() -> str:
    return PROMPTS[prompt_version()]


SYSTEM_PROMPT = PROMPT_V2  # backwards-compatible name for the default prompt

_SEVERITIES = {"critical", "high", "medium", "low"}
_FRAMEWORKS = {"PCI-DSS", "SOC2", "OWASP"}


class LLMError(RuntimeError):
    """Raised when the model call fails or returns something unusable, so the
    analyze node records it instead of silently reporting 'no findings'."""


def gemini_model() -> str:
    return os.environ.get("GEMINI_MODEL", DEFAULT_MODEL)


def _use_real_gemini() -> bool:
    return bool(os.environ.get("GEMINI_API_KEY"))


def analyze_file(
    file_path: str,
    diff: str,
    relevant_rules: dict[str, list[dict[str, Any]]],
    use_mock: bool,
    context_files: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    if not use_mock and _use_real_gemini():
        return _analyze_with_gemini(file_path, diff, relevant_rules, context_files or {})
    return _analyze_with_stub(file_path, diff, relevant_rules)


# --- Gemini --------------------------------------------------------------------

def _format_rules(relevant_rules: dict[str, list[dict[str, Any]]]) -> str:
    out = []
    for framework, rules in relevant_rules.items():
        for r in rules:
            cwes = ", ".join(f"CWE-{c}" for c in r.get("cwe", []))
            out.append(f"- {r['rule_id']} ({framework}) {r['title']} [{cwes}]: {r['text']}")
    return "\n".join(out)


def build_user_prompt(
    file_path: str,
    diff: str,
    relevant_rules: dict[str, list[dict[str, Any]]],
    context_files: dict[str, str] | None = None,
) -> str:
    numbered = "\n".join(f"{i:>4}| {line}" for i, line in enumerate(diff.splitlines(), 1))
    parts = [f"File: {file_path}", "", "Diff (line number | diff line):", "```", numbered, "```", ""]
    if context_files:
        parts.append("Related repository files (read-only context, do not review):")
        for path, src in context_files.items():
            parts += [f"--- {path} ---", "```", src.rstrip(), "```"]
        parts.append("")
    parts += ["Compliance rules:", _format_rules(relevant_rules)]
    return "\n".join(parts)


# Structured-output schemas: Gemini's constrained decoding then always returns valid JSON,
# even when the evidence it copies contains characters like \' that are illegal in JSON.
FINDING_SCHEMA: dict[str, Any] = {
    "type": "OBJECT",
    "properties": {
        "framework": {"type": "STRING", "enum": ["PCI-DSS", "SOC2", "OWASP"]},
        "rule_id": {"type": "STRING"},
        "rule_title": {"type": "STRING"},
        "cwe": {"type": "INTEGER"},
        "line_hint": {"type": "INTEGER", "nullable": True},
        "evidence": {"type": "STRING"},
        "explanation": {"type": "STRING"},
        "severity": {"type": "STRING", "enum": ["critical", "high", "medium", "low"]},
        "confidence": {"type": "NUMBER"},
    },
    "required": ["framework", "rule_id", "cwe", "evidence", "explanation", "severity"],
}
SINGLE_SCHEMA: dict[str, Any] = {"type": "ARRAY", "items": FINDING_SCHEMA}
BATCH_SCHEMA: dict[str, Any] = {
    "type": "OBJECT",
    "properties": {"files": {"type": "ARRAY", "items": {
        "type": "OBJECT",
        "properties": {"file": {"type": "STRING"}, "findings": {"type": "ARRAY", "items": FINDING_SCHEMA}},
        "required": ["file", "findings"],
    }}},
    "required": ["files"],
}

_VALID_ESCAPES = set('"\\/bfnrtu')


def _repair_escapes(text: str) -> str:
    """Double any backslash that doesn't start a legal JSON escape (e.g. \' copied from code)."""
    return re.sub(r"\\(.)", lambda m: m.group(0) if m.group(1) in _VALID_ESCAPES else "\\\\" + m.group(1),
                  text, flags=re.S)


def loads_lenient(text: str) -> Any:
    """json.loads, then retry with escape repair. Raises json.JSONDecodeError if still invalid."""
    text = re.sub(r"^\s*```(?:json)?\s*|\s*```\s*$", "", text.strip())
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return json.loads(_repair_escapes(text))


def salvage_batch(text: str) -> list[dict[str, Any]]:
    """Recover every complete {"file": ..., "findings": [...]} entry from a reply that is
    truncated or broken further on, so one bad entry doesn't waste the whole request."""
    text = _repair_escapes(text)
    m = re.search(r'"files"\s*:\s*\[', text)
    if not m:
        return []
    dec, pos, out = json.JSONDecoder(), m.end(), []
    while True:
        while pos < len(text) and text[pos] in " \t\r\n,":
            pos += 1
        if pos >= len(text) or text[pos] != "{":
            break
        try:
            obj, pos = dec.raw_decode(text, pos)
        except json.JSONDecodeError:
            break
        if isinstance(obj, dict):
            out.append(obj)
    return out


def _call_gemini(prompt: str, max_attempts: int = 7, system_prompt: str | None = None,
                 schema: dict[str, Any] | None = None) -> str:
    try:
        from google import genai
        from google.genai import errors, types
    except ImportError as exc:  # pragma: no cover - depends on the user's install
        raise LLMError("google-genai is not installed. Run: pip install google-genai") from exc

    client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
    config = types.GenerateContentConfig(
        system_instruction=system_prompt or globals()["system_prompt"](),
        temperature=0.0,
        response_mime_type="application/json",
        response_schema=types.Schema.model_validate(schema or SINGLE_SCHEMA),
    )

    delay = 5.0
    for attempt in range(1, max_attempts + 1):
        try:
            resp = client.models.generate_content(model=gemini_model(), contents=prompt, config=config)
            return resp.text or ""
        except errors.APIError as exc:
            code = getattr(exc, "code", None)
            msg = str(exc)
            if code == 404:
                raise LLMError(
                    f"Model '{gemini_model()}' was not found for this API key. "
                    "Set GEMINI_MODEL to a model listed at https://ai.google.dev/gemini-api/docs/models"
                ) from exc
            if code in (401, 403) or "API key not valid" in msg or "API_KEY_INVALID" in msg:
                raise LLMError(f"Gemini rejected the API key ({code}): it is mistyped, deleted, or a "
                               "placeholder. Check GEMINI_API_KEY.") from exc
            daily = "PerDay" in msg or "per day" in msg.lower()
            retryable = code in (429, 500, 502, 503, 504) and not daily
            if not retryable or attempt == max_attempts:
                raise LLMError(f"Gemini API error {code}: {msg[:400]}") from exc
            m = re.search(r"retry in ([\d.]+)s|'retryDelay': '(\d+)s'", msg)
            wait = float(next(g for g in m.groups() if g)) + 1 if m else delay
            time.sleep(min(wait, 120))  # 503 "high demand" usually clears within a minute or two
            delay *= 2
        except Exception as exc:  # network/proxy/timeouts: retry, then report clearly
            if attempt == max_attempts:
                raise LLMError(f"Could not reach Gemini ({type(exc).__name__}: {str(exc)[:200]})") from exc
            time.sleep(delay)
            delay *= 2
    raise LLMError("unreachable")


def _parse_findings(text: str) -> list[dict[str, Any]]:
    try:
        data = loads_lenient(text)
    except json.JSONDecodeError as exc:
        raise LLMError(f"Model returned invalid JSON: {text[:200]!r}") from exc
    if isinstance(data, dict):  # tolerate {"findings": [...]}
        data = data.get("findings", [])
    if not isinstance(data, list):
        raise LLMError(f"Model returned {type(data).__name__}, expected a JSON array")
    return [d for d in data if isinstance(d, dict)]


def _coerce_int(v: Any) -> int | None:
    if isinstance(v, int):
        return v
    m = re.search(r"\d+", str(v or ""))
    return int(m.group()) if m else None


def normalize_finding(f: dict[str, Any], file_path: str) -> dict[str, Any]:
    """Make model output safe for the downstream nodes (missing/odd fields)."""
    severity = str(f.get("severity", "medium")).lower()
    framework = str(f.get("framework", "OWASP"))
    framework = {"SOC 2": "SOC2", "PCI DSS": "PCI-DSS", "PCI": "PCI-DSS"}.get(framework, framework)
    try:
        confidence = float(f.get("confidence", 0.5))
    except (TypeError, ValueError):
        confidence = 0.5
    return {
        "framework": framework if framework in _FRAMEWORKS else "OWASP",
        "rule_id": str(f.get("rule_id", "")),
        "rule_title": str(f.get("rule_title", "")),
        "cwe": _coerce_int(f.get("cwe")),
        "file": file_path,
        "line_hint": _coerce_int(f.get("line_hint")),
        "evidence": str(f.get("evidence", "")),
        "explanation": str(f.get("explanation", "")),
        "severity": severity if severity in _SEVERITIES else "medium",
        "confidence": max(0.0, min(1.0, confidence)),
    }


def _analyze_with_gemini(
    file_path: str,
    diff: str,
    relevant_rules: dict[str, list[dict[str, Any]]],
    context_files: dict[str, str],
) -> list[dict[str, Any]]:
    prompt = build_user_prompt(file_path, diff, relevant_rules, context_files)
    return [normalize_finding(f, file_path) for f in _parse_findings(_call_gemini(prompt))]


# --- Batched review (several files per API request) -------------------------

BATCH_ADDENDUM = """

BATCH MODE: you will receive several independent files, each under its own \
"=== FILE: <path> ===" header. Review each file on its own; never let one file \
influence your judgment of another. Return ONLY a JSON object of the form
  {"files": [{"file": "<path exactly as given>", "findings": [ ...finding objects as above... ]}, ...]}
with exactly one entry per file, in the same order, using [] for files with no issues."""


def build_batch_prompt(items: list[dict[str, Any]], rules: dict[str, list[dict[str, Any]]]) -> str:
    """items: [{"path", "diff", "context_files"}]. Shared rules and related files are sent once."""
    related: dict[str, str] = {}
    for it in items:
        related.update(it.get("context_files") or {})
    parts = []
    if related:
        parts.append("Related repository files (read-only context, shared by all files below, do not review):")
        for path, src in related.items():
            parts += [f"--- {path} ---", "```", src.rstrip(), "```"]
        parts.append("")
    parts += ["Compliance rules:", _format_rules(rules), ""]
    for it in items:
        numbered = "\n".join(f"{i:>4}| {line}" for i, line in enumerate(it["diff"].splitlines(), 1))
        parts += [f"=== FILE: {it['path']} ===", "Diff (line number | diff line):", "```", numbered, "```", ""]
    return "\n".join(parts)


def analyze_batch(
    items: list[dict[str, Any]], rules: dict[str, list[dict[str, Any]]]
) -> dict[str, list[dict[str, Any]]]:
    """Review several files with ONE Gemini request. Returns {path: findings} for every
    file the model answered; files it skipped are simply absent (the caller retries them)."""
    text = _call_gemini(build_batch_prompt(items, rules), system_prompt=system_prompt() + BATCH_ADDENDUM,
                        schema=BATCH_SCHEMA)
    try:
        data = loads_lenient(text)
        entries = data.get("files", []) if isinstance(data, dict) else data
    except json.JSONDecodeError:
        entries = salvage_batch(text)  # keep every complete entry; the rest get retried
        if not entries:
            raise LLMError(f"Model returned invalid JSON for a batch: {text[:200]!r}")
    wanted = {it["path"] for it in items}
    out: dict[str, list[dict[str, Any]]] = {}
    for e in entries if isinstance(entries, list) else []:
        if not isinstance(e, dict) or e.get("file") not in wanted:
            continue
        findings = e.get("findings", [])
        out[e["file"]] = [normalize_finding(f, e["file"]) for f in findings if isinstance(f, dict)]
    return out


# --- Exploitability check (second-pass critic) --------------------------------

CRITIC_PROMPT = """You are a senior application security engineer double-checking findings \
that another reviewer reported on one file of a merge request. Most false alarms come from \
reporting a dangerous-looking call whose input is not actually attacker-controlled.

For EACH finding, independently:
1. Name the attacker-controlled source (request parameter, header, cookie, body, uploaded \
file), or "none" if the issue does not depend on input.
2. Trace the value step by step from the source to the line in the finding: every \
assignment, branch, list/dict/config read and helper call in order. Evaluate conditions and \
arithmetic on constants to see which branch really runs, and use the related repository \
files to see what helpers return.
3. Decide:
   - "confirmed" if attacker-controlled data reaches that operation in a dangerous form, or \
the issue does not depend on input and the insecure construct is really present and used for \
a security-relevant purpose.
   - "rejected" if the value reaching the operation is a constant or otherwise not \
attacker-controlled, if it is properly parameterized/escaped/validated first, if the code is \
unreachable, or if the finding misreads the code.

Diff markers: "+" added, "-" removed, " " context; judge the code as it is after the merge.
Return ONLY a JSON array with one object per finding, in the same order, each with fields: \
id (as given), source, trace (the step-by-step trace), verdict ("confirmed" | "rejected"), \
reason (one sentence)."""

CRITIC_ITEM_SCHEMA: dict[str, Any] = {
    "type": "OBJECT",
    "properties": {
        "id": {"type": "STRING"},
        "source": {"type": "STRING"},
        "trace": {"type": "STRING"},
        "verdict": {"type": "STRING", "enum": ["confirmed", "rejected"]},
        "reason": {"type": "STRING"},
    },
    "required": ["id", "trace", "verdict", "reason"],
}
CRITIC_SCHEMA: dict[str, Any] = {"type": "ARRAY", "items": CRITIC_ITEM_SCHEMA}
CRITIC_BATCH_SCHEMA: dict[str, Any] = {
    "type": "OBJECT",
    "properties": {"files": {"type": "ARRAY", "items": {
        "type": "OBJECT",
        "properties": {"file": {"type": "STRING"}, "verdicts": {"type": "ARRAY", "items": CRITIC_ITEM_SCHEMA}},
        "required": ["file", "verdicts"],
    }}},
    "required": ["files"],
}
CRITIC_BATCH_ADDENDUM = """

BATCH MODE: several independent files follow, each under "=== FILE: <path> ===" with its own \
findings. Judge each file on its own. Return ONLY a JSON object \
{"files": [{"file": "<path exactly as given>", "verdicts": [ ...one per finding, same order... ]}]}."""

CRITIC_FIELDS = ("framework", "rule_id", "cwe", "evidence", "explanation", "severity")


def critic_enabled() -> bool:
    return os.environ.get("REVIEW_CRITIC", "on").lower() not in ("off", "0", "false", "no")


def critic_view(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The stable part of each finding that the critic sees (ids f1, f2, ... by position)."""
    return [{"id": f"f{i}", **{k: f.get(k) for k in CRITIC_FIELDS}} for i, f in enumerate(findings, 1)]


def _critic_block(path: str, diff: str, findings: list[dict[str, Any]]) -> list[str]:
    numbered = "\n".join(f"{i:>4}| {line}" for i, line in enumerate(diff.splitlines(), 1))
    return [f"=== FILE: {path} ===", "Diff (line number | diff line):", "```", numbered, "```",
            "Findings to check:", json.dumps(critic_view(findings), indent=1), ""]


def _related_block(context_files: dict[str, str]) -> list[str]:
    if not context_files:
        return []
    out = ["Related repository files (read-only context):"]
    for p, src in context_files.items():
        out += [f"--- {p} ---", "```", src.rstrip(), "```"]
    return out + [""]


def _verdicts_in_order(raw: list[Any], n: int) -> list[dict[str, Any]]:
    by_id = {str(v.get("id")): v for v in raw if isinstance(v, dict)}
    out = []
    for i in range(1, n + 1):
        v = by_id.get(f"f{i}")
        if v is None and len(raw) == n and isinstance(raw[i - 1], dict):
            v = raw[i - 1]
        verdict = str((v or {}).get("verdict", "confirmed")).lower()
        out.append({
            "verdict": "rejected" if verdict == "rejected" else "confirmed",  # fail open
            "reason": str((v or {}).get("reason", "no verdict returned; kept")),
            "trace": str((v or {}).get("trace", "")),
        })
    return out


def critique_file(path: str, diff: str, findings: list[dict[str, Any]],
                  context_files: dict[str, str] | None, use_mock: bool) -> list[dict[str, Any]]:
    """One verdict per finding, same order. Demo mode / critic off: everything confirmed."""
    if not findings:
        return []
    if use_mock or not _use_real_gemini() or not critic_enabled():
        return [{"verdict": "confirmed", "reason": "exploitability check not run", "trace": ""} for _ in findings]
    prompt = "\n".join(_related_block(context_files or {}) + _critic_block(path, diff, findings))
    text = _call_gemini(prompt, system_prompt=CRITIC_PROMPT, schema=CRITIC_SCHEMA)
    try:
        raw = loads_lenient(text)
    except json.JSONDecodeError as exc:
        raise LLMError(f"Critic returned invalid JSON: {text[:200]!r}") from exc
    return _verdicts_in_order(raw if isinstance(raw, list) else [], len(findings))


def critique_batch(items: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """items: [{"path", "diff", "findings", "context_files"}] -> {path: verdicts} with ONE request."""
    related: dict[str, str] = {}
    for it in items:
        related.update(it.get("context_files") or {})
    lines = _related_block(related)
    for it in items:
        lines += _critic_block(it["path"], it["diff"], it["findings"])
    text = _call_gemini("\n".join(lines), system_prompt=CRITIC_PROMPT + CRITIC_BATCH_ADDENDUM,
                        schema=CRITIC_BATCH_SCHEMA)
    try:
        data = loads_lenient(text)
        entries = data.get("files", []) if isinstance(data, dict) else data
    except json.JSONDecodeError:
        entries = salvage_batch(text)
        if not entries:
            raise LLMError(f"Critic returned invalid JSON for a batch: {text[:200]!r}")
    wanted = {it["path"]: len(it["findings"]) for it in items}
    out = {}
    for e in entries if isinstance(entries, list) else []:
        if isinstance(e, dict) and e.get("file") in wanted:
            out[e["file"]] = _verdicts_in_order(e.get("verdicts") or [], wanted[e["file"]])
    return out


# --- Deterministic stub analyzer (demo mode) -------------------------------

_PATTERNS: list[dict[str, Any]] = [
    {
        "regex": re.compile(r'(?i)(api[_-]?key|secret[_-]?key|password)\s*=\s*["\'][^"\']{6,}["\']'),
        "framework": "PCI-DSS",
        "rule_id": "PCI-DSS-3.4",
        "rule_title": "Protect stored authentication credentials",
        "cwe": 798,
        "explanation": "A credential/secret is hardcoded in source rather than pulled from a secrets manager or environment variable.",
        "severity": "critical",
    },
    {
        "regex": re.compile(r'(?i)(select|insert|update|delete)\b.{0,80}["\']\s*\+\s*\w+'),
        "framework": "OWASP",
        "rule_id": "OWASP-A03",
        "rule_title": "Injection",
        "cwe": 89,
        "explanation": "SQL is built via string concatenation with untrusted input, enabling SQL injection.",
        "severity": "critical",
    },
    {
        "regex": re.compile(r'(?i)(print|log(ger)?\.\w+)\([^)]*\b(card[_-]?number|cvv|pan)\b'),
        "framework": "PCI-DSS",
        "rule_id": "PCI-DSS-3.3",
        "rule_title": "Mask/never log full cardholder data",
        "cwe": 532,
        "explanation": "Cardholder data (card number/CVV) is written to logs in plaintext.",
        "severity": "critical",
    },
    {
        "regex": re.compile(r'(?i)\b(md5|sha1)\s*\('),
        "framework": "OWASP",
        "rule_id": "OWASP-A02",
        "rule_title": "Cryptographic Failures",
        "cwe": 328,
        "explanation": "A broken/weak hash algorithm is used where a modern password hash (e.g. bcrypt/argon2) is required.",
        "severity": "high",
    },
    {
        "regex": re.compile(r'(?i)http://[^\s"\']*'),
        "framework": "PCI-DSS",
        "rule_id": "PCI-DSS-4.1",
        "rule_title": "Encrypt transmission of cardholder data across open, public networks",
        "cwe": 319,
        "explanation": "Data is transmitted over plaintext HTTP instead of TLS.",
        "severity": "high",
    },
]

_AUTH_HINTS = re.compile(r'(?i)(login_required|authenticated|check_auth|require_auth|permission|token_required|@auth)')
_ROUTE_LINE = re.compile(r'(?i)@app\.route\(|@router\.(get|post|put|delete)\(')
_DEF_LINE = re.compile(r'^\+?\s*def\s+\w+\(')
_REQUEST_INPUT = re.compile(r'(?i)request\.(args|form|json|get_json)')


def _check_missing_auth(file_path: str, lines: list[str]) -> list[dict[str, Any]]:
    """Heuristic: a route handler that reads request input with no nearby auth check."""
    findings: list[dict[str, Any]] = []
    for i, line in enumerate(lines):
        if line.startswith("-") or not _ROUTE_LINE.search(line):
            continue
        def_idx = None
        for k in range(i, min(i + 6, len(lines))):
            if _DEF_LINE.search(lines[k]):
                def_idx = k
                break
        if def_idx is None:
            continue
        window_end = len(lines)
        for j in range(def_idx + 1, len(lines)):
            if _ROUTE_LINE.search(lines[j]) or _DEF_LINE.search(lines[j]):
                window_end = j
                break
        window_text = "\n".join(lines[i:window_end])
        if not _REQUEST_INPUT.search(window_text) or _AUTH_HINTS.search(window_text):
            continue
        evidence = line.strip().lstrip("+").strip()
        if not evidence:
            continue
        findings.append(
            {
                "framework": "SOC2",
                "rule_id": "SOC2-CC6.1",
                "rule_title": "Logical access controls restrict unauthorized access",
                "cwe": 862,
                "file": file_path,
                "line_hint": i + 1,
                "evidence": evidence,
                "explanation": "This endpoint reads request input but no authentication/authorization check is visible in the diff.",
                "severity": "medium",
                "confidence": 0.7,
            }
        )
    return findings


def _analyze_with_stub(
    file_path: str, diff: str, relevant_rules: dict[str, list[dict[str, Any]]]
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    lines = diff.splitlines()

    for pattern in _PATTERNS:
        for i, line in enumerate(lines):
            if line.startswith("-"):  # removed code is going away; don't flag it
                continue
            if not pattern["regex"].search(line):
                continue
            evidence = line.strip().lstrip("+").strip()
            if not evidence:
                continue
            findings.append(
                {
                    "framework": pattern["framework"],
                    "rule_id": pattern["rule_id"],
                    "rule_title": pattern["rule_title"],
                    "cwe": pattern["cwe"],
                    "file": file_path,
                    "line_hint": i + 1,
                    "evidence": evidence,
                    "explanation": pattern["explanation"],
                    "severity": pattern["severity"],
                    "confidence": 0.9,
                }
            )

    findings.extend(_check_missing_auth(file_path, lines))
    return findings
