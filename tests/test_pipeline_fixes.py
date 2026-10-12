"""Tests for the live-Gemini path (with the API call faked) and the pipeline fixes."""

import json

import pytest

from mr_security_reviewer.integrations import gitlab_client, llm_client
from mr_security_reviewer.nodes.context import context_node
from mr_security_reviewer.nodes.verify import verify_node
from mr_security_reviewer.graph import run_review


def test_verify_rejects_evidence_that_only_exists_on_removed_lines():
    state = {
        "changed_files": [{
            "path": "db.py",
            "diff": '-    query = "SELECT * FROM users WHERE id = " + user_id\n'
                    '+    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))\n',
        }],
        "raw_findings": [{
            "file": "db.py",
            "evidence": 'query = "SELECT * FROM users WHERE id = " + user_id',
            "severity": "critical",
        }],
    }
    out = verify_node(state)
    assert out["verified_findings"] == []
    assert "removed line" in out["dropped_findings"][0]["verification_note"]


def test_verify_pins_line_hint_to_the_grounded_line():
    state = {
        "changed_files": [{"path": "a.py", "diff": "+import os\n+\n+token = os.environ['T']\n+print(token)\n"}],
        "raw_findings": [{"file": "a.py", "evidence": "print(token)", "line_hint": 99, "severity": "high"}],
    }
    out = verify_node(state)
    assert out["verified_findings"][0]["line_hint"] == 4


def test_context_sends_every_rule_and_imported_related_files():
    state = {
        "changed_files": [{"path": "views.py", "diff": "+import helpers.utils\n+x = 1\n"}],
        "context_files": {"helpers/utils.py": "def f(): return 1", "helpers/other.py": "y = 2"},
    }
    out = context_node(state)
    rules = out["relevant_rules"]["views.py"]
    ids = {r["rule_id"] for fw in rules.values() for r in fw}
    assert {"OWASP-A01", "OWASP-A03", "OWASP-A08", "SOC2-CC6.1", "PCI-DSS-3.3"} <= ids
    assert list(out["file_context"]["views.py"]) == ["helpers/utils.py"]


def test_gemini_path_end_to_end_with_faked_model(monkeypatch):
    """Messy model output: string CWE, odd severity casing, a hallucinated quote."""
    fake = [
        {"framework": "OWASP", "rule_id": "OWASP-A03", "rule_title": "Injection", "cwe": "CWE-89",
         "line_hint": "9", "evidence": 'query = "SELECT * FROM users WHERE id = " + user_id',
         "explanation": "SQL built from input.", "severity": "CRITICAL", "confidence": "0.9"},
        {"framework": "SOC 2", "rule_id": "SOC2-CC6.1", "rule_title": "Access", "cwe": 862,
         "evidence": "def delete_everything(request):", "explanation": "made up", "severity": "high"},
    ]
    calls = []

    def fake_call(prompt, max_attempts=4):
        calls.append(prompt)
        return json.dumps(fake) if "auth/db.py" in prompt else "[]"

    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.delenv("GITLAB_TOKEN", raising=False)
    monkeypatch.setattr(llm_client, "_call_gemini", fake_call)

    result = run_review(project="demo", mr_id="1", use_mock=False)

    assert len(calls) == 3  # one call per changed file
    assert "Compliance rules:" in calls[0] and "   1| " in calls[0]  # rules + numbered diff
    finals = result["final_findings"]
    assert len(finals) == 1
    assert finals[0]["cwe"] == 89 and finals[0]["severity"] == "critical" and finals[0]["line_hint"] == 9
    assert len(result["dropped_findings"]) == 1  # the fabricated quote
    assert result["dropped_findings"][0]["framework"] == "SOC2"
    assert result["gate_decision"] == "block"
    assert "CWE-89" in result["report_markdown"]


def test_model_errors_are_reported_not_silently_empty(monkeypatch):
    def broken(prompt, max_attempts=4):
        raise llm_client.LLMError("Gemini API error 429: quota")

    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.delenv("GITLAB_TOKEN", raising=False)
    monkeypatch.setattr(llm_client, "_call_gemini", broken)

    result = run_review(project="demo", mr_id="1", use_mock=False)
    assert len(result["errors"]) == 3
    assert "could not be analyzed" in result["report_markdown"]


def test_invalid_json_from_model_raises():
    with pytest.raises(llm_client.LLMError):
        llm_client._parse_findings("Sure! Here are the findings: ...")
    assert llm_client._parse_findings('```json\n{"findings": []}\n```') == []


def test_batch_review_parses_per_file_answers_and_tolerates_skips(monkeypatch):
    seen = {}

    def fake_call(prompt, max_attempts=7, system_prompt=None, schema=None):
        seen["schema"] = schema
        seen["prompt"], seen["system"] = prompt, system_prompt
        return json.dumps({"files": [
            {"file": "a.py", "findings": [{"rule_id": "OWASP-A03", "cwe": "89", "evidence": "x", "severity": "HIGH"}]},
            {"file": "not-requested.py", "findings": []},
        ]})

    monkeypatch.setattr(llm_client, "_call_gemini", fake_call)
    items = [{"path": "a.py", "diff": "+x\n", "context_files": {"helpers/u.py": "def u(): pass"}},
             {"path": "b.py", "diff": "+y\n", "context_files": {"helpers/u.py": "def u(): pass"}}]
    out = llm_client.analyze_batch(items, {"OWASP": []})
    assert set(out) == {"a.py"}  # b.py skipped by the model -> absent, so the caller retries it
    assert out["a.py"][0]["cwe"] == 89 and out["a.py"][0]["severity"] == "high"
    assert "BATCH MODE" in seen["system"]
    assert seen["prompt"].count("--- helpers/u.py ---") == 1  # shared context sent once
    assert "=== FILE: a.py ===" in seen["prompt"] and "=== FILE: b.py ===" in seen["prompt"]


def test_adaptive_selection_prefers_uncertain_groups():
    import importlib.util, pathlib
    spec = importlib.util.spec_from_file_location(
        "run_benchmark", pathlib.Path(__file__).resolve().parent.parent / "benchmark" / "run_benchmark.py")
    rb = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rb)

    def mk(i, cat, real):
        return {"id": f"c{i:03}", "owasp": {"category": cat, "real": real}}

    pool = [mk(i, "sqli", True) for i in range(20)] + [mk(100 + i, "xss", True) for i in range(20)]
    # sqli: 10 evaluated, always caught (certain). xss: 2 evaluated, 1 caught (very uncertain)
    done = {f"c{i:03}": True for i in range(10)}
    done.update({"c100": True, "c101": False})
    picked = rb.select_adaptive(pool, done, 5, seed=1)
    assert len(picked) == 5 and len({p["id"] for p in picked}) == 5
    assert not any(p["id"] in done for p in picked)
    assert sum(p["owasp"]["category"] == "xss" for p in picked) >= 4
    lo, hi = rb.wilson(5, 10)
    assert 0.2 < lo < 0.3 and 0.7 < hi < 0.8


def test_backslash_quote_evidence_survives_and_still_grounds(monkeypatch):
    """784 OWASP cases contain \\' in code; a model copying it verbatim emits invalid JSON."""
    code_line = "sql = f'SELECT u FROM t WHERE p = \\'{bar}\\''"
    raw = '[{"framework": "OWASP", "rule_id": "OWASP-A03", "cwe": 89, "evidence": "' \
          + code_line.replace("\\'", "\\'") + '", "explanation": "x", "severity": "critical"}]'
    with pytest.raises(json.JSONDecodeError):
        json.loads(raw)  # what the API actually sends back
    monkeypatch.setattr(llm_client, "_call_gemini", lambda *a, **k: raw)
    found = llm_client._analyze_with_gemini("h.py", "+" + code_line + "\n", {}, {})
    assert found[0]["evidence"] == code_line
    out = verify_node({"changed_files": [{"path": "h.py", "diff": "+" + code_line + "\n"}],
                       "raw_findings": found})
    assert len(out["verified_findings"]) == 1


def test_exploit_check_drops_rejected_and_fails_open(monkeypatch):
    from mr_security_reviewer.nodes.exploit_check import exploit_check_node

    findings = [{"file": "a.py", "rule_id": "OWASP-A03", "cwe": 95, "evidence": "eval(bar)", "severity": "critical"},
                {"file": "a.py", "rule_id": "OWASP-A02", "cwe": 328, "evidence": "md5(x)", "severity": "high"},
                {"file": "b.py", "rule_id": "OWASP-A03", "cwe": 89, "evidence": "q", "severity": "critical"}]
    state = {"use_mock": False, "changed_files": [{"path": "a.py", "diff": "+x"}, {"path": "b.py", "diff": "+y"}],
             "verified_findings": findings, "errors": []}

    def fake_critique(path, diff, fs, ctx, use_mock):
        if path == "b.py":
            raise llm_client.LLMError("boom")
        return [{"verdict": "rejected", "reason": "bar is the constant 'safe'", "trace": ""},
                {"verdict": "confirmed", "reason": "md5 used for passwords", "trace": ""}]

    monkeypatch.setattr(llm_client, "critique_file", fake_critique)
    out = exploit_check_node(state)
    assert [f["evidence"] for f in out["rejected_findings"]] == ["eval(bar)"]
    assert {f["evidence"] for f in out["checked_findings"]} == {"md5(x)", "q"}  # b.py kept: fail open
    assert out["errors"] and "exploit_check[b.py]" in out["errors"][0]


def test_critic_verdicts_map_by_id_and_default_to_confirmed(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "k")
    raw = json.dumps([{"id": "f2", "trace": "t", "verdict": "rejected", "reason": "constant"}])
    monkeypatch.setattr(llm_client, "_call_gemini", lambda *a, **k: raw)
    v = llm_client.critique_file("a.py", "+x\n", [{"evidence": "a"}, {"evidence": "b"}], {}, use_mock=False)
    assert [x["verdict"] for x in v] == ["confirmed", "rejected"]


def test_prompt_versions_are_selectable(monkeypatch):
    monkeypatch.setenv("REVIEW_PROMPT", "v1")
    assert llm_client.system_prompt() == llm_client.PROMPT_V1
    monkeypatch.setenv("REVIEW_PROMPT", "v2")
    assert "Cross-site scripting (CWE-79)" in llm_client.system_prompt()
