"""End-to-end test of the six-node graph in demo mode (no network/credentials)."""

from mr_security_reviewer.graph import run_review


def test_demo_run_produces_findings_and_gate_decision():
    result = run_review(project="demo/fixture-project", mr_id="1", use_mock=True)

    assert result["mr_title"]
    assert len(result["changed_files"]) == 3

    # every framework named in the task description should show up at least once
    frameworks_hit = {f["framework"] for f in result["final_findings"]}
    assert frameworks_hit == {"PCI-DSS", "SOC2", "OWASP"}

    assert result["gate_decision"] == "block"  # the fixture contains a hardcoded secret -> critical
    assert result["risk_score"] > 0

    assert "Automated Security Review" in result["report_markdown"]


def test_all_findings_are_grounded_in_the_diff():
    result = run_review(project="demo/fixture-project", mr_id="1", use_mock=True)

    diffs = {cf["path"]: cf["diff"] for cf in result["changed_files"]}
    for finding in result["final_findings"]:
        assert finding["evidence"] in diffs[finding["file"]] or finding["grounded"] is True


def test_verify_node_never_lets_ungrounded_evidence_through():
    from mr_security_reviewer.nodes.verify import verify_node

    state = {
        "changed_files": [{"path": "x.py", "diff": "+x = 1\n+y = 2\n"}],
        "raw_findings": [
            {
                "id": "abc",
                "framework": "OWASP",
                "rule_id": "OWASP-A03",
                "rule_title": "Injection",
                "file": "x.py",
                "line_hint": 1,
                "evidence": "this line was never in the diff at all",
                "explanation": "fabricated",
                "severity": "critical",
                "confidence": 0.9,
            }
        ],
    }
    out = verify_node(state)
    assert out["verified_findings"] == []
    assert len(out["dropped_findings"]) == 1
    assert out["dropped_findings"][0]["grounded"] is False
