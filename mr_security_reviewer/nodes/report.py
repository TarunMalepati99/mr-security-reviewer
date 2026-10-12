"""Node 7: report -- render the findings as a Markdown MR comment and post it
(real mode) or just return it for the CLI to print/save (demo mode).
"""

from __future__ import annotations

from ..integrations.gitlab_client import post_comment
from ..state import ReviewState

_GATE_EMOJI = {"pass": "✅", "warn": "⚠️", "block": "⛔"}


def _render(state: ReviewState) -> str:
    findings = state.get("final_findings", [])
    dropped = state.get("dropped_findings", [])
    gate = state.get("gate_decision", "pass")
    risk = state.get("risk_score", 0)

    lines = [
        f"## {_GATE_EMOJI.get(gate, '')} Automated Security Review -- gate: **{gate.upper()}** (risk score {risk}/100)",
        "",
        f"MR: **{state.get('mr_title', '(untitled)')}** by `{state.get('mr_author', 'unknown')}`",
        "",
    ]

    if not findings:
        lines.append("No PCI-DSS / SOC 2 / OWASP issues found in the changed files. ✅")
    else:
        lines.append(f"Found **{len(findings)}** issue(s) across {len(state.get('changed_files', []))} changed file(s):")
        lines.append("")
        lines.append("| Severity | Framework | Rule | CWE | File:Line | Issue |")
        lines.append("|---|---|---|---|---|---|")
        for f in findings:
            loc = f"{f['file']}:{f.get('line_hint') or '?'}"
            cwes = f.get("cwes") or ([f["cwe"]] if f.get("cwe") else [])
            cwe = ", ".join(f"CWE-{c}" for c in cwes) or "-"
            explanation = str(f.get("explanation", "")).replace("|", "\\|").replace("\n", " ")
            lines.append(
                f"| {str(f.get('severity', '?')).upper()} | {f.get('framework', '?')} | "
                f"{f.get('rule_id', '?')} — {f.get('rule_title', '')} | {cwe} | `{loc}` | {explanation} |"
            )
        lines.append("")
        lines.append("<details><summary>Evidence quoted from the diff</summary>\n")
        for f in findings:
            lines.append(f"- `{f['file']}`: `{str(f.get('evidence', '')).strip()}`")
        lines.append("\n</details>")

    errors = state.get("errors", [])
    if errors:
        lines.append("")
        lines.append(f"**{len(errors)} file(s) could not be analyzed** -- this review is incomplete:")
        lines += [f"- {e}" for e in errors]

    rejected = state.get("rejected_findings", [])
    if rejected:
        lines.append("")
        lines.append(f"<details><summary>{len(rejected)} candidate finding(s) rejected by the exploitability "
                     "check</summary>\n")
        for f in rejected:
            lines.append(f"- `{f['file']}`: {f.get('rule_id')} -- {f.get('exploitability_reason', '')}")
        lines.append("\n</details>")

    lines.append("")
    lines.append(
        f"_Hallucination check: {len(dropped)} candidate finding(s) were discarded because their "
        f"quoted evidence could not be grounded in the actual diff._"
    )

    return "\n".join(lines)


def report_node(state: ReviewState) -> dict:
    markdown = _render(state)
    posted = False
    errors = list(state.get("errors", []))
    try:
        posted = post_comment(state["project"], state["mr_id"], markdown, state.get("use_mock", True))
    except Exception as exc:  # noqa: BLE001 -- posting failure shouldn't hide the report itself
        errors.append(f"report: {exc}")

    return {"report_markdown": markdown, "posted": posted, "errors": errors}
