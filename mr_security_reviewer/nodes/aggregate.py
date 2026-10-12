"""Node 6: aggregate/score -- dedupe findings that multiple frameworks flag
for the same underlying issue (e.g. a hardcoded secret can trip both
PCI-DSS and SOC 2), compute an overall risk score, and decide the MR gate
outcome.
"""

from __future__ import annotations

import re

from ..state import ReviewState

_SEVERITY_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}
_SEVERITY_POINTS = {"critical": 25, "high": 15, "medium": 8, "low": 3}


def _norm_key(finding: dict) -> tuple:
    # verify has already pinned line_hint to the grounded diff line, so two
    # frameworks flagging the same line collapse into one finding
    if isinstance(finding.get("line_hint"), int):
        return finding.get("file", ""), finding["line_hint"]
    evidence = re.sub(r"\s+", " ", finding.get("evidence", "").strip().lower())
    return finding.get("file", ""), evidence


def _merge_group(group: list[dict]) -> dict:
    group_sorted = sorted(
        group,
        key=lambda f: (_SEVERITY_RANK.get(f.get("severity"), 0), f.get("confidence", 0)),
        reverse=True,
    )
    primary = dict(group_sorted[0])
    others = group_sorted[1:]
    primary["cwes"] = sorted({f["cwe"] for f in group if isinstance(f.get("cwe"), int)})
    if others:
        seen = {(primary.get("framework"), primary.get("rule_id"))}
        extra = []
        for o in others:
            key = (o.get("framework"), o.get("rule_id"))
            if key not in seen:
                seen.add(key)
                extra.append(f"{o.get('framework')} {o.get('rule_id')}")
        if extra:
            primary["rule_title"] = f"{primary.get('rule_title', '')} (also violates: {', '.join(extra)})"
    return primary


def aggregate_node(state: ReviewState) -> dict:
    groups: dict[tuple[str, str], list[dict]] = {}
    for f in state.get("checked_findings", state.get("verified_findings", [])):
        groups.setdefault(_norm_key(f), []).append(f)

    final_findings = [_merge_group(g) for g in groups.values()]
    final_findings.sort(key=lambda f: _SEVERITY_RANK.get(f.get("severity"), 0), reverse=True)

    risk_score = min(100, sum(_SEVERITY_POINTS.get(f.get("severity"), 0) for f in final_findings))

    has_critical = any(f.get("severity") == "critical" for f in final_findings)
    has_high = any(f.get("severity") == "high" for f in final_findings)
    if has_critical:
        gate_decision = "block"
    elif has_high or risk_score >= 15:
        gate_decision = "warn"
    else:
        gate_decision = "pass"

    return {
        "final_findings": final_findings,
        "risk_score": risk_score,
        "gate_decision": gate_decision,
    }
