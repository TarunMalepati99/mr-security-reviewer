"""Shared state schema passed between every node in the LangGraph graph.

LangGraph threads a single mutable-ish state object through the whole
graph. Each node reads what it needs and returns a partial dict of the
fields it wants to update -- LangGraph merges that into the running state.
"""

from __future__ import annotations

from typing import Any, Literal, Optional, TypedDict


class ChangedFile(TypedDict):
    path: str
    diff: str  # unified diff hunk(s) for this file


class Finding(TypedDict):
    id: str
    framework: Literal["PCI-DSS", "SOC2", "OWASP"]
    rule_id: str
    rule_title: str
    cwe: Optional[int]  # most specific CWE id, when known
    file: str
    line_hint: Optional[int]
    evidence: str  # the exact snippet of code the model is pointing at
    explanation: str
    severity: Literal["critical", "high", "medium", "low"]
    confidence: float  # 0.0-1.0, set by the analyze node
    grounded: Optional[bool]  # set by the hallucination-verification node
    verification_note: Optional[str]


class ReviewState(TypedDict, total=False):
    # --- inputs ---
    project: str
    mr_id: str
    use_mock: bool

    # --- populated by node 1: ingest ---
    mr_title: str
    mr_author: str
    changed_files: list[ChangedFile]
    context_files: dict[str, str]  # path -> source of related repo files (read-only context)

    # --- populated by node 2: context/retrieval ---
    relevant_rules: dict[str, dict[str, list[dict[str, Any]]]]  # file path -> framework -> rule chunks
    file_context: dict[str, dict[str, str]]  # changed path -> {related path: source} given to the analyzer

    # --- populated by node 3: analyze ---
    raw_findings: list[Finding]

    # --- populated by node 4: hallucination verification ---
    verified_findings: list[Finding]
    dropped_findings: list[Finding]  # findings whose evidence didn't ground in the diff

    # --- populated by node 5: exploitability check ---
    checked_findings: list[Finding]  # grounded findings the critic confirmed (or couldn't check)
    rejected_findings: list[Finding]  # grounded findings whose input never reaches the sink

    # --- populated by node 6: aggregate/score ---
    final_findings: list[Finding]
    risk_score: int  # 0-100
    gate_decision: Literal["pass", "warn", "block"]

    # --- populated by node 7: report ---
    report_markdown: str
    posted: bool

    # --- bookkeeping ---
    errors: list[str]
