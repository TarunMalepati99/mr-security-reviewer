"""Node 3: analyze -- run each changed file through the LLM (Gemini, or the
deterministic stub in demo mode) against the compliance rules and any related
repository files, producing a list of candidate findings. These are *unverified*:
the next node grounds each one against the actual diff before it's trusted.
"""

from __future__ import annotations

import uuid

from ..integrations import llm_client
from ..state import ReviewState


def analyze_node(state: ReviewState) -> dict:
    raw_findings = []
    errors = list(state.get("errors", []))
    relevant_rules = state.get("relevant_rules", {})
    file_context = state.get("file_context", {})
    use_mock = state.get("use_mock", True)

    for cf in state.get("changed_files", []):
        path = cf["path"]
        try:
            file_findings = llm_client.analyze_file(
                path, cf["diff"], relevant_rules.get(path, {}), use_mock, file_context.get(path, {})
            )
        except Exception as exc:  # noqa: BLE001 -- one bad file shouldn't kill the whole MR review
            errors.append(f"analyze[{path}]: {exc}")
            continue

        for f in file_findings:
            f["file"] = path
            f.setdefault("confidence", 0.5)
            f.setdefault("cwe", None)
            f["id"] = str(uuid.uuid4())[:8]
            f["grounded"] = None
            f["verification_note"] = None
            raw_findings.append(f)

    # returned (not mutated in place) so LangGraph actually keeps the errors in state
    return {"raw_findings": raw_findings, "errors": errors}
