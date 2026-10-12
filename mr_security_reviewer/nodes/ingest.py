"""Node 1: ingest -- pull the MR title, author, and per-file diffs from GitLab."""

from __future__ import annotations

from ..integrations.gitlab_client import fetch_merge_request
from ..state import ReviewState


def ingest_node(state: ReviewState) -> dict:
    try:
        mr = fetch_merge_request(state["project"], state["mr_id"], state.get("use_mock", True))
    except Exception as exc:  # noqa: BLE001 -- surface any client error into state, don't crash the graph
        return {"errors": state.get("errors", []) + [f"ingest: {exc}"], "changed_files": []}

    return {
        "mr_title": mr["title"],
        "mr_author": mr["author"],
        "changed_files": mr["changed_files"],
        "context_files": mr.get("context_files", {}),
    }
