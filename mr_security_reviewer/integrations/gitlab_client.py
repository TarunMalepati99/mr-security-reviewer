"""GitLab merge-request fetching, with a mock fallback for demo mode.

Real mode talks to the GitLab REST API v4 (`/projects/:id/merge_requests/:iid/changes`).
Mock mode reads a bundled fixture so the whole pipeline runs with zero setup.

Swap to live GitLab by setting GITLAB_TOKEN and GITLAB_URL (defaults to
https://gitlab.com) and running the CLI without --demo.
"""

from __future__ import annotations

import json
import os
import urllib.parse
from pathlib import Path
from typing import Any

import requests

FIXTURE_PATH = Path(__file__).resolve().parent.parent / "fixtures" / "sample_mr_diff.json"


class GitLabClientError(RuntimeError):
    pass


def _load_fixture() -> dict[str, Any]:
    with open(FIXTURE_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def fetch_merge_request(project: str, mr_id: str, use_mock: bool) -> dict[str, Any]:
    """Return {"title": str, "author": str, "changed_files": [{"path", "diff"}]}."""
    if use_mock or not os.environ.get("GITLAB_TOKEN"):
        data = _load_fixture()
        return {
            "title": data["title"],
            "author": data["author"],
            "changed_files": data["changed_files"],
            "context_files": data.get("context_files", {}),
        }

    base_url = os.environ.get("GITLAB_URL", "https://gitlab.com").rstrip("/")
    token = os.environ["GITLAB_TOKEN"]
    project_id = urllib.parse.quote_plus(project)
    headers = {"PRIVATE-TOKEN": token}

    mr_resp = requests.get(
        f"{base_url}/api/v4/projects/{project_id}/merge_requests/{mr_id}",
        headers=headers,
        timeout=30,
    )
    if mr_resp.status_code != 200:
        raise GitLabClientError(
            f"Failed to fetch MR {mr_id} for {project}: {mr_resp.status_code} {mr_resp.text}"
        )
    mr_json = mr_resp.json()

    changes_resp = requests.get(
        f"{base_url}/api/v4/projects/{project_id}/merge_requests/{mr_id}/changes",
        headers=headers,
        timeout=30,
    )
    if changes_resp.status_code != 200:
        raise GitLabClientError(
            f"Failed to fetch diff for MR {mr_id}: {changes_resp.status_code} {changes_resp.text}"
        )
    changes_json = changes_resp.json()

    changed_files = [
        {"path": c["new_path"], "diff": c.get("diff", "")} for c in changes_json.get("changes", [])
    ]

    return {
        "title": mr_json.get("title", ""),
        "author": (mr_json.get("author") or {}).get("username", "unknown"),
        "changed_files": changed_files,
        "context_files": {},
    }


def post_comment(project: str, mr_id: str, body: str, use_mock: bool) -> bool:
    """Post the review as a top-level MR discussion comment. No-op in mock mode."""
    if use_mock or not os.environ.get("GITLAB_TOKEN"):
        return False

    base_url = os.environ.get("GITLAB_URL", "https://gitlab.com").rstrip("/")
    token = os.environ["GITLAB_TOKEN"]
    project_id = urllib.parse.quote_plus(project)
    headers = {"PRIVATE-TOKEN": token}

    resp = requests.post(
        f"{base_url}/api/v4/projects/{project_id}/merge_requests/{mr_id}/notes",
        headers=headers,
        data={"body": body},
        timeout=30,
    )
    if resp.status_code not in (200, 201):
        raise GitLabClientError(f"Failed to post MR comment: {resp.status_code} {resp.text}")
    return True
