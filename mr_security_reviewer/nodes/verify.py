"""Node 4: hallucination verification -- ground every finding's quoted
`evidence` against the actual diff before it's trusted downstream.

This is the anti-hallucination step: LLMs reviewing code will occasionally
invent a plausible-sounding line that isn't actually in the diff, or
misattribute a real issue to the wrong file. We treat "evidence I cannot
find in the source" as a hallucination and drop it rather than surface it,
because a security report that cries wolf trains reviewers to ignore it.

Only lines that will exist after the merge count as evidence: added ("+")
and unchanged context (" ") lines. A finding that quotes a removed ("-") line
is pointing at code the MR deletes, so it is dropped too.

Grounding, per evidence line, in three passes:
  1. Exact match (whitespace/diff-marker normalized) -- the common case,
     since both the real prompt and the stub analyzer quote verbatim.
  2. Substring containment either way (the evidence may be a fragment of a
     longer line, or a multi-line quote may contain the line).
  3. Fuzzy match (difflib ratio >= FUZZY_THRESHOLD) -- tolerates minor
     whitespace/formatting drift without accepting fabricated evidence.

On success the finding's `line_hint` is corrected to the grounded line.
"""

from __future__ import annotations

import difflib
import re

from ..state import ReviewState

FUZZY_THRESHOLD = 0.85
MIN_SUBSTRING = 8  # a fragment shorter than this (e.g. "x = 1") proves nothing


def _normalize(line: str) -> str:
    line = line.strip()
    line = re.sub(r"^[+\-]\s*", "", line)  # drop leading diff +/- marker
    line = re.sub(r"\s+", " ", line)
    return line.strip().lower()


def _live_lines(diff_lines: list[str]) -> list[tuple[int, str]]:
    """(1-based diff line number, normalized text) for lines that survive the merge."""
    return [
        (i, _normalize(l))
        for i, l in enumerate(diff_lines, 1)
        if not l.startswith("-") and not l.startswith("@@") and _normalize(l)
    ]


def _ground_one(ev: str, live: list[tuple[int, str]]) -> tuple[int | None, str]:
    for n, nl in live:
        if ev == nl:
            return n, "Exact match against the diff."
    for n, nl in live:
        if (len(ev) >= MIN_SUBSTRING and ev in nl) or (len(nl) >= MIN_SUBSTRING and nl in ev):
            return n, "Substring match against the diff."
    best_ratio, best_n = 0.0, None
    for n, nl in live:
        ratio = difflib.SequenceMatcher(None, ev, nl).ratio()
        if ratio > best_ratio:
            best_ratio, best_n = ratio, n
    if best_ratio >= FUZZY_THRESHOLD:
        return best_n, f"Fuzzy match (similarity={best_ratio:.2f})."
    return None, f"best similarity={best_ratio:.2f}"


def _ground(evidence: str, diff_lines: list[str]) -> tuple[bool, str, int | None]:
    ev_lines = [_normalize(l) for l in evidence.splitlines()]
    ev_lines = [l for l in ev_lines if l]
    if not ev_lines:
        return False, "Empty evidence.", None

    live = _live_lines(diff_lines)
    removed = [_normalize(l) for l in diff_lines if l.startswith("-")]

    for ev in ev_lines:
        n, note = _ground_one(ev, live)
        if n is not None:
            return True, note, n

    if any(ev in removed for ev in ev_lines):
        return False, "Evidence is only on a removed line -- the MR deletes this code.", None
    return False, f"No matching line found in the diff ({note}) -- likely hallucinated.", None


def verify_node(state: ReviewState) -> dict:
    diffs_by_file = {cf["path"]: cf["diff"].splitlines() for cf in state.get("changed_files", [])}

    verified = []
    dropped = []

    for finding in state.get("raw_findings", []):
        file_lines = diffs_by_file.get(finding.get("file", ""), [])
        grounded, note, line_no = _ground(finding.get("evidence", ""), file_lines)
        finding = dict(finding)
        finding["grounded"] = grounded
        finding["verification_note"] = note
        if grounded:
            finding["line_hint"] = line_no
            verified.append(finding)
        else:
            dropped.append(finding)

    return {"verified_findings": verified, "dropped_findings": dropped}
