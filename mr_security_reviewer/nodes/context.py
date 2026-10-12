"""Node 2: context/retrieval -- assemble what the analyzer needs to judge each file.

1. Compliance rules. Every changed file gets the full PCI-DSS / SOC 2 / OWASP rule
   set (it is small: ~17 rules), ordered so the rules whose keywords appear in the
   diff come first. An earlier version sent only keyword-matched rules, which meant
   the model never saw, e.g., the access-control rule for a handler that didn't
   happen to contain the word "route" -- and since the prompt requires findings to
   cite a provided rule id, those issues were impossible to report.
2. Related repository files. When the MR source provides them (`context_files`),
   any related file whose module name is imported by the changed file is attached,
   so the analyzer can see what a helper actually returns instead of guessing.

Swap in an embedding-based retriever here without touching any other node -- the
contract is "path -> {framework: [rules]}" plus "path -> {related path: source}".
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ..state import ReviewState

_RULES_DIR = Path(__file__).resolve().parent.parent / "rules"
_FRAMEWORK_FILES = {
    "PCI-DSS": "pci_dss.json",
    "SOC2": "soc2.json",
    "OWASP": "owasp.json",
}


def _load_rules() -> dict[str, list[dict[str, Any]]]:
    rules = {}
    for framework, filename in _FRAMEWORK_FILES.items():
        with open(_RULES_DIR / filename, "r", encoding="utf-8") as f:
            rules[framework] = json.load(f)
    return rules


_ALL_RULES = _load_rules()


def _rules_for_text(text: str) -> dict[str, list[dict[str, Any]]]:
    """All rules, keyword-matched ones first within each framework."""
    text_lower = text.lower()
    ordered: dict[str, list[dict[str, Any]]] = {}
    for framework, rules in _ALL_RULES.items():
        hits = [r for r in rules if any(kw.lower() in text_lower for kw in r["keywords"])]
        rest = [r for r in rules if r not in hits]
        ordered[framework] = hits + rest
    return ordered


def _related_files(diff: str, context_files: dict[str, str]) -> dict[str, str]:
    related = {}
    for path, src in context_files.items():
        module = Path(path).stem
        if module == "__init__":
            module = Path(path).parent.name
        if re.search(rf"\b{re.escape(module)}\b", diff):
            related[path] = src
    return related


def context_node(state: ReviewState) -> dict:
    per_file_rules: dict[str, dict[str, list[dict[str, Any]]]] = {}
    per_file_context: dict[str, dict[str, str]] = {}
    context_files = state.get("context_files", {}) or {}
    for cf in state.get("changed_files", []):
        per_file_rules[cf["path"]] = _rules_for_text(cf["diff"])
        per_file_context[cf["path"]] = _related_files(cf["diff"], context_files)

    return {"relevant_rules": per_file_rules, "file_context": per_file_context}
