"""CLI entrypoint.

    # demo mode, zero setup, runs against the bundled fixture MR
    python -m mr_security_reviewer.cli --demo

    # live mode, once GITLAB_TOKEN / GEMINI_API_KEY are set (environment or a .env file)
    python -m mr_security_reviewer.cli --project mygroup/myrepo --mr-id 42

    # either, with Arize Phoenix tracing turned on
    python -m mr_security_reviewer.cli --demo --trace
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mr-security-reviewer",
        description="LangGraph agent that reviews GitLab MRs against PCI-DSS/SOC2/OWASP.",
    )
    parser.add_argument("--project", default="demo/fixture-project", help="GitLab project path or ID")
    parser.add_argument("--mr-id", default="1", help="Merge request IID")
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Force mock GitLab data + stub analyzer, ignoring any GITLAB_TOKEN/GEMINI_API_KEY.",
    )
    parser.add_argument("--trace", action="store_true", help="Enable Arize Phoenix tracing (if installed).")
    parser.add_argument("--out", type=Path, default=None, help="Also write the Markdown report to this file.")
    parser.add_argument("--json", action="store_true", help="Print the full final state as JSON instead of Markdown.")
    return parser


def _load_dotenv() -> None:
    """Read KEY=value lines from a .env file in the current folder, if present.
    Values already set in the environment win."""
    env = Path(".env")
    if not env.is_file():
        return
    for raw in env.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip().strip('"').strip("'")
        if value and key.strip() not in os.environ:
            os.environ[key.strip()] = value


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _load_dotenv()

    from .integrations.llm_client import gemini_model

    if args.demo:
        print("[mode] demo: bundled fixture MR + pattern-matching stub analyzer", file=sys.stderr)
    else:
        llm = f"Gemini ({gemini_model()})" if os.environ.get("GEMINI_API_KEY") else "stub analyzer (no GEMINI_API_KEY set)"
        mr = "GitLab" if os.environ.get("GITLAB_TOKEN") else "bundled fixture MR (no GITLAB_TOKEN set)"
        print(f"[mode] live: {mr} + {llm}", file=sys.stderr)

    if args.trace:
        from .observability.tracing import enable_tracing

        enable_tracing()

    from .graph import run_review

    # --demo forces mock GitLab + stub analyzer; otherwise each integration client
    # falls back to mock/stub on its own only when GITLAB_TOKEN/GEMINI_API_KEY is unset.
    result = run_review(project=args.project, mr_id=args.mr_id, use_mock=args.demo)

    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        print(result.get("report_markdown", "(no report produced)"))
        if result.get("errors"):
            print("\n--- errors ---", file=sys.stderr)
            for e in result["errors"]:
                print(e, file=sys.stderr)

    if args.out:
        args.out.write_text(result.get("report_markdown", ""), encoding="utf-8")
        print(f"\nWrote report to {args.out}", file=sys.stderr)

    return 0 if result.get("gate_decision") != "block" else 1


if __name__ == "__main__":
    raise SystemExit(main())
