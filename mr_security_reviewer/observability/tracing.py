"""Optional Arize Phoenix observability.

When enabled, every node's inputs/outputs, latency, and token usage
(for the real Gemini path) are captured as OpenTelemetry spans and
viewable in Phoenix's local UI. This is intentionally lazy-imported and
fails soft: the reviewer runs fine with `--trace` on a machine that
doesn't have `arize-phoenix` / `openinference-instrumentation-langchain`
installed, it just skips tracing and says so.

Usage:
    from mr_security_reviewer.observability.tracing import enable_tracing
    enable_tracing()          # call once, before build_graph()/run_review()
"""

from __future__ import annotations

_ENABLED = False


def enable_tracing(ui: bool = True) -> bool:
    """Best-effort: start a local Phoenix session and instrument LangChain/
    LangGraph runs. Returns True if tracing is actually active.
    """
    global _ENABLED
    if _ENABLED:
        return True

    try:
        import phoenix as px
        from openinference.instrumentation.langchain import LangChainInstrumentor
        from phoenix.otel import register
    except ImportError as exc:
        print(
            "[tracing] Skipping Arize Phoenix instrumentation -- missing package "
            f"({exc.name}). Install with: pip install arize-phoenix "
            "openinference-instrumentation-langchain"
        )
        return False
    except Exception as exc:  # noqa: BLE001 -- an optional, best-effort feature must never crash the review
        print(
            f"[tracing] Skipping Arize Phoenix instrumentation -- import failed ({exc!r}). "
            "This is usually a version mismatch between arize-phoenix and your Python version; "
            "see README.md's Observability section for a known-good pin."
        )
        return False

    try:
        if ui:
            px.launch_app()
            print("[tracing] Phoenix UI running at http://localhost:6006")

        tracer_provider = register(project_name="mr-security-reviewer", endpoint="http://localhost:6006/v1/traces")
        LangChainInstrumentor().instrument(tracer_provider=tracer_provider)
    except Exception as exc:  # noqa: BLE001 -- same rationale: never take down the review over tracing
        print(f"[tracing] Skipping Arize Phoenix instrumentation -- setup failed ({exc!r}).")
        return False

    _ENABLED = True
    return True
