"""Wires the seven nodes into a LangGraph StateGraph.

    ingest -> context -> analyze -> verify -> exploit_check -> aggregate -> report

verify drops findings whose quoted code isn't in the diff (hallucinations);
exploit_check drops findings whose input never actually reaches the flagged line.

Linear on purpose: each stage's output is a strict input to the next, and
the interesting behavior (mock vs. live GitLab/Gemini, hallucination
dropping) lives inside the nodes, not in graph branching. The graph shape
is still worth having as a graph rather than a plain function chain: it
gives you LangGraph's per-node tracing, the ability to checkpoint/resume
a review, and a natural place to add conditional edges later (e.g. skip
`analyze` for files with no matched rules, or loop `verify` back into
`analyze` with a re-prompt when grounding fails).
"""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from .nodes.aggregate import aggregate_node
from .nodes.analyze import analyze_node
from .nodes.context import context_node
from .nodes.exploit_check import exploit_check_node
from .nodes.ingest import ingest_node
from .nodes.report import report_node
from .nodes.verify import verify_node
from .state import ReviewState


def build_graph():
    graph = StateGraph(ReviewState)

    graph.add_node("ingest", ingest_node)
    graph.add_node("context", context_node)
    graph.add_node("analyze", analyze_node)
    graph.add_node("verify", verify_node)
    graph.add_node("exploit_check", exploit_check_node)
    graph.add_node("aggregate", aggregate_node)
    graph.add_node("report", report_node)

    graph.set_entry_point("ingest")
    graph.add_edge("ingest", "context")
    graph.add_edge("context", "analyze")
    graph.add_edge("analyze", "verify")
    graph.add_edge("verify", "exploit_check")
    graph.add_edge("exploit_check", "aggregate")
    graph.add_edge("aggregate", "report")
    graph.add_edge("report", END)

    return graph.compile()


def run_review(project: str, mr_id: str, use_mock: bool = True) -> ReviewState:
    app = build_graph()
    initial_state: ReviewState = {
        "project": project,
        "mr_id": mr_id,
        "use_mock": use_mock,
        "errors": [],
    }
    result = app.invoke(initial_state)
    return result
